/**
 * 소셜 로그인 콜백. 외부 프로바이더가 authorization code 를 들고 돌려보내는 지점이다.
 *
 * 순서: state 검증 → code 교환 → 프로필 조회 → 계정 해석(§2.4/§2.8) → 세션 또는 가입 폼.
 *
 * CSRF 주의: 이 라우트는 외부 origin 에서 오는 GET 이므로 `hooks.server.ts` 의
 * Origin/Referer 검사 대상이 아니다(비-GET 만 검사). 대신 state 쿠키 대조가
 * 그 역할을 한다 — 우리가 시작하지 않은 콜백은 쿠키가 없어 여기서 끊긴다.
 */

import { error, redirect } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { dev } from "$app/environment";
import { requireDbContext } from "$lib/server/auth/guards";
import { getRuntimeConfig } from "$lib/server/auth/runtime";
import { sanitizeRedirectTarget } from "$lib/server/auth/redirect";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { checkRateLimit } from "$lib/server/ratelimit";
import { createSessionRecord, setSessionCookie } from "$lib/server/auth/session";
import { hasTotpCredential } from "$lib/server/auth/users";
import { createMfaPendingToken, MFA_PENDING_COOKIE } from "$lib/server/auth/mfa";
import { clearTrustedDeviceCookie, TRUSTED_DEVICE_COOKIE, verifyTrustedDevice } from "$lib/server/auth/trusted-device";
import { AMR_FEDERATED, AMR_TOTP, amrToAcr } from "$lib/server/auth/constants";
import { setPendingLinkCookie } from "$lib/server/auth/pending-link";
import { timingSafeEqual } from "$lib/server/auth/signed-token";
import { buildRedirectUri, exchangeCode, resolveEndpoints } from "$lib/server/oauth/client";
import { loadClientSecret, loadProviderBySlug } from "$lib/server/oauth/provider-store";
import { consumeOAuthStateCookie } from "$lib/server/oauth/state";
import { linkIdentityToUser, resolveFederatedIdentity } from "$lib/server/oauth/provision";

/** 로그인 페이지로 되돌리며 사유를 알린다. 사유는 i18n 키 suffix 로 쓰인다. */
function backToLogin(reason: string, redirectTo: string | null, skinHint: string | null): never {
    const params = new URLSearchParams({ socialError: reason });
    if (redirectTo) params.set("redirectTo", redirectTo);
    if (skinHint) params.set("skinHint", skinHint);
    throw redirect(303, `/login?${params.toString()}`);
}

export const GET: RequestHandler = async (event) => {
    const slug = event.params.slug;
    if (!slug) throw error(404, "Not found");

    if (!event.locals.db || !event.locals.tenant) {
        throw error(503, event.locals.runtimeError ?? "데이터베이스가 준비되지 않았습니다.");
    }
    const { db, tenant, rateLimitStore } = requireDbContext(event.locals);

    const config = getRuntimeConfig(event.platform);
    if (!config.signingKeySecret) throw error(503, "IDP_SIGNING_KEY_SECRET 이 설정되지 않았습니다.");

    const meta = getRequestMetadata(event);
    const rl = await checkRateLimit(rateLimitStore, `oauth:callback:${meta.ipKey}`, { windowMs: 15 * 60 * 1000, limit: 30 });
    if (!rl.allowed) throw error(429, "요청이 너무 잦습니다. 잠시 후 다시 시도해 주세요.");

    // ── 1. state 검증 ──────────────────────────────────────────────────────────
    // 성공/실패와 무관하게 쿠키는 여기서 소비된다(단일 사용).
    const stateClaims = await consumeOAuthStateCookie(event.cookies, event.url, config.signingKeySecret);
    if (!stateClaims) backToLogin("state_expired", null, null);

    const redirectTo = sanitizeRedirectTarget(stateClaims.redirectTo);
    const skinHint = stateClaims.skinHint;

    // 쿠키가 발급된 프로바이더와 지금 콜백된 프로바이더가 같아야 한다.
    if (!timingSafeEqual(stateClaims.slug, slug)) backToLogin("state_mismatch", redirectTo, skinHint);

    const queryState = event.url.searchParams.get("state") ?? "";
    if (!queryState || !timingSafeEqual(stateClaims.state, queryState)) {
        backToLogin("state_mismatch", redirectTo, skinHint);
    }

    // 사용자가 프로바이더 동의 화면에서 취소한 경우 등.
    const providerError = event.url.searchParams.get("error");
    if (providerError) {
        if (dev) console.warn(`[oauth] ${slug} 프로바이더 오류: ${providerError} ${event.url.searchParams.get("error_description") ?? ""}`);
        backToLogin("provider_denied", redirectTo, skinHint);
    }

    const code = event.url.searchParams.get("code");
    if (!code) backToLogin("missing_code", redirectTo, skinHint);

    // ── 2. 프로바이더 로드 & 코드 교환 ──────────────────────────────────────────
    const provider = await loadProviderBySlug(db, tenant.id, slug);
    if (!provider) backToLogin("provider_unavailable", redirectTo, skinHint);

    const clientSecret = await loadClientSecret(db, tenant.id, provider.id, config.signingKeySecrets);
    if (!clientSecret) {
        console.warn(`[oauth] ${slug}: client secret 복호화 실패 — 관리자 페이지에서 재저장이 필요합니다.`);
        backToLogin("provider_unavailable", redirectTo, skinHint);
    }

    let profile;
    // 단계를 나눠 잡는다. 사용자에게 주는 메시지는 일반화하되, 어느 단계에서 실패했는지는
    // 감사 로그와 서버 로그에서 구분되어야 한다 — 세 단계를 한 사유로 뭉치면 운영자가
    // `wrangler tail` 없이는 설정 오류인지 프로바이더 장애인지 알 수 없다.
    let stage: "discovery_failed" | "exchange_failed" | "profile_failed" = "discovery_failed";
    try {
        const endpoints = await resolveEndpoints(provider.preset, provider.config);

        stage = "exchange_failed";
        const tokens = await exchangeCode({
            preset: provider.preset,
            endpoints,
            clientId: provider.clientId,
            clientSecret,
            code,
            redirectUri: buildRedirectUri(event.url.origin, slug),
            codeVerifier: stateClaims.codeVerifier,
            state: stateClaims.state,
        });

        stage = "profile_failed";
        profile = await provider.preset.fetchProfile(tokens, {
            config: provider.config,
            clientId: provider.clientId,
            nonce: stateClaims.nonce,
            resolved: endpoints,
        });
    } catch (e) {
        // 설정 오류이거나 프로바이더 장애다. 상세는 서버 로그에만 남긴다 —
        // 프로바이더 응답 본문에는 진단 정보가 들어 있어 사용자에게 노출하지 않는다.
        console.warn(`[oauth] ${slug} ${stage}:`, (e as Error).message);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            kind: "login",
            outcome: "failure",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { via: "oauth", provider: slug, reason: stage },
        });
        backToLogin(stage, redirectTo, skinHint);
    }

    const providerKey = `oauth:${slug}`;

    // ── 3a. 이미 로그인한 사용자의 "계정 연결" 경로 ─────────────────────────────
    // `/account/connections` 에서 시작한 흐름이다. 로그인 해석(§2.4)을 타지 않는다 —
    // 본인 계정에 로그인한 상태에서 명시적으로 연결하는 것이므로 이메일이 달라도 정당하다.
    // 위조된 연결 시도는 state 쿠키가 막는다(공격자가 시작한 플로우의 쿠키는 피해자
    // 브라우저에 없다).
    if (event.locals.user) {
        const link = await linkIdentityToUser({ db, tenantId: tenant.id, userId: event.locals.user.id, provider: providerKey, profile });

        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: event.locals.user.id,
            actorId: event.locals.user.id,
            kind: "social_identity_linked",
            outcome: link.type === "already_linked_elsewhere" ? "failure" : "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { provider: slug, result: link.type },
        });

        const query = link.type === "already_linked_elsewhere" ? "linkError=already_linked_elsewhere" : "linked=1";
        throw redirect(303, `/account/connections?${query}`);
    }

    // ── 3b. 로그인 해석 ────────────────────────────────────────────────────────
    const outcome = await resolveFederatedIdentity({
        db,
        tenantId: tenant.id,
        provider: providerKey,
        providerLabel: provider.config.buttonLabel?.trim() || provider.preset.label,
        profile,
        config: provider.config,
    });

    if (outcome.type === "denied") {
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            kind: "login",
            outcome: "failure",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { via: "oauth", provider: slug, reason: outcome.reason },
        });
        backToLogin(outcome.reason, redirectTo, skinHint);
    }

    if (outcome.type === "link_required") {
        // 같은 이메일의 기존 계정이 있다 — 자동 연결하지 않는다(§2.4).
        // 이메일 자체를 쿼리로 흘리지 않고 안내 플래그만 넘긴다.
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            kind: "login",
            outcome: "failure",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { via: "oauth", provider: slug, reason: "link_required" },
        });
        backToLogin("link_required", redirectTo, skinHint);
    }

    if (outcome.type === "signup_form") {
        // 아직 계정을 만들지 않는다. 서명 쿠키로 신원을 넘기고 가입 폼으로 보낸다(§2.8).
        await setPendingLinkCookie(event.cookies, event.url, { ...outcome.claims, redirectTo, skinHint }, config.signingKeySecret);

        const params = new URLSearchParams({ federated: "1" });
        if (skinHint) params.set("skinHint", skinHint);
        throw redirect(303, `/signup?${params.toString()}`);
    }

    // ── 4. 로그인 확정 ─────────────────────────────────────────────────────────
    const user = outcome.user;

    if (await hasTotpCredential(db, user.id)) {
        const forced = event.url.searchParams.get("forceAuthn") === "true";

        // 신뢰 기기: 14일 내 MFA 를 통과한 기기면 TOTP 단계를 건너뛴다(로컬 로그인과 동일).
        const trustedDeviceToken = event.cookies.get(TRUSTED_DEVICE_COOKIE);
        if (!forced && trustedDeviceToken) {
            const trusted = await verifyTrustedDevice(db, trustedDeviceToken, { userId: user.id, tenantId: tenant.id, ip: meta.ip });
            if (trusted) {
                const amr = [AMR_FEDERATED, AMR_TOTP];
                const { sessionToken, expiresAt } = await createSessionRecord(db, {
                    tenantId: tenant.id,
                    userId: user.id,
                    ip: meta.ip,
                    userAgent: meta.userAgent,
                    amr,
                    acr: amrToAcr(amr),
                });
                setSessionCookie(event.cookies, event.url, sessionToken, expiresAt);
                await recordAuditEvent(db, {
                    tenantId: tenant.id,
                    userId: user.id,
                    actorId: user.id,
                    kind: "login",
                    outcome: "success",
                    ip: meta.ip,
                    userAgent: meta.userAgent,
                    detail: { amr, via: "oauth", provider: slug, trustedDevice: true },
                });
                throw redirect(303, user.role === "admin" ? (redirectTo ?? "/admin") : (redirectTo ?? "/"));
            }
            clearTrustedDeviceCookie(event.cookies, event.url);
        }

        // 1차 요소를 `fed` 로 실어 보낸다 — MFA 라우트가 이 값으로 세션 amr 을 조립한다.
        const mfaToken = await createMfaPendingToken({ userId: user.id, tenantId: tenant.id, redirectTo, ip: meta.ip, forced, firstFactor: AMR_FEDERATED }, config.signingKeySecret);

        event.cookies.set(MFA_PENDING_COOKIE, mfaToken, {
            path: "/",
            httpOnly: true,
            sameSite: "lax",
            secure: !dev || event.url.protocol === "https:",
            maxAge: 5 * 60,
        });

        throw redirect(303, skinHint ? `/mfa?skinHint=${encodeURIComponent(skinHint)}` : "/mfa");
    }

    const amr = [AMR_FEDERATED];
    const { sessionToken, expiresAt } = await createSessionRecord(db, {
        tenantId: tenant.id,
        userId: user.id,
        ip: meta.ip,
        userAgent: meta.userAgent,
        amr,
        acr: amrToAcr(amr),
    });

    setSessionCookie(event.cookies, event.url, sessionToken, expiresAt);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId: user.id,
        actorId: user.id,
        kind: "login",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { amr, via: "oauth", provider: slug },
    });

    throw redirect(303, user.role === "admin" ? (redirectTo ?? "/admin") : (redirectTo ?? "/"));
};
