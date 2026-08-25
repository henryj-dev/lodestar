import { error, redirect } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { requireDbContext } from "$lib/server/auth/guards";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit";
import { findOidcClient, isAllowedRedirectUri, parseGrantedScopes } from "$lib/server/oidc/client";
import { createGrant } from "$lib/server/oidc/grant";
import { checkRateLimit } from "$lib/server/ratelimit";
import { hasServiceAccess } from "$lib/server/access/service-permissions";
import { verifyIdToken, b64uEncode } from "$lib/server/crypto/keys";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";
import { translate } from "$lib/i18n/server";

/** redirect_uri 가 확정된 이후에만 사용. 그 전 오류는 throw error() 로 직접 응답. */
function authRedirectError(redirectUri: string, errorCode: string, description: string, state?: string | null): never {
    const dest = new URL(redirectUri);
    dest.searchParams.set("error", errorCode);
    dest.searchParams.set("error_description", description);
    if (state) dest.searchParams.set("state", state);
    throw redirect(302, dest.toString());
}

export const GET: RequestHandler = async (event) => {
    const { locals, url } = event;
    const { db, tenant, rateLimitStore } = requireDbContext(locals);

    // IP당 60회/분 제한 — grant INSERT DoS 방지
    const { ip, ipKey } = getRequestMetadata(event);
    const rl = await checkRateLimit(rateLimitStore, `oidc-authorize:${ipKey}`, {
        windowMs: 60 * 1000,
        limit: 60,
    });
    if (!rl.allowed) {
        throw error(429, translate(locals.locale, "oidc.errors.rate_limited"));
    }

    const clientId = url.searchParams.get("client_id");
    const redirectUri = url.searchParams.get("redirect_uri");
    const responseType = url.searchParams.get("response_type");
    const scope = url.searchParams.get("scope") ?? "openid";
    const state = url.searchParams.get("state");
    const nonce = url.searchParams.get("nonce");
    const codeChallenge = url.searchParams.get("code_challenge");
    const codeChallengeMethod = url.searchParams.get("code_challenge_method");

    // client_id / redirect_uri 가 없으면 redirect 불가 → 직접 오류 응답
    if (!clientId || !redirectUri) {
        throw error(400, translate(locals.locale, "oidc.errors.client_id_redirect_uri_required"));
    }
    if (responseType !== "code") {
        throw error(400, translate(locals.locale, "oidc.errors.response_type_unsupported"));
    }

    const client = await findOidcClient(db, tenant.id, clientId);
    if (!client) {
        throw error(401, translate(locals.locale, "oidc.errors.unknown_client"));
    }

    if (!isAllowedRedirectUri(client, redirectUri)) {
        throw error(400, translate(locals.locale, "oidc.errors.redirect_uri_mismatch"));
    }

    // PKCE 검증
    // - 공개 클라이언트(tokenEndpointAuthMethod=none)는 PKCE 필수 (RFC 8252)
    // - code_challenge 가 빈 문자열이면 거부
    // - code_challenge 가 어떤 형태로든 제공되면 method 는 반드시 S256 만 허용
    const pkceRequired = client.requirePkce || client.tokenEndpointAuthMethod === "none";
    const hasChallenge = codeChallenge !== null && codeChallenge.trim().length > 0;

    if (pkceRequired && !hasChallenge) {
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            spOrClientId: clientId,
            kind: "oidc_authorize",
            outcome: "failure",
            ip,
            userAgent: getRequestMetadata(event).userAgent,
            detail: { error: "invalid_request", reason: "pkce_required" },
        });
        authRedirectError(redirectUri, "invalid_request", translate(locals.locale, "oidc.errors.pkce_required"), state);
    }
    if (codeChallenge !== null && !hasChallenge) {
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            spOrClientId: clientId,
            kind: "oidc_authorize",
            outcome: "failure",
            ip,
            userAgent: getRequestMetadata(event).userAgent,
            detail: { error: "invalid_request", reason: "empty_code_challenge" },
        });
        authRedirectError(redirectUri, "invalid_request", translate(locals.locale, "oidc.errors.empty_code_challenge"), state);
    }
    if (hasChallenge && codeChallengeMethod !== "S256") {
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            spOrClientId: clientId,
            kind: "oidc_authorize",
            outcome: "failure",
            ip,
            userAgent: getRequestMetadata(event).userAgent,
            detail: { error: "invalid_request", reason: "invalid_code_challenge_method", method: codeChallengeMethod },
        });
        authRedirectError(redirectUri, "invalid_request", translate(locals.locale, "oidc.errors.code_challenge_method_unsupported"), state);
    }

    // scope 검증
    const grantedScopes = parseGrantedScopes(client, scope);
    if (!grantedScopes.includes("openid")) {
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            spOrClientId: clientId,
            kind: "oidc_authorize",
            outcome: "failure",
            ip,
            userAgent: getRequestMetadata(event).userAgent,
            detail: { error: "invalid_scope", requestedScope: scope },
        });
        authRedirectError(redirectUri, "invalid_scope", translate(locals.locale, "oidc.errors.openid_scope_required"), state);
    }
    const grantedScope = grantedScopes.join(" ");

    // ── prompt / max_age / id_token_hint / login_hint (OIDC Core 3.1.2) ─────────
    const prompts = new Set((url.searchParams.get("prompt") ?? "").split(/\s+/).filter(Boolean));
    const promptNone = prompts.has("none");
    // prompt=none 은 다른 값과 함께 올 수 없다.
    if (promptNone && prompts.size > 1) {
        authRedirectError(redirectUri, "invalid_request", translate(locals.locale, "oidc.errors.prompt_none_conflict"), state);
    }

    const maxAgeRaw = url.searchParams.get("max_age");
    let maxAge: number | null = null;
    if (maxAgeRaw !== null) {
        const n = Number.parseInt(maxAgeRaw, 10);
        if (!Number.isFinite(n) || n < 0) {
            authRedirectError(redirectUri, "invalid_request", translate(locals.locale, "oidc.errors.max_age_invalid"), state);
        }
        maxAge = n;
    }

    const idTokenHint = url.searchParams.get("id_token_hint");
    const loginHint = url.searchParams.get("login_hint");

    const loggedIn = Boolean(locals.user && locals.session);

    // 재인증 필요 여부: prompt=login, max_age 초과, id_token_hint 의 sub 불일치.
    // prompt=login 은 로그인 여부와 무관하게 재인증 요구다 — 미로그인이어도 forceAuthn 을 전달해야
    // 신뢰 기기(trusted device) 가 OTP 를 건너뛰지 않는다. 나머지 두 조건은 locals.session/user 를
    // 읽으므로 로그인된 경우에만 평가한다(미로그인은 어차피 새로 인증하므로 자동 충족).
    let reauthRequired = prompts.has("login");
    if (loggedIn) {
        if (!reauthRequired && maxAge !== null) {
            const authTimeSec = Math.floor(locals.session!.createdAt.getTime() / 1000);
            if (Math.floor(Date.now() / 1000) - authTimeSec > maxAge) reauthRequired = true;
        }
        if (!reauthRequired && idTokenHint) {
            const issuer = resolveIssuerUrl(locals.runtimeConfig, url.origin, locals.tenant?.slug ?? undefined);
            // id_token_hint 는 만료돼 있는 것이 정상이므로 exp 검사는 건너뛰되 서명은 검증한다.
            const hintClaims = await verifyIdToken(db, tenant.id, idTokenHint, { expectedIssuer: issuer, ignoreExpiry: true });
            if (!hintClaims || hintClaims.sub !== locals.user!.id) reauthRequired = true;
        }
    }

    const needsInteraction = !loggedIn || reauthRequired;

    if (promptNone && needsInteraction) {
        // 무상호작용 요청인데 상호작용이 필요 → 표준 오류를 redirect_uri 로 반환.
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: locals.user?.id,
            spOrClientId: clientId,
            kind: "oidc_authorize",
            outcome: "failure",
            ip,
            userAgent: getRequestMetadata(event).userAgent,
            detail: { error: "login_required", reason: reauthRequired ? "reauth_required" : "not_authenticated" },
        });
        authRedirectError(redirectUri, "login_required", translate(locals.locale, "oidc.errors.login_required"), state);
    }

    if (needsInteraction) {
        // 무한 루프 방지 (SAML /saml/sso 의 saml_reauth_<id> 가드를 변형).
        // reauthRequired 조건(prompt=login / max_age / id_token_hint)은 재인증을 마치고 돌아와도
        // 요청 파라미터가 그대로라 여전히 참일 수 있어, 가드가 없으면 /login ↔ /oidc/authorize 를
        // 무한 왕복한다. SAML 과 달리 authorize 요청에는 AuthnRequest.id 같은 고유 ID 가 없으므로
        // 재진입 시에도 동일하게 유지되는 pathname+search 를 SHA-256 해시해 마커 쿠키명을 만든다.
        // 해시의 base64url 출력은 [A-Za-z0-9_-] 뿐이라, SAML 이 겪은 쿠키명 injection(공백·;·제어문자로
        // cookie.serialize 가 throw → 500 DoS) 문제는 구조적으로 발생하지 않는다.
        // prompt=none 은 위에서 이미 login_required 로 끝났으므로 여기서 쿠키를 남기지 않는다.
        if (reauthRequired) {
            const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(url.pathname + url.search));
            const reauthCookieName = `oidc_reauth_${b64uEncode(digest).slice(0, 32)}`;
            // 마커에는 발급 시각(ms)을 담고, 복귀 시 "그 이후에 생성된 세션" 일 때만 재인증을 인정한다.
            // 존재 여부만 보면(SAML 가드의 약점) 사용자가 /login 에서 실제로 인증하지 않고 같은 authorize
            // URL 로 되돌아오기만 해도 prompt=login 이 소진돼 재인증 요구를 우회할 수 있다.
            // 미로그인 상태에서는 마커가 있어도 재인증을 마쳤다고 볼 수 없다 — 반드시 forceAuthn 을 붙인다.
            // 숫자 형식을 원시 문자열에서 검사한다: Number("") 는 0 이라 빈 쿠키 값이 "아주 오래된 마커" 로
            // 둔갑해 무조건 통과해버린다.
            const rawMarker = event.cookies.get(reauthCookieName);
            const marker = rawMarker && /^\d+$/.test(rawMarker) ? Number(rawMarker) : null;
            if (loggedIn && marker !== null && locals.session!.createdAt.getTime() >= marker) {
                // 마커 발급 이후에 만들어진 세션 = 재인증을 실제로 마치고 돌아온 복귀 — 소진 후 정상 진행.
                event.cookies.delete(reauthCookieName, { path: "/oidc/authorize" });
                reauthRequired = false;
            } else {
                event.cookies.set(reauthCookieName, String(Date.now()), {
                    path: "/oidc/authorize",
                    httpOnly: true,
                    sameSite: "lax",
                    secure: url.protocol === "https:",
                    maxAge: 600,
                });
            }
        }

        if (!loggedIn || reauthRequired) {
            // 인터랙티브 로그인/재인증으로 리다이렉트.
            const loginUrl = new URL("/login", url);
            loginUrl.searchParams.set("redirectTo", url.pathname + url.search);
            loginUrl.searchParams.set("skinHint", `oidc:${client.id}`);
            if (reauthRequired) loginUrl.searchParams.set("forceAuthn", "true");
            if (loginHint) loginUrl.searchParams.set("loginHint", loginHint);
            throw redirect(302, loginUrl.toString());
        }
    }

    // 여기 도달 시 로그인 상태가 보장된다 (타입 좁히기용 방어 체크).
    if (!locals.user || !locals.session) {
        throw error(500, translate(locals.locale, "oidc.errors.session_missing_after_gate"));
    }

    // 서비스 권한 게이트 (기본 deny). 매핑 없으면 SSO 거부.
    // 단, allowAllUsers 클라이언트는 매핑 없이도 테넌트의 모든 사용자를 허용한다.
    const allowed =
        client.allowAllUsers ||
        (await hasServiceAccess(db, {
            tenantId: tenant.id,
            userId: locals.user.id,
            serviceType: "oidc",
            serviceRefId: client.id,
        }));
    if (!allowed) {
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: locals.user.id,
            actorId: locals.user.id,
            spOrClientId: clientId,
            kind: "oidc_authorize",
            outcome: "failure",
            ip,
            userAgent: getRequestMetadata(event).userAgent,
            detail: { error: "access_denied", reason: "no_service_assignment" },
        });
        authRedirectError(redirectUri, "access_denied", translate(locals.locale, "oidc.errors.service_access_denied"), state);
    }

    // ctrls R6: 클라이언트가 이메일 인증을 요구하면(requireVerifiedEmail) 미인증 사용자를 거부한다.
    // email_verified 클레임은 항상 전파되지만, RP 가 IdP 측 강제를 원할 때 이 플래그로 차단한다.
    if (client.requireVerifiedEmail && !locals.user.emailVerifiedAt) {
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: locals.user.id,
            actorId: locals.user.id,
            spOrClientId: clientId,
            kind: "oidc_authorize",
            outcome: "failure",
            ip,
            userAgent: getRequestMetadata(event).userAgent,
            detail: { error: "access_denied", reason: "email_verification_required" },
        });
        authRedirectError(redirectUri, "access_denied", translate(locals.locale, "oidc.errors.email_verification_required"), state);
    }

    // authorization code 발급
    const code = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");

    await createGrant(db, {
        tenantId: tenant.id,
        clientId,
        userId: locals.user.id,
        sessionId: locals.session.id,
        code,
        codeChallenge: codeChallenge ?? null,
        codeChallengeMethod: (codeChallengeMethod as "S256" | "plain" | null) ?? null,
        redirectUri,
        scope: grantedScope,
        nonce: nonce ?? null,
        state: state ?? null,
        acr: locals.session.acr ?? null,
    });

    const { userAgent } = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId: locals.user.id,
        actorId: locals.user.id,
        spOrClientId: clientId,
        kind: "oidc_authorize",
        outcome: "success",
        ip,
        userAgent,
        detail: { clientId, scope: grantedScope },
    });

    const callbackUrl = new URL(redirectUri);
    callbackUrl.searchParams.set("code", code);
    if (state) callbackUrl.searchParams.set("state", state);
    throw redirect(302, callbackUrl.toString());
};
