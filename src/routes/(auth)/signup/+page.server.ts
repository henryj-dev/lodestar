import { fail, redirect } from "@sveltejs/kit";
import { eq, and } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { resolveSkinHtml, replacePlaceholders, escapeHtml } from "$lib/server/skin/resolver";
import { requireDbContext } from "$lib/server/auth/guards";
import { hashPassword, MAX_PASSWORD_LENGTH } from "$lib/server/auth/password";
import { isBreachCheckEnabled, isPasswordBreached } from "$lib/server/auth/breach-check";
import { users, credentials, identities } from "$lib/server/db/schema";
import { resolve } from "$app/paths";
import { sanitizeRedirectTarget } from "$lib/server/auth/redirect";
import { checkRateLimit } from "$lib/server/ratelimit";
import { getRequestMetadata } from "$lib/server/audit";
import { translate } from "$lib/i18n/server";
import { issueEmailVerification } from "$lib/server/auth/email-verification";
import { getRuntimeConfig } from "$lib/server/auth/runtime";
import { tryWithSecretsNullable } from "$lib/server/crypto/keys";
import { clearPendingLinkCookie, readPendingLink } from "$lib/server/auth/pending-link";
import { createFederatedAccount } from "$lib/server/auth/federated-signup";
import { createSessionRecord, setSessionCookie } from "$lib/server/auth/session";
import { AMR_FEDERATED, amrToAcr } from "$lib/server/auth/constants";
import { recordAuditEvent } from "$lib/server/audit";

export const load: PageServerLoad = async ({ locals, url, platform, cookies }) => {
    const skinHint = url.searchParams.get("skinHint");
    const redirectTo = sanitizeRedirectTarget(url.searchParams.get("redirectTo"));
    let skinHtml: string | null = null;

    // ── 연합 회원가입 모드 (§2.8) ──────────────────────────────────────────────
    // 외부 IdP 인증을 마쳤지만 매칭 계정이 없어 콜백이 여기로 보낸 경우다.
    // 프로필은 서명 쿠키에서만 읽는다 — 폼/쿼리에서 오는 값은 신뢰하지 않는다.
    if (url.searchParams.get("federated") === "1") {
        const config = getRuntimeConfig(platform);
        const claims = await tryWithSecretsNullable(config.signingKeySecrets, (s) => readPendingLink(cookies, s));

        if (!claims || claims.tenantId !== locals.tenant?.id) {
            throw redirect(303, "/login?socialError=link_expired");
        }

        // 커스텀 스킨은 연합 모드의 필드 구성을 알지 못하므로 기본 스킨으로 폴백한다.
        // (로그인 페이지가 복구 흐름에서 같은 선택을 한다 — login/+page.svelte 참고.)
        return {
            skinHint,
            skinHtml: null,
            redirectTo: claims.redirectTo,
            federated: {
                providerLabel: claims.providerLabel,
                email: claims.email,
                emailLocked: claims.emailVerified && Boolean(claims.email),
                suggestedUsername: claims.suggestedUsername ?? "",
                displayName: claims.displayName ?? "",
                allowPassword: claims.allowPassword,
                allowUsernameEdit: claims.allowUsernameEdit,
            },
        };
    }

    if (skinHint && locals.db && locals.tenant) {
        const colonIdx = skinHint.indexOf(":");
        if (colonIdx > 0) {
            const clientType = skinHint.slice(0, colonIdx) as "oidc" | "saml";
            const clientRefId = skinHint.slice(colonIdx + 1);
            if ((clientType === "oidc" || clientType === "saml") && clientRefId) {
                const raw = await resolveSkinHtml(locals.db, platform, locals.tenant.id, clientType, clientRefId, "signup");
                if (raw) {
                    skinHtml = replacePlaceholders(raw, {
                        IDP_FORM_ACTION: "",
                        IDP_SKIN_HINT: escapeHtml(skinHint),
                        IDP_REDIRECT_TO: escapeHtml(redirectTo ?? ""),
                        IDP_FLASH_MSG: "",
                    });
                }
            }
        }
    }

    return { skinHint, skinHtml, redirectTo, federated: null };
};

async function resolveSkinForAction(event: Parameters<Actions["default"]>[0], flashMsg: string): Promise<string | null> {
    const skinHint = event.url.searchParams.get("skinHint");
    if (!skinHint || !event.locals.db || !event.locals.tenant) return null;
    const colonIdx = skinHint.indexOf(":");
    if (colonIdx <= 0) return null;
    const clientType = skinHint.slice(0, colonIdx) as "oidc" | "saml";
    const clientRefId = skinHint.slice(colonIdx + 1);
    if ((clientType !== "oidc" && clientType !== "saml") || !clientRefId) return null;
    const raw = await resolveSkinHtml(event.locals.db, event.platform, event.locals.tenant.id, clientType, clientRefId, "signup");
    if (!raw) return null;
    const redirectTo = sanitizeRedirectTarget(event.url.searchParams.get("redirectTo"));
    return replacePlaceholders(raw, {
        IDP_FORM_ACTION: "",
        IDP_SKIN_HINT: escapeHtml(skinHint),
        IDP_REDIRECT_TO: escapeHtml(redirectTo ?? ""),
        IDP_FLASH_MSG: escapeHtml(flashMsg),
    });
}

/**
 * 연합 회원가입 제출 처리 (§2.8).
 *
 * 신원(provider/subject/검증된 이메일)은 서명 쿠키에서만 읽고, 폼에서는 사용자가
 * 정당하게 고를 수 있는 값만 받는다. 자세한 규칙은 `auth/federated-signup.ts` 참고.
 */
async function handleFederatedSignup(event: Parameters<Actions["default"]>[0], formData: FormData) {
    const { db, tenant, rateLimitStore } = requireDbContext(event.locals);
    const locale = event.locals.locale;

    const config = getRuntimeConfig(event.platform);
    const claims = await tryWithSecretsNullable(config.signingKeySecrets, (s) => readPendingLink(event.cookies, s));

    // 토큰이 없거나 만료됐거나 다른 테넌트에서 발급된 것 → 처음부터 다시.
    if (!claims || claims.tenantId !== tenant.id) {
        clearPendingLinkCookie(event.cookies, event.url);
        throw redirect(303, "/login?socialError=link_expired");
    }

    // 외부 IdP 인증을 이미 통과한 요청이라 봇 비용이 높다. 로컬 가입(5회/시간)보다
    // 여유를 두되, 폼 재제출 남용은 막는다.
    const meta = getRequestMetadata(event);
    const rl = await checkRateLimit(rateLimitStore, `signup:fed:${meta.ipKey}`, { windowMs: 60 * 60 * 1000, limit: 20 });
    if (!rl.allowed) {
        return fail(429, { federated: true, error: translate(locale, "signup.err_rate_limit", { minutes: Math.ceil(rl.retryAfterMs / 60000) }) });
    }

    const result = await createFederatedAccount(
        db,
        claims,
        {
            username: String(formData.get("username") ?? ""),
            email: String(formData.get("email") ?? ""),
            password: String(formData.get("password") ?? ""),
            confirmPassword: String(formData.get("confirmPassword") ?? ""),
        },
        locale,
        event.platform,
    );

    if (!result.ok) {
        return fail(result.status, {
            federated: true,
            username: String(formData.get("username") ?? ""),
            error: translate(locale, result.errorKey, result.params),
        });
    }

    // 계정이 생겼으니 pending 신원은 소비 완료.
    clearPendingLinkCookie(event.cookies, event.url);

    // 방금 외부 인증을 마쳤으므로 로그인 페이지로 되돌리지 않고 바로 세션을 발급한다.
    // 신규 계정이라 TOTP 크레덴셜이 있을 수 없어 MFA 분기는 필요 없다.
    const amr = [AMR_FEDERATED];
    const { sessionToken, expiresAt } = await createSessionRecord(db, {
        tenantId: tenant.id,
        userId: result.user.id,
        ip: meta.ip,
        userAgent: meta.userAgent,
        amr,
        acr: amrToAcr(amr),
    });
    setSessionCookie(event.cookies, event.url, sessionToken, expiresAt);

    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId: result.user.id,
        actorId: result.user.id,
        kind: "federated_signup",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { provider: claims.provider, emailVerified: claims.emailVerified },
    });

    const dest = sanitizeRedirectTarget(claims.redirectTo);
    throw redirect(303, dest ?? "/");
}

export const actions: Actions = {
    // 커스텀 스킨이 `{{IDP_FORM_ACTION}}`(=빈 문자열)로 이 default 액션에 제출하므로
    // 액션 이름을 바꾸거나 named action 을 추가하면 기존 스킨이 깨진다.
    // 연합 가입은 별도 액션이 아니라 이 안에서 분기한다.
    default: async (event) => {
        const { db, tenant, rateLimitStore } = requireDbContext(event.locals);

        const formData = await event.request.formData();

        if (String(formData.get("federated") ?? "") === "1") {
            return handleFederatedSignup(event, formData);
        }
        const username = String(formData.get("username") ?? "")
            .trim()
            .toLowerCase();
        const email = String(formData.get("email") ?? "")
            .trim()
            .toLowerCase();
        const password = String(formData.get("password") ?? "");
        const confirmPassword = String(formData.get("confirmPassword") ?? "");

        const locale = event.locals.locale;
        const failSkin = async (status: number, msg: string) => fail(status, { error: msg, skinHtml: await resolveSkinForAction(event, msg) });

        // IP 기반 레이트리밋 — 60분/5회.
        const meta = getRequestMetadata(event);
        const rl = await checkRateLimit(rateLimitStore, `signup:${meta.ipKey}`, { windowMs: 60 * 60 * 1000, limit: 5 });
        if (!rl.allowed) {
            return failSkin(429, translate(locale, "signup.err_rate_limit", { minutes: Math.ceil(rl.retryAfterMs / 60000) }));
        }

        if (!username || !email || !password) return failSkin(400, translate(locale, "signup.err_missing_fields"));
        if (!/^[a-z0-9_]{3,32}$/.test(username)) return failSkin(400, translate(locale, "signup.err_invalid_username"));
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return failSkin(400, translate(locale, "signup.err_invalid_email"));
        if (password.length < 8) return failSkin(400, translate(locale, "signup.err_password_short"));
        if (password.length > MAX_PASSWORD_LENGTH) return failSkin(400, translate(locale, "errors.password_too_long", { max: MAX_PASSWORD_LENGTH }));
        // ctrls R5: HIBP 유출 비밀번호 차단(운영자 opt-in). 오류 시 fail-open.
        if (isBreachCheckEnabled() && (await isPasswordBreached(password))) return failSkin(400, translate(locale, "signup.err_password_breached"));
        if (password !== confirmPassword) return failSkin(400, translate(locale, "signup.err_password_mismatch"));

        const [existingByUsername] = await db
            .select({ id: users.id })
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.username, username)))
            .limit(1);
        if (existingByUsername) return failSkin(409, translate(locale, "signup.err_username_taken"));

        const [existingByEmail] = await db
            .select({ id: users.id })
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.email, email)))
            .limit(1);
        if (existingByEmail) return failSkin(409, translate(locale, "signup.err_email_taken"));

        const hashedPw = await hashPassword(password);
        const userId = crypto.randomUUID();
        const now = new Date();

        await db.insert(users).values({ id: userId, tenantId: tenant.id, username, email, displayName: username, role: "user", status: "active" });
        await db.insert(credentials).values({ userId, type: "password", secret: hashedPw, label: "비밀번호", createdAt: now });
        await db.insert(identities).values({ tenantId: tenant.id, userId, provider: "local", subject: email, email, linkedAt: now });

        // 이메일 인증 메일 발송 — 실패해도 가입은 성공 처리(격리).
        await issueEmailVerification(db, userId, email, locale, event.platform);

        const redirectTo = sanitizeRedirectTarget(event.url.searchParams.get("redirectTo"));
        const skinHint = event.url.searchParams.get("skinHint") ?? "";
        const extra = new URLSearchParams();
        if (redirectTo) extra.set("redirectTo", redirectTo);
        if (skinHint) extra.set("skinHint", skinHint);
        const extraStr = extra.toString();
        throw redirect(302, resolve("/login") + "?registered=1" + (extraStr ? `&${extraStr}` : ""));
    },
};
