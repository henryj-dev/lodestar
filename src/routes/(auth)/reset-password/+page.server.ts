import { fail, redirect } from "@sveltejs/kit";
import { eq, and, gt, isNull } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireDbContext } from "$lib/server/auth/guards";
import { credentials, users, passwordResetTokens } from "$lib/server/db/schema";
import { DB_DIALECT, type DB } from "$lib/server/db";
import { runAtomic } from "$lib/server/db/atomic";
import { checkPasswordPolicy, hashPassword } from "$lib/server/auth/password";
import { isBreachCheckEnabled, isPasswordBreached } from "$lib/server/auth/breach-check";
import { hashToken } from "$lib/server/email";
import { clearTrustedDeviceCookie, revokeAllTrustedDevices } from "$lib/server/auth/trusted-device";
import { revokeUserEverywhere } from "$lib/server/oidc/revoke-everywhere";
import { resolve } from "$app/paths";
import { sanitizeRedirectTarget } from "$lib/server/auth/redirect";
import { resolveSkinHtml, replacePlaceholders, escapeHtml } from "$lib/server/skin/resolver";
import { checkRateLimit } from "$lib/server/ratelimit";
import { getRequestMetadata } from "$lib/server/audit";
import { translate } from "$lib/i18n/server";
import { dispatchSecurityAlert } from "$lib/server/security-notify";

async function resolveSkin(skinHint: string | null, locals: App.Locals, platform: App.Platform | undefined, token: string | null, redirectTo: string | null, flashMsg = ""): Promise<string | null> {
    if (!skinHint || !locals.db || !locals.tenant) return null;
    const colonIdx = skinHint.indexOf(":");
    if (colonIdx <= 0) return null;
    const clientType = skinHint.slice(0, colonIdx) as "oidc" | "saml";
    const clientRefId = skinHint.slice(colonIdx + 1);
    if (clientType !== "oidc" && clientType !== "saml") return null;
    const raw = await resolveSkinHtml(locals.db, platform, locals.tenant.id, clientType, clientRefId, "reset_password");
    if (!raw) return null;
    return replacePlaceholders(raw, {
        IDP_FORM_ACTION: "",
        IDP_REDIRECT_TO: escapeHtml(redirectTo ?? ""),
        IDP_SKIN_HINT: escapeHtml(skinHint),
        IDP_TOKEN: escapeHtml(token ?? ""),
        IDP_FLASH_MSG: escapeHtml(flashMsg),
    });
}

export const load: PageServerLoad = async ({ locals, url, platform }) => {
    const redirectTo = sanitizeRedirectTarget(url.searchParams.get("redirectTo"));
    const skinHint = url.searchParams.get("skinHint") ?? null;

    const token = url.searchParams.get("token");
    if (!token) {
        const skinHtml = await resolveSkin(skinHint, locals, platform, null, redirectTo);
        return { valid: false, token: null, redirectTo, skinHint, skinHtml };
    }

    if (!locals.db) {
        const skinHtml = await resolveSkin(skinHint, locals, platform, token, redirectTo);
        return { valid: false, token: null, redirectTo, skinHint, skinHtml };
    }

    const tokenHash = await hashToken(token);
    const now = new Date();

    const [record] = await locals.db
        .select({ id: passwordResetTokens.id, expiresAt: passwordResetTokens.expiresAt })
        .from(passwordResetTokens)
        .where(and(eq(passwordResetTokens.tokenHash, tokenHash), isNull(passwordResetTokens.usedAt)))
        .limit(1);

    const valid = !!(record && record.expiresAt >= now);
    const skinHtml = await resolveSkin(skinHint, locals, platform, valid ? token : null, redirectTo);

    if (!valid) return { valid: false, token, redirectTo, skinHint, skinHtml };

    return { valid: true, token, redirectTo, skinHint, skinHtml };
};

export const actions: Actions = {
    default: async (event) => {
        const { db, tenant, rateLimitStore } = requireDbContext(event.locals);

        const formData = await event.request.formData();
        const token = String(formData.get("token") ?? "");
        const password = String(formData.get("password") ?? "");
        const confirmPassword = String(formData.get("confirmPassword") ?? "");
        const redirectTo = sanitizeRedirectTarget(String(formData.get("redirectTo") ?? ""));
        const skinHint = String(formData.get("skinHint") ?? "");

        const locale = event.locals.locale;
        const failWithSkin = async (msg: string) => fail(400, { error: msg, skinHtml: await resolveSkin(skinHint || null, event.locals, event.platform, token || null, redirectTo, msg) });

        // ctrls C8: 토큰 제출 브루트포스/자동화 방어. 토큰이 256bit CSPRNG 라 추측 실익은
        // 낮지만, 형제 인증 라우트와 동일하게 IP 당 시도를 제한해 정합성·DB 부하를 막는다.
        const meta = getRequestMetadata(event);
        const rl = await checkRateLimit(rateLimitStore, `reset-password:${meta.ipKey}`, { windowMs: 15 * 60 * 1000, limit: 10 });
        if (!rl.allowed) {
            return failWithSkin(translate(locale, "errors.rate_limit", { minutes: Math.ceil(rl.retryAfterMs / 60000) }));
        }

        if (!token) return failWithSkin(translate(locale, "reset_password.err_invalid_request"));
        const violation = checkPasswordPolicy(password);
        if (violation === "too_short") return failWithSkin(translate(locale, "reset_password.err_password_short"));
        if (violation) return failWithSkin(translate(locale, "errors.password_weak"));
        // ctrls R5: HIBP 유출 비밀번호 차단(운영자 opt-in). 오류 시 fail-open.
        if (isBreachCheckEnabled() && (await isPasswordBreached(password))) return failWithSkin(translate(locale, "reset_password.err_password_breached"));
        if (password !== confirmPassword) return failWithSkin(translate(locale, "reset_password.err_password_mismatch"));

        const tokenHash = await hashToken(token);
        const now = new Date();

        const [record] = await db
            .select({ id: passwordResetTokens.id, userId: passwordResetTokens.userId, expiresAt: passwordResetTokens.expiresAt, email: users.email, locale: users.locale })
            .from(passwordResetTokens)
            .innerJoin(users, eq(passwordResetTokens.userId, users.id))
            // 요청 테넌트의 사용자 토큰만 받는다. 다른 테넌트 호스트로 제출하면 그 테넌트 issuer 로 엉뚱한
            // RP 에 로그아웃을 통지하게 된다(세션 폐기는 userId 기준이라 문제없었지만 통지는 테넌트 기준이다).
            .where(and(eq(passwordResetTokens.tokenHash, tokenHash), isNull(passwordResetTokens.usedAt), eq(users.tenantId, tenant.id)))
            .limit(1);

        if (!record || record.expiresAt < now) return failWithSkin(translate(locale, "reset_password.err_expired_link"));

        // Consume the presented token first. This conditional write is the
        // single-winner gate for concurrent submissions.
        const consumeBuilder = db
            .update(passwordResetTokens)
            .set({ usedAt: now })
            .where(and(eq(passwordResetTokens.id, record.id), eq(passwordResetTokens.tokenHash, tokenHash), isNull(passwordResetTokens.usedAt), gt(passwordResetTokens.expiresAt, now)));
        let consumed: boolean;
        if (DB_DIALECT === "mysql") {
            const result = (await consumeBuilder) as unknown as [{ affectedRows?: number }];
            consumed = (result?.[0]?.affectedRows ?? 0) === 1;
        } else {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const rows = (await (consumeBuilder as any).returning({ id: passwordResetTokens.id })) as Array<{ id: string }>;
            consumed = rows.length === 1;
        }
        if (!consumed) return failWithSkin(translate(locale, "reset_password.err_expired_link"));

        const hashedPw = await hashPassword(password);

        // Determine the credential branch before runAtomic. D1/SQLite batch
        // builders are collected synchronously and cannot branch on a query.
        const [existing] = await db
            .select({ id: credentials.id })
            .from(credentials)
            .where(and(eq(credentials.userId, record.userId), eq(credentials.type, "password")))
            .limit(1);

        const updateCredential = (h: Pick<DB, "insert" | "update">) =>
            existing
                ? h.update(credentials).set({ secret: hashedPw }).where(eq(credentials.id, existing.id))
                : h.insert(credentials).values({ userId: record.userId, type: "password", secret: hashedPw, label: "비밀번호", createdAt: now });

        // Password/user metadata and the remaining reset-token invalidation are
        // atomic. The already-consumed token remains consumed if this batch fails,
        // which is the safe fail-closed outcome for a reset link.
        await runAtomic(db, [
            (h) => h.update(users).set({ updatedAt: now }).where(eq(users.id, record.userId)),
            updateCredential,
            (h) =>
                h
                    .update(passwordResetTokens)
                    .set({ usedAt: now })
                    .where(and(eq(passwordResetTokens.userId, record.userId), isNull(passwordResetTokens.usedAt))),
        ]);

        // 비밀번호가 바뀌었으므로 기존 세션과 OIDC refresh token 을 모두 무효화한다.
        // RP 에도 back-channel logout 을 보낸다 — 탈취된 RP 세션도 함께 끊어야 리셋의 의미가 있다.
        await revokeUserEverywhere(event, { db, tenant, userId: record.userId, actorId: record.userId, reason: "password_reset", revokedAt: now });
        // 신뢰 기기도 함께 폐기한다 — 비밀번호 탈취자가 기존 신뢰 기기로 MFA 를 건너뛰지 못하게.
        await revokeAllTrustedDevices(db, record.userId, now);
        clearTrustedDeviceCookie(event.cookies, event.url);

        // 보안 알림(best-effort, 완전 격리) — 비밀번호가 변경됨.
        dispatchSecurityAlert({ to: record.email, locale: record.locale, kind: "password_changed", when: now, platform: event.platform });

        const extra = new URLSearchParams();
        if (redirectTo) extra.set("redirectTo", redirectTo);
        if (skinHint) extra.set("skinHint", skinHint);
        const extraStr = extra.toString();
        throw redirect(302, resolve("/login") + "?passwordReset=1" + (extraStr ? `&${extraStr}` : ""));
    },
};
