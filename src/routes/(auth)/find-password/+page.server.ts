import { fail } from "@sveltejs/kit";
import { eq, and, isNull } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { resolveSkinHtml, replacePlaceholders, escapeHtml } from "$lib/server/skin/resolver";
import { requireDbContext } from "$lib/server/auth/guards";
import { users, passwordResetTokens } from "$lib/server/db/schema";
import { sendPasswordResetEmail, generateToken } from "$lib/server/email";
import { normalizeLocale } from "$lib/i18n/core";
import { checkRateLimit } from "$lib/server/ratelimit";
import { getRequestMetadata } from "$lib/server/audit";
import { env } from "$env/dynamic/private";
import { translate } from "$lib/i18n/server";

// 회원 공통 정책: 재설정 링크는 30분.
const RESET_EXPIRY_MS = 30 * 60 * 1000;

export const load: PageServerLoad = async ({ locals, url, platform }) => {
    const skinHint = url.searchParams.get("skinHint");
    let skinHtml: string | null = null;

    if (skinHint && locals.db && locals.tenant) {
        const colonIdx = skinHint.indexOf(":");
        if (colonIdx > 0) {
            const clientType = skinHint.slice(0, colonIdx) as "oidc" | "saml";
            const clientRefId = skinHint.slice(colonIdx + 1);
            if ((clientType === "oidc" || clientType === "saml") && clientRefId) {
                const raw = await resolveSkinHtml(locals.db, platform, locals.tenant.id, clientType, clientRefId, "find_password");
                if (raw) {
                    skinHtml = replacePlaceholders(raw, {
                        IDP_FORM_ACTION: "",
                        IDP_SKIN_HINT: escapeHtml(skinHint),
                        IDP_REDIRECT_TO: "",
                        IDP_FIND_PASSWORD_SENT: "",
                        IDP_SUBMITTED_EMAIL: "",
                        IDP_FLASH_MSG: "",
                    });
                }
            }
        }
    }

    const redirectTo = url.searchParams.get("redirectTo") ?? null;
    return { skinHint, skinHtml, redirectTo };
};

async function resolveSkinForAction(event: Parameters<Actions["default"]>[0], sent: boolean, submittedEmail?: string, flashMsg = ""): Promise<string | null> {
    const skinHint = event.url.searchParams.get("skinHint");
    if (!skinHint || !event.locals.db || !event.locals.tenant) return null;
    const colonIdx = skinHint.indexOf(":");
    if (colonIdx <= 0) return null;
    const clientType = skinHint.slice(0, colonIdx) as "oidc" | "saml";
    const clientRefId = skinHint.slice(colonIdx + 1);
    if ((clientType !== "oidc" && clientType !== "saml") || !clientRefId) return null;
    const raw = await resolveSkinHtml(event.locals.db, event.platform, event.locals.tenant.id, clientType, clientRefId, "find_password");
    if (!raw) return null;
    return replacePlaceholders(raw, {
        IDP_FORM_ACTION: "",
        IDP_SKIN_HINT: escapeHtml(skinHint),
        IDP_REDIRECT_TO: "",
        IDP_FIND_PASSWORD_SENT: sent ? "1" : "",
        IDP_SUBMITTED_EMAIL: submittedEmail ? escapeHtml(submittedEmail) : "",
        IDP_FLASH_MSG: escapeHtml(flashMsg),
    });
}

export const actions: Actions = {
    default: async (event) => {
        const { db, tenant, rateLimitStore } = requireDbContext(event.locals);

        const formData = await event.request.formData();
        const email = String(formData.get("email") ?? "")
            .trim()
            .toLowerCase();
        const username = String(formData.get("username") ?? "")
            .trim()
            .toLowerCase();

        const locale = event.locals.locale;

        if (!email || !username) {
            const msg = translate(locale, "find_password.err_missing_fields");
            return fail(400, { error: msg, skinHtml: await resolveSkinForAction(event, false, undefined, msg) });
        }

        // IP 기반 레이트리밋 — 60분/5회.
        const meta = getRequestMetadata(event);
        const rl = await checkRateLimit(rateLimitStore, `find-password:${meta.ipKey}`, { windowMs: 60 * 60 * 1000, limit: 5 });
        if (!rl.allowed) {
            const msg = translate(locale, "errors.rate_limit", { minutes: Math.ceil(rl.retryAfterMs / 60000) });
            return fail(429, { error: msg, skinHtml: await resolveSkinForAction(event, false, undefined, msg) });
        }

        const [user] = await db
            .select({ id: users.id, email: users.email, locale: users.locale })
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.email, email), eq(users.username, username)))
            .limit(1);

        // ctrls C-7 후속: IDP_ISSUER_URL 가 없으면 event.url.origin (= Host 헤더 기반)
        // 으로 fallback 하던 패턴은 host header injection 으로 reset 링크 도메인을
        // 공격자 도메인으로 바꿔치기당할 수 있어 (계정 takeover) 즉시 제거.
        // 미설정 시 메일 발송 자체를 skip 하되 응답은 정상 흐름과 동일하게 유지하여
        // user enumeration / 설정 노출 면적을 0 으로 둔다.
        const issuer = env.IDP_ISSUER_URL?.replace(/\.+$/, "").replace(/\/+$/, "");

        if (user && issuer) {
            try {
                // 같은 user 의 미사용 토큰을 모두 사용 처리하여 새 토큰만 유효하게.
                await db
                    .update(passwordResetTokens)
                    .set({ usedAt: new Date() })
                    .where(and(eq(passwordResetTokens.userId, user.id), isNull(passwordResetTokens.usedAt)));

                const { token, tokenHash } = await generateToken();
                const expiresAt = new Date(Date.now() + RESET_EXPIRY_MS);
                await db.insert(passwordResetTokens).values({ userId: user.id, tokenHash, expiresAt });
                const resetParams = new URLSearchParams({ token });
                const redirectTo = event.url.searchParams.get("redirectTo");
                const skinHint = event.url.searchParams.get("skinHint");
                if (redirectTo) resetParams.set("redirectTo", redirectTo);
                if (skinHint) resetParams.set("skinHint", skinHint);
                const resetUrl = `${issuer}/reset-password?${resetParams.toString()}`;
                // ctrls C5(후속): SMTP 왕복을 응답 경로에서 분리해 타이밍 계정 열거를 차단한다.
                // (find-id 와 동일 패턴 — Workers: waitUntil, Node: fire-and-forget.)
                const sendPromise = sendPasswordResetEmail(user.email, resetUrl, normalizeLocale(user.locale ?? locale), event.platform).catch(() => {
                    // 메일 발송 실패는 조용히 무시
                });
                const wait = event.platform?.ctx?.waitUntil?.bind(event.platform.ctx);
                if (wait) wait(sendPromise);
            } catch {
                // 조용히 무시
            }
        } else if (user && !issuer) {
            // 운영 가시화용 — IDP_ISSUER_URL 누락은 설정 사고이므로 서버 로그로 알림.
            console.error("[find-password] IDP_ISSUER_URL 미설정 — 비밀번호 재설정 메일 발송 불가");
        }

        // 메일 발송 분기와 미발송 분기 모두 timing 균등화 — 200~300ms.
        await new Promise((r) => setTimeout(r, 200 + Math.random() * 100));

        return { sent: true, skinHtml: await resolveSkinForAction(event, true, email) };
    },
};
