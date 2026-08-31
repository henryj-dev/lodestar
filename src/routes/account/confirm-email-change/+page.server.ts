import { fail } from "@sveltejs/kit";
import { and, eq, isNull, ne } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireDbContext } from "$lib/server/auth/guards";
import { escapeHtml, replacePlaceholders, resolveSkinByHint } from "$lib/server/skin/resolver";
import { users, emailChangeTokens } from "$lib/server/db/schema";
import { hashToken } from "$lib/server/email";
import { runAtomic } from "$lib/server/db/atomic";
import { checkRateLimit } from "$lib/server/ratelimit";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit";
import { translate } from "$lib/i18n/server";

// 토큰 상태를 tenant 범위에서 조회한다(read-only). 유효하면 record 반환, 아니면 null.
// targetEmail 은 토큰에 바인딩된 변경 대상 주소 — 확인 시 이 값으로만 email 을 교체한다.
async function lookupToken(db: App.Locals["db"], tenantId: string, token: string) {
    if (!db) return null;
    const tokenHash = await hashToken(token);
    const now = new Date();
    const [record] = await db
        .select({
            tokenId: emailChangeTokens.id,
            userId: users.id,
            targetEmail: emailChangeTokens.targetEmail,
            expiresAt: emailChangeTokens.expiresAt,
        })
        .from(emailChangeTokens)
        .innerJoin(users, eq(emailChangeTokens.userId, users.id))
        .where(and(eq(emailChangeTokens.tokenHash, tokenHash), isNull(emailChangeTokens.usedAt), eq(users.tenantId, tenantId)))
        .limit(1);
    if (!record || record.expiresAt < now) return null;
    return record;
}

/** 계정 화면에서 시작되는 흐름이라 클라이언트 정보가 없다 — 테넌트 기본 스킨으로 폴백한다. */
async function resolveSkin(locals: App.Locals, platform: App.Platform | undefined, skinHint: string | null, vars: { token: string | null; flashMsg?: string }): Promise<string | null> {
    if (!locals.db || !locals.tenant) return null;
    const raw = await resolveSkinByHint(locals.db, platform, locals.tenant.id, skinHint, "confirm_email_change");
    if (!raw) return null;
    return replacePlaceholders(raw, {
        IDP_FORM_ACTION: "",
        IDP_REDIRECT_TO: "",
        IDP_SKIN_HINT: escapeHtml(skinHint ?? ""),
        IDP_TOKEN: escapeHtml(vars.token ?? ""),
        IDP_FLASH_MSG: escapeHtml(vars.flashMsg ?? ""),
    });
}

export const load: PageServerLoad = async ({ locals, url, platform }) => {
    const token = url.searchParams.get("token");
    const skinHint = url.searchParams.get("skinHint");
    if (!token || !locals.db || !locals.tenant) {
        return { valid: false, token: null as string | null, skinHint, skinHtml: await resolveSkin(locals, platform, skinHint, { token: null }) };
    }
    const record = await lookupToken(locals.db, locals.tenant.id, token);
    if (!record) return { valid: false, token: null as string | null, skinHint, skinHtml: await resolveSkin(locals, platform, skinHint, { token: null }) };
    return { valid: true, token: token as string | null, skinHint, skinHtml: await resolveSkin(locals, platform, skinHint, { token }) };
};

export const actions: Actions = {
    default: async (event) => {
        const { db, tenant, rateLimitStore } = requireDbContext(event.locals);
        const locale = event.locals.locale;
        const skinHint = event.url.searchParams.get("skinHint");
        const formData = await event.request.formData();
        const token = String(formData.get("token") ?? "");

        /**
         * 실패 응답에도 스킨을 실어 준다 — 스킨이 걸린 페이지가 제출 후 기본 UI 로 튀지 않게.
         * 토큰을 그대로 되돌려줘야 재제출 폼의 hidden input 이 살아 있어 다시 시도할 수 있다.
         */
        const failWithSkin = async (status: number, message: string) =>
            fail(status, { error: message, skinHtml: await resolveSkin(event.locals, event.platform, skinHint, { token: token || null, flashMsg: message }) });

        // 토큰 제출 브루트포스 방어 — 형제 인증 라우트와 동일하게 IP 당 제한.
        const meta = getRequestMetadata(event);
        const rl = await checkRateLimit(rateLimitStore, `confirm-email-change:${meta.ipKey}`, { windowMs: 15 * 60 * 1000, limit: 10 });
        if (!rl.allowed) {
            return failWithSkin(429, translate(locale, "errors.rate_limit", { minutes: Math.ceil(rl.retryAfterMs / 60000) }));
        }

        if (!token) return failWithSkin(400, translate(locale, "confirm_email_change.invalid_link"));

        const record = await lookupToken(db, tenant.id, token);
        if (!record) return failWithSkin(400, translate(locale, "confirm_email_change.invalid_link"));

        // 확인 시점 중복 재검사 — 요청 이후 다른 계정이 같은 주소를 선점했을 수 있다.
        // (users_tenant_email_uidx 가 최종 방어이지만 사용자 친화적 에러를 위해 선검사한다.)
        const [taken] = await db
            .select({ id: users.id })
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.email, record.targetEmail), ne(users.id, record.userId)))
            .limit(1);
        if (taken) return failWithSkin(409, translate(locale, "confirm_email_change.invalid_link"));

        const now = new Date();
        // 1회용 소진 + email 교체 + pending 클리어 + emailVerifiedAt 세팅을 원자적으로.
        // 같은 user 의 미사용 변경 토큰을 모두 소진해 재사용을 차단한다.
        await runAtomic(db, [
            (h) =>
                h
                    .update(emailChangeTokens)
                    .set({ usedAt: now })
                    .where(and(eq(emailChangeTokens.userId, record.userId), isNull(emailChangeTokens.usedAt))),
            (h) => h.update(users).set({ email: record.targetEmail, pendingEmail: null, pendingEmailRequestedAt: null, emailVerifiedAt: now, updatedAt: now }).where(eq(users.id, record.userId)),
        ]);

        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: record.userId,
            actorId: record.userId,
            kind: "email_changed",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
        });

        return { changed: true };
    },
};
