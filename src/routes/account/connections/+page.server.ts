/**
 * 소셜 계정 연결 관리 (계획서 §2.8 / P7).
 *
 * 콜백이 "같은 이메일의 기존 계정" 을 자동 연결하지 않기 때문에(§2.4), 사용자가
 * **로그인한 상태에서 스스로 연결**할 수 있는 자리가 반드시 필요하다. 이 페이지가 그것이다.
 *
 * 연결 자체는 `/auth/oauth/{slug}/start` 로 나가서 콜백이 처리한다. 여기서는 목록과
 * 해제만 담당한다.
 */

import { fail, redirect } from "@sveltejs/kit";
import { and, eq, inArray } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireDbContext } from "$lib/server/auth/guards";
import { ensureCsrfToken, isValidCsrf } from "$lib/server/auth/csrf";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { dispatchSecurityAlert } from "$lib/server/security-notify";
import { credentials, identities } from "$lib/server/db/schema";
import { listEnabledProviderButtons } from "$lib/server/oauth/provider-store";
import { LOCAL_IDENTITY_PROVIDER } from "$lib/server/auth/constants";
import { translate } from "$lib/i18n/server";

export const load: PageServerLoad = async ({ locals, url, cookies }) => {
    if (!locals.user) {
        throw redirect(303, `/login?redirectTo=${encodeURIComponent(url.pathname)}`);
    }

    const { db, tenant } = requireDbContext(locals);

    const linked = await db
        .select({
            id: identities.id,
            provider: identities.provider,
            email: identities.email,
            linkedAt: identities.linkedAt,
            lastLoginAt: identities.lastLoginAt,
        })
        .from(identities)
        .where(and(eq(identities.tenantId, tenant.id), eq(identities.userId, locals.user.id)));

    const available = await listEnabledProviderButtons(db, tenant.id);

    // 이미 연결된 프로바이더는 "연결하기" 목록에서 뺀다.
    const linkedProviders = new Set(linked.map((l) => l.provider));

    return {
        csrf: ensureCsrfToken(cookies, url),
        // 콜백이 연결 결과를 쿼리로 알려준다.
        justLinked: url.searchParams.get("linked") === "1",
        linkError: url.searchParams.get("linkError") === "already_linked_elsewhere" ? "already_linked_elsewhere" : null,
        connections: linked
            // `local` 은 소셜 연결이 아니라 자체 계정 표식이므로 목록에서 제외한다.
            .filter((l) => l.provider !== LOCAL_IDENTITY_PROVIDER)
            .map((l) => {
                const slug = l.provider.startsWith("oauth:") ? l.provider.slice("oauth:".length) : null;
                return {
                    id: l.id,
                    slug,
                    label: available.find((a) => a.slug === slug)?.label ?? slug ?? l.provider,
                    // LDAP 등 소셜이 아닌 연합은 사용자가 스스로 해제할 수 없다(관리자 영역).
                    unlinkable: slug !== null,
                    email: l.email,
                    linkedAt: l.linkedAt,
                    lastLoginAt: l.lastLoginAt,
                };
            }),
        availableProviders: available.filter((a) => !linkedProviders.has(`oauth:${a.slug}`)),
    };
};

export const actions: Actions = {
    unlink: async (event) => {
        const { locals } = event;
        if (!locals.user) throw redirect(303, "/login");

        const { db, tenant } = requireDbContext(locals);
        const locale = locals.locale;
        const fd = await event.request.formData();

        if (!isValidCsrf(event.cookies, fd)) {
            return fail(403, { error: translate(locale, "connections.err_csrf") });
        }

        const id = String(fd.get("id") ?? "").trim();
        if (!id) return fail(400, { error: translate(locale, "connections.err_invalid_request") });

        const [target] = await db
            .select({ id: identities.id, provider: identities.provider })
            .from(identities)
            .where(and(eq(identities.id, id), eq(identities.tenantId, tenant.id), eq(identities.userId, locals.user.id)))
            .limit(1);

        if (!target) return fail(404, { error: translate(locale, "connections.err_not_found") });

        // 소셜 연결만 셀프 해제 대상이다. LDAP 등은 관리자가 다룬다.
        if (!target.provider.startsWith("oauth:")) {
            return fail(400, { error: translate(locale, "connections.err_not_unlinkable") });
        }

        // ── 마지막 로그인 수단 보호 ────────────────────────────────────────────
        // 이걸 지우면 계정에 다시 들어올 방법이 없어지는지 확인한다. `guards.ts` 의
        // 로그인 가능 판정과 같은 기준(credentials 또는 identities)을 쓴다.
        const remainingIdentities = await db
            .select({ id: identities.id })
            .from(identities)
            .where(and(eq(identities.tenantId, tenant.id), eq(identities.userId, locals.user.id)));

        const usableCredentials = await db
            .select({ id: credentials.id })
            .from(credentials)
            .where(and(eq(credentials.userId, locals.user.id), inArray(credentials.type, ["password", "webauthn"])));

        const otherLoginMethods = remainingIdentities.filter((i) => i.id !== target.id).length + usableCredentials.length;
        if (otherLoginMethods === 0) {
            return fail(400, { error: translate(locale, "connections.err_last_method") });
        }

        await db.delete(identities).where(and(eq(identities.id, id), eq(identities.tenantId, tenant.id), eq(identities.userId, locals.user.id)));

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: locals.user.id,
            actorId: locals.user.id,
            kind: "social_identity_unlinked",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { provider: target.provider },
        });

        // 로그인 수단이 사라지는 변경은 계정 탈취 정황일 수 있으므로 본인에게 알린다.
        // fire-and-forget — 발송 실패가 해제 자체를 되돌리지는 않는다.
        dispatchSecurityAlert({
            to: locals.user.email,
            locale: locals.user.locale,
            kind: "social_identity_unlinked",
            platform: event.platform,
        });

        return { unlinked: true };
    },
};
