import { fail } from "@sveltejs/kit";
import { and, desc, eq } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireAdminContext } from "$lib/server/auth/guards";
import { ensureCsrfToken } from "$lib/server/auth/csrf";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";
import { serviceApiTokens } from "$lib/server/db/schema";
import { adminError, requireCsrf, requireFormId } from "$lib/server/admin/errors";
import { generateServiceToken, hashServiceToken, SERVICE_API_SCOPES } from "$lib/server/auth/service-token";

/**
 * 서비스 API 토큰 발급·폐기.
 *
 * 평문은 **생성 응답에 한 번만** 실린다(DB 엔 해시만). OIDC client_secret 화면과 같은 계약이고,
 * 잃어버리면 재발급밖에 없다 — 해시에서 평문을 되돌릴 수 없기 때문이다.
 */
export const load: PageServerLoad = async ({ locals, cookies, url }) => {
    const { db, tenant } = requireAdminContext(locals);
    const csrfToken = ensureCsrfToken(cookies, url);

    const tokens = await db
        .select({
            id: serviceApiTokens.id,
            name: serviceApiTokens.name,
            tokenPrefix: serviceApiTokens.tokenPrefix,
            scopes: serviceApiTokens.scopes,
            createdAt: serviceApiTokens.createdAt,
            expiresAt: serviceApiTokens.expiresAt,
            lastUsedAt: serviceApiTokens.lastUsedAt,
        })
        .from(serviceApiTokens)
        .where(eq(serviceApiTokens.tenantId, tenant.id))
        .orderBy(desc(serviceApiTokens.createdAt));

    return { tokens, csrfToken, availableScopes: SERVICE_API_SCOPES };
};

export const actions: Actions = {
    create: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;

        const name = String(fd.get("name") ?? "").trim();
        if (!name) return fail(400, { create: true, error: adminError(locale, "name_required") });

        // 체크된 스코프만. 정의된 것 외의 값은 폼 위조 신호이므로 조용히 무시하지 않고 거부한다.
        const requested = [
            ...new Set(
                fd
                    .getAll("scopes")
                    .map((v) => String(v))
                    .filter(Boolean),
            ),
        ];
        for (const s of requested) {
            if (!(SERVICE_API_SCOPES as readonly string[]).includes(s)) {
                return fail(400, { create: true, error: adminError(locale, "invalid_service_scope") });
            }
        }
        if (requested.length === 0) return fail(400, { create: true, error: adminError(locale, "service_scope_required") });

        const expiresAtRaw = String(fd.get("expiresAt") ?? "").trim();
        let expiresAt: Date | null = null;
        if (expiresAtRaw) {
            const d = new Date(expiresAtRaw);
            if (Number.isNaN(d.getTime())) return fail(400, { create: true, error: adminError(locale, "invalid_expiry_format") });
            expiresAt = d;
        }

        const plain = generateServiceToken();
        await db.insert(serviceApiTokens).values({
            id: crypto.randomUUID(),
            tenantId: tenant.id,
            name,
            tokenHash: await hashServiceToken(plain),
            tokenPrefix: plain.slice(0, 12),
            scopes: requested.join(" "),
            createdBy: locals.user!.id,
            expiresAt,
        });

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            kind: "service_api_token_created",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            // 평문은 절대 남기지 않는다. 접두사만으로 어느 토큰인지 대조된다.
            detail: { name, scopes: requested, tokenPrefix: plain.slice(0, 12), expiresAt: expiresAt?.toISOString() ?? null },
        });

        // 평문은 여기서만 밖으로 나간다.
        return { created: true, token: plain, name };
    },

    // 폐기는 행 삭제다 — 소프트 회수 컬럼을 두지 않았다(PLAN §3). 이력은 감사에 남는다.
    revoke: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;

        const idr = requireFormId(fd, locale, { field: "tokenId" });
        if (!idr.ok) return idr.failure;
        const id = idr.id;

        const scope = and(eq(serviceApiTokens.id, id), eq(serviceApiTokens.tenantId, tenant.id));
        const [row] = await db.select({ name: serviceApiTokens.name, tokenPrefix: serviceApiTokens.tokenPrefix, scopes: serviceApiTokens.scopes }).from(serviceApiTokens).where(scope).limit(1);
        if (!row) return fail(404, { error: adminError(locale, "service_token_not_found") });

        await db.delete(serviceApiTokens).where(scope);

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            kind: "service_api_token_revoked",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { name: row.name, tokenPrefix: row.tokenPrefix, scopes: row.scopes.split(/\s+/).filter(Boolean) },
        });

        return { revoked: true };
    },
};
