import { fail } from "@sveltejs/kit";
import { and, asc, desc, eq } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { createAdminCrudRoute } from "$lib/server/admin/crud-factory";
import { termsCreateSchema, termsUpdateSchema } from "$lib/server/admin/schemas";
import { adminError, requireFormId } from "$lib/server/admin/errors";
import { FALLBACK_LOCALE } from "$lib/i18n/core";
import { requireAdminContext } from "$lib/server/auth/guards";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { clientTerms, oidcClients, samlSps, termsDocuments } from "$lib/server/db/schema";

/**
 * 약관 문서 관리.
 *
 * 정형 CRUD 는 팩토리에 맡기고, 이 화면에만 있는 세 동작을 따로 둔다.
 *
 *   publish / unpublish — `publishedAt` 토글. 초안은 사용자에게 노출되지 않으므로 본문을 다
 *     쓴 뒤 발행하는 흐름이 된다. **발행 즉시 대상 사용자에게 동의 요구가 걸린다.**
 *   mapClient / unmapClient — 앱별 노출 매핑. 문서 id 가 아니라 `key` 로 걸어 개정 때 다시 걸지
 *     않아도 된다. 매핑이 하나도 없는 key 는 전역 약관이다.
 *
 * `key` 와 `version` 은 만든 뒤 바꿀 수 없다(update 스키마에 없다). 동의 기록이 (key, version) 을
 * 가리키므로 나중에 바꾸면 이미 받은 동의가 어떤 문서에 대한 것인지 알 수 없게 된다. 개정은
 * version 을 올린 **새 문서**를 만드는 것이다.
 */
const route = createAdminCrudRoute({
    table: termsDocuments,
    auditPrefix: "terms_document",
    createSchema: termsCreateSchema,
    updateSchema: termsUpdateSchema,
    load: async ({ db, tenant }) => {
        const [docs, mappings, oidcList, samlList] = await Promise.all([
            db.select().from(termsDocuments).where(eq(termsDocuments.tenantId, tenant.id)).orderBy(asc(termsDocuments.displayOrder), asc(termsDocuments.key), desc(termsDocuments.version)),
            db.select().from(clientTerms).where(eq(clientTerms.tenantId, tenant.id)),
            db.select({ id: oidcClients.id, name: oidcClients.name, clientId: oidcClients.clientId }).from(oidcClients).where(eq(oidcClients.tenantId, tenant.id)),
            db.select({ id: samlSps.id, name: samlSps.name, entityId: samlSps.entityId }).from(samlSps).where(eq(samlSps.tenantId, tenant.id)),
        ]);
        return { docs, mappings, oidcList, samlList };
    },
    /**
     * (key, version, locale) 유니크 위반을 **미리** 잡는다.
     *
     * 팩토리는 insert 예외를 그대로 올리므로 그냥 두면 관리자에게 500 이 보인다. 개정 작업 중
     * 같은 버전을 두 번 만드는 것은 흔한 실수라 친절한 409 로 돌려주는 편이 맞다.
     */
    beforeCreate: async ({ db, tenant }, v) => {
        const [dup] = await db
            .select({ id: termsDocuments.id })
            .from(termsDocuments)
            .where(and(eq(termsDocuments.tenantId, tenant.id), eq(termsDocuments.key, v.key), eq(termsDocuments.version, v.version), eq(termsDocuments.locale, v.locale)))
            .limit(1);
        // 훅 계약은 "사용자에게 보여줄 문구" — i18n 키가 아니라 해석된 값이다.
        // 훅에 locale 이 넘어오지 않으므로 기본 로케일로 해석한다(다른 admin 훅들과 같은 한계).
        return dup ? adminError(FALLBACK_LOCALE, "terms_document_exists") : null;
    },
    buildCreateDetail: (v) => ({ key: v.key, version: v.version, locale: v.locale, required: v.required }),
    buildUpdateDetail: (id, v) => ({ id, title: v.title, required: v.required }),
});

/** 발행 상태를 토글한다. 발행은 곧 사용자에게 동의 요구가 걸린다는 뜻이라 감사에 남긴다. */
async function setPublished(event: Parameters<Actions[string]>[0], published: boolean) {
    const { db, tenant, user } = requireAdminContext(event.locals);
    const locale = event.locals.locale;
    const fd = await event.request.formData();
    const parsed = requireFormId(fd, locale);
    if (!parsed.ok) return parsed.failure;

    const [doc] = await db
        .select()
        .from(termsDocuments)
        .where(and(eq(termsDocuments.id, parsed.id), eq(termsDocuments.tenantId, tenant.id)))
        .limit(1);
    if (!doc) return fail(404, { error: adminError(locale, "terms_not_found") });

    await db
        .update(termsDocuments)
        .set({ publishedAt: published ? new Date() : null })
        .where(eq(termsDocuments.id, parsed.id));

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        actorId: user.id,
        kind: published ? "terms_document_published" : "terms_document_unpublished",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { id: parsed.id, key: doc.key, version: doc.version, locale: doc.locale },
    });

    return { published };
}

export const load: PageServerLoad = route.load;

export const actions: Actions = {
    ...route.actions,

    publish: (event) => setPublished(event, true),
    unpublish: (event) => setPublished(event, false),

    /** 약관 key 를 앱에 매핑한다 — 그 앱으로 SSO 할 때만 노출된다. */
    mapClient: async (event) => {
        const { db, tenant, user } = requireAdminContext(event.locals);
        const locale = event.locals.locale;
        const fd = await event.request.formData();

        const termsKey = String(fd.get("termsKey") ?? "").trim();
        const clientType = fd.get("clientType");
        const clientRefId = String(fd.get("clientRefId") ?? "").trim();
        if (!termsKey || !clientRefId || (clientType !== "oidc" && clientType !== "saml")) {
            return fail(400, { map: true, error: adminError(locale, "invalid_request") });
        }

        // 존재하는 key 인지 확인한다 — 오타로 아무 앱에도 뜨지 않는 매핑이 조용히 생기는 것을 막는다.
        const [doc] = await db
            .select({ key: termsDocuments.key })
            .from(termsDocuments)
            .where(and(eq(termsDocuments.tenantId, tenant.id), eq(termsDocuments.key, termsKey)))
            .limit(1);
        if (!doc) return fail(400, { map: true, error: adminError(locale, "terms_not_found") });

        try {
            await db.insert(clientTerms).values({ tenantId: tenant.id, clientType, clientRefId, termsKey });
        } catch {
            return fail(409, { map: true, error: adminError(locale, "terms_mapping_exists") });
        }

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: user.id,
            spOrClientId: clientRefId,
            kind: "terms_mapping_created",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { termsKey, clientType, clientRefId },
        });
        return { mapped: true };
    },

    unmapClient: async (event) => {
        const { db, tenant, user } = requireAdminContext(event.locals);
        const locale = event.locals.locale;
        const fd = await event.request.formData();
        const parsed = requireFormId(fd, locale);
        if (!parsed.ok) return parsed.failure;

        const [row] = await db
            .select()
            .from(clientTerms)
            .where(and(eq(clientTerms.id, parsed.id), eq(clientTerms.tenantId, tenant.id)))
            .limit(1);
        if (!row) return fail(404, { error: adminError(locale, "terms_not_found") });

        await db.delete(clientTerms).where(eq(clientTerms.id, parsed.id));

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: user.id,
            spOrClientId: row.clientRefId,
            kind: "terms_mapping_deleted",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { termsKey: row.termsKey, clientType: row.clientType, clientRefId: row.clientRefId },
        });
        return { unmapped: true };
    },
};
