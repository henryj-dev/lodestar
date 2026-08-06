import { error, fail } from "@sveltejs/kit";
import { and, asc, eq } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireAdminContext } from "$lib/server/auth/guards";
import { ensureCsrfToken } from "$lib/server/auth/csrf";
import { adminError, requireCsrf } from "$lib/server/admin/errors";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";
import type { DB } from "$lib/server/db";
import { samlSps, serviceEntitlements, serviceRoles, userServiceAssignments, userServiceEntitlements } from "$lib/server/db/schema";
import { SERVICE_KEY_RE, normalizeEntitlementKey } from "$lib/server/admin/schemas";
import { isUniqueViolation } from "$lib/server/db/errors";

// entitlement 정의 UI 는 SAML SSO 의 `Entitlements` 속성 발행과 **같이** 붙었다.
// 정의만 먼저 넣으면 관리자가 권한을 만들고 배정했는데 SP 에는 아무것도 가지 않는
// 조용한 무동작이 되므로, 둘을 분리하지 않는다.
// SP 가 allowedAttributes 에 "Entitlements" 를 넣어야 실제로 전달된다는 점도 화면에 적었다.

export const load: PageServerLoad = async ({ locals, params, cookies, url }) => {
    const { db, tenant } = requireAdminContext(locals);
    const csrfToken = ensureCsrfToken(cookies, url);

    const [sp] = await db
        .select()
        .from(samlSps)
        .where(and(eq(samlSps.id, params.id), eq(samlSps.tenantId, tenant.id)))
        .limit(1);
    if (!sp) error(404, adminError(locals.locale, "saml_sp_not_found"));

    const roles = await db
        .select()
        .from(serviceRoles)
        .where(and(eq(serviceRoles.tenantId, tenant.id), eq(serviceRoles.serviceType, "saml"), eq(serviceRoles.serviceRefId, sp.id)))
        .orderBy(asc(serviceRoles.displayOrder), asc(serviceRoles.key));

    const entitlements = await db
        .select()
        .from(serviceEntitlements)
        .where(and(eq(serviceEntitlements.tenantId, tenant.id), eq(serviceEntitlements.serviceType, "saml"), eq(serviceEntitlements.serviceRefId, sp.id)))
        .orderBy(asc(serviceEntitlements.displayOrder), asc(serviceEntitlements.key));

    return { sp, roles, entitlements, csrfToken };
};

async function spForTenant(db: DB, tenantId: string, spDbId: string) {
    const [s] = await db
        .select({ id: samlSps.id })
        .from(samlSps)
        .where(and(eq(samlSps.id, spDbId), eq(samlSps.tenantId, tenantId)))
        .limit(1);
    return s ?? null;
}

export const actions: Actions = {
    addRole: async (event) => {
        const { locals, params } = event;
        const { db, tenant } = requireAdminContext(locals);
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;

        const key = String(fd.get("key") ?? "").trim();
        const label = String(fd.get("label") ?? "").trim();
        const description = String(fd.get("description") ?? "").trim() || null;
        const isDefault = fd.get("isDefault") === "true";
        const displayOrder = Number(fd.get("displayOrder") ?? "0") | 0;

        if (!SERVICE_KEY_RE.test(key)) return fail(400, { error: adminError(locals.locale, "invalid_role_key") });
        if (!label) return fail(400, { error: adminError(locals.locale, "label_required") });

        const s = await spForTenant(db, tenant.id, params.id);
        if (!s) return fail(404, { error: adminError(locals.locale, "saml_sp_not_found") });

        try {
            await db.insert(serviceRoles).values({
                id: crypto.randomUUID(),
                tenantId: tenant.id,
                serviceType: "saml",
                serviceRefId: s.id,
                key,
                label,
                description,
                isDefault,
                displayOrder,
            });
        } catch {
            return fail(409, { error: adminError(locals.locale, "role_key_exists") });
        }

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            spOrClientId: params.id,
            kind: "service_role_created",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { serviceType: "saml", serviceRefId: s.id, key },
        });

        return { added: true };
    },

    updateRole: async (event) => {
        const { locals, params } = event;
        const { db, tenant } = requireAdminContext(locals);
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;

        const id = String(fd.get("roleId") ?? "");
        const label = String(fd.get("label") ?? "").trim();
        const description = String(fd.get("description") ?? "").trim() || null;
        const isDefault = fd.get("isDefault") === "true";
        const displayOrder = Number(fd.get("displayOrder") ?? "0") | 0;

        if (!id || !label) return fail(400, { error: adminError(locals.locale, "required_field_missing") });

        await db
            .update(serviceRoles)
            .set({ label, description, isDefault, displayOrder, updatedAt: new Date() })
            .where(and(eq(serviceRoles.id, id), eq(serviceRoles.tenantId, tenant.id), eq(serviceRoles.serviceType, "saml"), eq(serviceRoles.serviceRefId, params.id)));

        return { updated: true };
    },

    deleteRole: async (event) => {
        const { locals, params } = event;
        const { db, tenant } = requireAdminContext(locals);
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;
        const id = String(fd.get("roleId") ?? "");
        if (!id) return fail(400, { error: adminError(locals.locale, "invalid_request") });

        await db.delete(serviceRoles).where(and(eq(serviceRoles.id, id), eq(serviceRoles.tenantId, tenant.id), eq(serviceRoles.serviceType, "saml"), eq(serviceRoles.serviceRefId, params.id)));

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            spOrClientId: params.id,
            kind: "service_role_deleted",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { serviceType: "saml", serviceRefId: params.id, roleId: id },
        });

        return { deleted: true };
    },

    // ── entitlement (권한) 정의 ──────────────────────────────────────────────
    // oidc-clients/[id] 와 같은 모양. serviceType 만 "saml" 이다.
    addEntitlement: async (event) => {
        const { locals, params } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;

        const key = normalizeEntitlementKey(String(fd.get("key") ?? ""));
        const label = String(fd.get("label") ?? "").trim();
        const description = String(fd.get("description") ?? "").trim() || null;
        const displayOrder = Number(fd.get("displayOrder") ?? "0") | 0;

        if (!SERVICE_KEY_RE.test(key)) return fail(400, { error: adminError(locale, "invalid_entitlement_key") });
        if (!label) return fail(400, { error: adminError(locale, "label_required") });

        const sp = await spForTenant(db, tenant.id, params.id);
        if (!sp) return fail(404, { error: adminError(locale, "saml_sp_not_found") });

        try {
            await db.insert(serviceEntitlements).values({
                id: crypto.randomUUID(),
                tenantId: tenant.id,
                serviceType: "saml",
                serviceRefId: sp.id,
                key,
                label,
                description,
                displayOrder,
            });
        } catch (err) {
            if (!isUniqueViolation(err)) throw err;
            return fail(409, { error: adminError(locale, "entitlement_key_exists") });
        }

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            spOrClientId: params.id,
            kind: "service_entitlement_created",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { serviceType: "saml", serviceRefId: sp.id, key },
        });

        return { entitlementAdded: true };
    },

    updateEntitlement: async (event) => {
        const { locals, params } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;

        const id = String(fd.get("entitlementId") ?? "");
        const label = String(fd.get("label") ?? "").trim();
        const description = String(fd.get("description") ?? "").trim() || null;
        const displayOrder = Number(fd.get("displayOrder") ?? "0") | 0;

        if (!id || !label) return fail(400, { error: adminError(locale, "required_field_missing") });

        const scope = and(eq(serviceEntitlements.id, id), eq(serviceEntitlements.tenantId, tenant.id), eq(serviceEntitlements.serviceType, "saml"), eq(serviceEntitlements.serviceRefId, params.id));
        const [before] = await db
            .select({ key: serviceEntitlements.key, label: serviceEntitlements.label, displayOrder: serviceEntitlements.displayOrder })
            .from(serviceEntitlements)
            .where(scope)
            .limit(1);
        if (!before) return fail(404, { error: adminError(locale, "entitlement_not_found") });

        await db.update(serviceEntitlements).set({ label, description, displayOrder, updatedAt: new Date() }).where(scope);

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            spOrClientId: params.id,
            kind: "service_entitlement_updated",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { serviceType: "saml", serviceRefId: params.id, entitlementId: id, key: before.key, from: { label: before.label, displayOrder: before.displayOrder }, to: { label, displayOrder } },
        });

        return { entitlementUpdated: true };
    },

    // 정의 삭제 = 보유자 전원 회수. OIDC 쪽과 달리 SET(role-change)은 OIDC 전용이라 발행하지
    // 않지만, **보유자별 감사는 동일하게 남긴다** — 정의가 지워지면 id→key 매핑이 사라지므로
    // key 를 먼저 읽어 기록한다.
    deleteEntitlement: async (event) => {
        const { locals, params } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;
        const id = String(fd.get("entitlementId") ?? "");
        if (!id) return fail(400, { error: adminError(locale, "invalid_request") });

        const scope = and(eq(serviceEntitlements.id, id), eq(serviceEntitlements.tenantId, tenant.id), eq(serviceEntitlements.serviceType, "saml"), eq(serviceEntitlements.serviceRefId, params.id));
        const [ent] = await db.select({ key: serviceEntitlements.key }).from(serviceEntitlements).where(scope).limit(1);
        if (!ent) return fail(404, { error: adminError(locale, "entitlement_not_found") });

        const affected = await db
            .select({ userId: userServiceAssignments.userId })
            .from(userServiceEntitlements)
            .innerJoin(userServiceAssignments, eq(userServiceEntitlements.assignmentId, userServiceAssignments.id))
            .where(eq(userServiceEntitlements.serviceEntitlementId, id));
        const affectedUserIds = [...new Set(affected.map((a) => a.userId))];

        await db.delete(serviceEntitlements).where(scope);

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            spOrClientId: params.id,
            kind: "service_entitlement_deleted",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { serviceType: "saml", serviceRefId: params.id, entitlementId: id, key: ent.key, affectedUsers: affectedUserIds.length },
        });
        for (const userId of affectedUserIds) {
            await recordAuditEvent(db, {
                tenantId: tenant.id,
                userId,
                actorId: locals.user!.id,
                spOrClientId: params.id,
                kind: "user_entitlement_revoked",
                outcome: "success",
                ip: meta.ip,
                userAgent: meta.userAgent,
                detail: { serviceType: "saml", serviceRefId: params.id, entitlementKey: ent.key, cause: "definition_deleted" },
            });
        }

        return { entitlementDeleted: true, affectedUsers: affectedUserIds.length };
    },
};
