import { error, fail } from "@sveltejs/kit";
import { and, asc, eq } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireAdminContext } from "$lib/server/auth/guards";
import { adminError } from "$lib/server/admin/errors";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";
import type { DB } from "$lib/server/db";
import { samlSps, serviceRoles } from "$lib/server/db/schema";
import { SERVICE_KEY_RE } from "$lib/server/admin/schemas";

// entitlement 정의 UI 는 여기 없다 — SAML SSO 가 아직 entitlement 를 발행하지 않기 때문이다
// (attribute 명 미정). 정의만 할 수 있게 두면 관리자가 권한을 만들고 배정했는데 SP 에는
// 아무것도 가지 않는 조용한 무동작이 된다. 발행이 붙는 시점에 이 화면도 같이 추가한다.

export const load: PageServerLoad = async ({ locals, params }) => {
    const { db, tenant } = requireAdminContext(locals);

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

    return { sp, roles };
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
};
