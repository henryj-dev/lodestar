import { error, fail } from "@sveltejs/kit";
import { and, asc, eq } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireAdminContext } from "$lib/server/auth/guards";
import { ensureCsrfToken } from "$lib/server/auth/csrf";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";
import type { DB } from "$lib/server/db";
import { oidcClients, serviceEntitlements, serviceRoles, userServiceAssignments, userServiceEntitlements } from "$lib/server/db/schema";
import { isUniqueViolation } from "$lib/server/db/errors";
import { revokeRefreshTokenFamily } from "$lib/server/oidc/refresh";
import { emitRoleChangeSet } from "$lib/server/admin/user-actions/service";
import { adminError, requireCsrf, requireFormId } from "$lib/server/admin/errors";
import { SERVICE_KEY_RE, normalizeEntitlementKey } from "$lib/server/admin/schemas";
import { ORGANIZATION_CLAIM_FIELDS, type OrganizationClaimConfig } from "$lib/server/oidc/claims";

export const load: PageServerLoad = async ({ locals, params, cookies, url }) => {
    const { db, tenant } = requireAdminContext(locals);
    const csrfToken = ensureCsrfToken(cookies, url);

    const [client] = await db
        .select()
        .from(oidcClients)
        .where(and(eq(oidcClients.id, params.id), eq(oidcClients.tenantId, tenant.id)))
        .limit(1);
    if (!client) error(404, adminError(locals.locale, "client_not_found"));

    const roles = await db
        .select()
        .from(serviceRoles)
        .where(and(eq(serviceRoles.tenantId, tenant.id), eq(serviceRoles.serviceType, "oidc"), eq(serviceRoles.serviceRefId, client.id)))
        .orderBy(asc(serviceRoles.displayOrder), asc(serviceRoles.key));

    // entitlement 는 displayOrder 순으로 내려보낸다 — 관리자가 체크박스를 위에서 아래로 읽으며
    // 권한 간 의존("아래를 켜려면 위도")을 파악하는 것이 이 순서의 유일한 근거다(의존은 모델에 없다).
    const entitlements = await db
        .select()
        .from(serviceEntitlements)
        .where(and(eq(serviceEntitlements.tenantId, tenant.id), eq(serviceEntitlements.serviceType, "oidc"), eq(serviceEntitlements.serviceRefId, client.id)))
        .orderBy(asc(serviceEntitlements.displayOrder), asc(serviceEntitlements.key));

    return { client, roles, entitlements, csrfToken };
};

async function clientForTenant(db: DB, tenantId: string, clientDbId: string) {
    const [c] = await db
        .select({ id: oidcClients.id })
        .from(oidcClients)
        .where(and(eq(oidcClients.id, clientDbId), eq(oidcClients.tenantId, tenantId)))
        .limit(1);
    return c ?? null;
}

export const actions: Actions = {
    addRole: async (event) => {
        const { locals, params } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;

        const key = String(fd.get("key") ?? "").trim();
        const label = String(fd.get("label") ?? "").trim();
        const description = String(fd.get("description") ?? "").trim() || null;
        const isDefault = fd.get("isDefault") === "true";
        const displayOrder = Number(fd.get("displayOrder") ?? "0") | 0;

        if (!SERVICE_KEY_RE.test(key)) return fail(400, { error: adminError(locale, "invalid_role_key") });
        if (!label) return fail(400, { error: adminError(locale, "label_required") });

        const c = await clientForTenant(db, tenant.id, params.id);
        if (!c) return fail(404, { error: adminError(locale, "client_not_found") });

        try {
            await db.insert(serviceRoles).values({
                id: crypto.randomUUID(),
                tenantId: tenant.id,
                serviceType: "oidc",
                serviceRefId: c.id,
                key,
                label,
                description,
                isDefault,
                displayOrder,
            });
        } catch {
            // unique (serviceType, serviceRefId, key)
            return fail(409, { error: adminError(locale, "role_key_exists") });
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
            detail: { serviceType: "oidc", serviceRefId: c.id, key },
        });

        return { added: true };
    },

    updateRole: async (event) => {
        const { locals, params } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;

        const id = String(fd.get("roleId") ?? "");
        const label = String(fd.get("label") ?? "").trim();
        const description = String(fd.get("description") ?? "").trim() || null;
        const isDefault = fd.get("isDefault") === "true";
        const displayOrder = Number(fd.get("displayOrder") ?? "0") | 0;

        if (!id || !label) return fail(400, { error: adminError(locale, "required_field_missing") });

        await db
            .update(serviceRoles)
            .set({ label, description, isDefault, displayOrder, updatedAt: new Date() })
            .where(and(eq(serviceRoles.id, id), eq(serviceRoles.tenantId, tenant.id), eq(serviceRoles.serviceType, "oidc"), eq(serviceRoles.serviceRefId, params.id)));

        // entitlement 쪽과 같은 이유로 남긴다 — label 은 관리자가 부여를 판단하는 근거이고,
        // 조용히 바꿀 수 있으면 "다른 것인 줄 알고 골랐다" 가 성립한다.
        const roleMeta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            spOrClientId: params.id,
            kind: "service_role_updated",
            outcome: "success",
            ip: roleMeta.ip,
            userAgent: roleMeta.userAgent,
            detail: { serviceType: "oidc", serviceRefId: params.id, roleId: id, label, isDefault, displayOrder },
        });

        return { updated: true };
    },

    // organization scope 클레임의 클라이언트별 노출 토글 저장.
    // 네 필드가 모두 켜져 있으면 null(=미설정=전량 노출, 하위호환)로 저장해 DB 를 깨끗이 유지하고,
    // 하나라도 꺼져 있으면 명시적 JSON config 를 저장한다. token/userinfo 양쪽이 동일 config 를 적용한다.
    updateOrganizationClaims: async (event) => {
        const { locals, params } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;

        const c = await clientForTenant(db, tenant.id, params.id);
        if (!c) return fail(404, { error: adminError(locale, "client_not_found") });

        const config: OrganizationClaimConfig = {};
        let allEnabled = true;
        for (const field of ORGANIZATION_CLAIM_FIELDS) {
            const enabled = fd.get(field) === "true";
            config[field] = enabled;
            if (!enabled) allEnabled = false;
        }

        const value = allEnabled ? null : JSON.stringify(config);
        await db
            .update(oidcClients)
            .set({ organizationClaimConfig: value, updatedAt: new Date() })
            .where(and(eq(oidcClients.id, c.id), eq(oidcClients.tenantId, tenant.id)));

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            spOrClientId: params.id,
            kind: "oidc_client_updated",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { organizationClaimConfig: value },
        });

        return { organizationClaimsUpdated: true };
    },

    // ── entitlement (권한) 정의 ──────────────────────────────────────────────
    // role 액션과 같은 모양이되 isDefault 가 없다 — 권한의 기본 부여는 "누가 줬는가" 에 답이
    // 없는 권한을 만든다. 전부 명시 부여로 둔다.
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

        const c = await clientForTenant(db, tenant.id, params.id);
        if (!c) return fail(404, { error: adminError(locale, "client_not_found") });

        try {
            await db.insert(serviceEntitlements).values({
                id: crypto.randomUUID(),
                tenantId: tenant.id,
                serviceType: "oidc",
                serviceRefId: c.id,
                key,
                label,
                description,
                displayOrder,
            });
        } catch (err) {
            // unique (serviceType, serviceRefId, key) 만 409 로 매핑한다. 나머지(연결 오류 등)를
            // 함께 삼키면 실제 장애가 "중복 key" 라는 엉뚱한 메시지로 보인다.
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
            detail: { serviceType: "oidc", serviceRefId: c.id, key },
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

        const scope = and(eq(serviceEntitlements.id, id), eq(serviceEntitlements.tenantId, tenant.id), eq(serviceEntitlements.serviceType, "oidc"), eq(serviceEntitlements.serviceRefId, params.id));

        // 대상이 실제로 이 서비스의 것인지 먼저 확인한다. 없는데도 성공을 돌려주면
        // 다른 서비스의 id 를 넣어 본 사람이 "되었다" 는 응답을 받는다.
        const [before] = await db
            .select({ key: serviceEntitlements.key, label: serviceEntitlements.label, displayOrder: serviceEntitlements.displayOrder })
            .from(serviceEntitlements)
            .where(scope)
            .limit(1);
        if (!before) return fail(404, { error: adminError(locale, "entitlement_not_found") });

        await db.update(serviceEntitlements).set({ label, description, displayOrder, updatedAt: new Date() }).where(scope);

        // label 과 displayOrder 는 관리자가 부여를 판단하는 근거다(체크박스 옆 설명과 순서).
        // 조용히 바꿀 수 있으면 "다른 것인 줄 알고 체크했다" 가 성립하므로 변경을 남긴다.
        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            spOrClientId: params.id,
            kind: "service_entitlement_updated",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: {
                serviceType: "oidc",
                serviceRefId: params.id,
                entitlementId: id,
                key: before.key,
                from: { label: before.label, displayOrder: before.displayOrder },
                to: { label, displayOrder },
            },
        });

        return { entitlementUpdated: true };
    },

    // 정의를 지우면 그 권한을 부여받은 **모든 사용자**의 권한이 cascade 로 사라진다.
    // 즉 이것은 대량 회수이므로, 개별 회수(setAssignmentEntitlements)가 하는 세 가지를 여기서도 한다:
    //   1. 보유자별 감사 — revokedAt 컬럼을 두지 않았으므로 이력이 남는 곳은 감사뿐이다. 정의 행이
    //      지워지면 id→key 매핑이 사라지므로 **key 를 먼저 읽어** 기록한다(id 만 남기면
    //      "누가 그 권한을 갖고 있었나" 에 영영 답할 수 없다).
    //   2. refresh family 폐기 — 정책 C 의 "제거" 에 해당한다.
    //   3. SET 발행 — 자체 세션을 쓰는 RP 에게는 이것이 유일한 회수 수단이다.
    deleteEntitlement: async (event) => {
        const { locals, params } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;
        const idr = requireFormId(fd, locale, { field: "entitlementId" });
        if (!idr.ok) return idr.failure;
        const id = idr.id;

        const scope = and(eq(serviceEntitlements.id, id), eq(serviceEntitlements.tenantId, tenant.id), eq(serviceEntitlements.serviceType, "oidc"), eq(serviceEntitlements.serviceRefId, params.id));

        // 삭제 전에 key 와 영향받는 사용자를 확보한다 — 삭제 후에는 둘 다 복원 불가.
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
            detail: { serviceType: "oidc", serviceRefId: params.id, entitlementId: id, key: ent.key, affectedUsers: affectedUserIds.length },
        });

        const [client] = await db
            .select({ clientId: oidcClients.clientId })
            .from(oidcClients)
            .where(and(eq(oidcClients.id, params.id), eq(oidcClients.tenantId, tenant.id)))
            .limit(1);

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
                detail: { serviceType: "oidc", serviceRefId: params.id, entitlementKey: ent.key, cause: "definition_deleted" },
            });
            if (client) await revokeRefreshTokenFamily(db, tenant.id, userId, client.clientId);
            await emitRoleChangeSet(event, db, tenant.id, userId, "oidc", params.id);
        }

        return { entitlementDeleted: true, affectedUsers: affectedUserIds.length };
    },

    deleteRole: async (event) => {
        const { locals, params } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await event.request.formData();
        const csrfFail = requireCsrf(event, fd);
        if (csrfFail) return csrfFail;
        const idr = requireFormId(fd, locale, { field: "roleId" });
        if (!idr.ok) return idr.failure;
        const id = idr.id;

        await db.delete(serviceRoles).where(and(eq(serviceRoles.id, id), eq(serviceRoles.tenantId, tenant.id), eq(serviceRoles.serviceType, "oidc"), eq(serviceRoles.serviceRefId, params.id)));

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            spOrClientId: params.id,
            kind: "service_role_deleted",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { serviceType: "oidc", serviceRefId: params.id, roleId: id },
        });

        return { deleted: true };
    },
};
