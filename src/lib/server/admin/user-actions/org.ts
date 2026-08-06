import { fail } from "@sveltejs/kit";
import type { RequestEvent } from "@sveltejs/kit";
import { and, eq } from "drizzle-orm";
import { requireAdminContext } from "$lib/server/auth/guards";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";
import { departments, parts, positions, teams, userDepartments, userParts, userTeams, users } from "$lib/server/db/schema";
import { adminError, requireCsrf, requireFormId } from "$lib/server/admin/errors";

// 사용자 상세 페이지의 조직 소속(부서/팀/파트) 배치 액션.
type UserActionEvent = RequestEvent<{ id: string }, "/admin/users/[id]">;

// 부서 소속 추가
export async function addDept(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const locale = locals.locale;
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;
    const userId = params.id;
    const departmentId = String(fd.get("departmentId") ?? "");
    const positionId = String(fd.get("positionId") ?? "").trim() || null;
    const jobTitle = String(fd.get("jobTitle") ?? "").trim() || null;
    const isPrimary = fd.get("isPrimary") === "true";

    if (!departmentId) return fail(400, { error: adminError(locale, "select_department") });

    const [targetUser] = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.id, userId), eq(users.tenantId, tenant.id)))
        .limit(1);
    if (!targetUser) return fail(404, { error: adminError(locale, "user_not_found") });

    const [dept] = await db
        .select({ id: departments.id })
        .from(departments)
        .where(and(eq(departments.id, departmentId), eq(departments.tenantId, tenant.id)))
        .limit(1);
    if (!dept) return fail(404, { error: adminError(locale, "department_not_found") });

    if (positionId) {
        const [pos] = await db
            .select({ id: positions.id })
            .from(positions)
            .where(and(eq(positions.id, positionId), eq(positions.tenantId, tenant.id)))
            .limit(1);
        if (!pos) return fail(404, { error: adminError(locale, "position_not_found") });
    }

    const membershipId = crypto.randomUUID();
    await db.insert(userDepartments).values({ id: membershipId, tenantId: tenant.id, userId, departmentId, positionId, jobTitle, isPrimary });

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId,
        actorId: locals.user!.id,
        kind: "membership_change",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { membershipId, action: "add_dept", departmentId, positionId, isPrimary },
    });

    return { addedDept: true };
}

// 부서 소속 제거 (endedAt 설정)
export async function removeDept(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;
    const idr = requireFormId(fd, locals.locale, { field: "membershipId" });
    if (!idr.ok) return idr.failure;
    const membershipId = idr.id;

    // IDOR 방어: membershipId가 본 페이지의 userId 소유인지도 확인
    const result = await db
        .update(userDepartments)
        .set({ endedAt: new Date() })
        .where(and(eq(userDepartments.id, membershipId), eq(userDepartments.userId, params.id), eq(userDepartments.tenantId, tenant.id)));

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId: params.id,
        actorId: locals.user!.id,
        kind: "membership_change",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { membershipId, action: "remove_dept" },
    });

    void result;
    return { removedDept: true };
}

// 팀 소속 추가
export async function addTeam(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const locale = locals.locale;
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;
    const userId = params.id;
    const teamId = String(fd.get("teamId") ?? "");
    const jobTitle = String(fd.get("jobTitle") ?? "").trim() || null;
    const isPrimary = fd.get("isPrimary") === "true";

    if (!teamId) return fail(400, { error: adminError(locale, "select_team") });

    const [targetUser] = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.id, userId), eq(users.tenantId, tenant.id)))
        .limit(1);
    if (!targetUser) return fail(404, { error: adminError(locale, "user_not_found") });

    const [team] = await db
        .select({ id: teams.id })
        .from(teams)
        .where(and(eq(teams.id, teamId), eq(teams.tenantId, tenant.id)))
        .limit(1);
    if (!team) return fail(404, { error: adminError(locale, "team_not_found") });

    const membershipId = crypto.randomUUID();
    await db.insert(userTeams).values({ id: membershipId, tenantId: tenant.id, userId, teamId, jobTitle, isPrimary });

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId,
        actorId: locals.user!.id,
        kind: "membership_change",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { membershipId, action: "add_team", teamId, isPrimary },
    });

    return { addedTeam: true };
}

// 팀 소속 제거
export async function removeTeam(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;
    const idr = requireFormId(fd, locals.locale, { field: "membershipId" });
    if (!idr.ok) return idr.failure;
    const membershipId = idr.id;

    await db
        .update(userTeams)
        .set({ endedAt: new Date() })
        .where(and(eq(userTeams.id, membershipId), eq(userTeams.userId, params.id), eq(userTeams.tenantId, tenant.id)));

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId: params.id,
        actorId: locals.user!.id,
        kind: "membership_change",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { membershipId, action: "remove_team" },
    });

    return { removedTeam: true };
}

// 파트 소속 추가
export async function addPart(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const locale = locals.locale;
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;
    const userId = params.id;
    const partId = String(fd.get("partId") ?? "");
    const jobTitle = String(fd.get("jobTitle") ?? "").trim() || null;
    const isPrimary = fd.get("isPrimary") === "true";

    if (!partId) return fail(400, { error: adminError(locale, "select_part") });

    const [targetUser] = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.id, userId), eq(users.tenantId, tenant.id)))
        .limit(1);
    if (!targetUser) return fail(404, { error: adminError(locale, "user_not_found") });

    const [part] = await db
        .select({ id: parts.id })
        .from(parts)
        .where(and(eq(parts.id, partId), eq(parts.tenantId, tenant.id)))
        .limit(1);
    if (!part) return fail(404, { error: adminError(locale, "part_not_found") });

    const membershipId = crypto.randomUUID();
    await db.insert(userParts).values({ id: membershipId, tenantId: tenant.id, userId, partId, jobTitle, isPrimary });

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId,
        actorId: locals.user!.id,
        kind: "membership_change",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { membershipId, action: "add_part", partId, isPrimary },
    });

    return { addedPart: true };
}

// 파트 소속 제거
export async function removePart(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;
    const idr = requireFormId(fd, locals.locale, { field: "membershipId" });
    if (!idr.ok) return idr.failure;
    const membershipId = idr.id;

    await db
        .update(userParts)
        .set({ endedAt: new Date() })
        .where(and(eq(userParts.id, membershipId), eq(userParts.userId, params.id), eq(userParts.tenantId, tenant.id)));

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId: params.id,
        actorId: locals.user!.id,
        kind: "membership_change",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { membershipId, action: "remove_part" },
    });

    return { removedPart: true };
}
