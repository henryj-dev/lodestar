import { error } from "@sveltejs/kit";
import { and, asc, eq, isNull } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireAdminContext } from "$lib/server/auth/guards";
import {
    departments,
    oidcClients,
    parts,
    positions,
    samlSps,
    serviceEntitlements,
    serviceRoles,
    teams,
    userDepartments,
    userParts,
    userServiceAssignments,
    userServiceEntitlements,
    userTeams,
    users,
} from "$lib/server/db/schema";
import { updateProfile } from "$lib/server/admin/user-actions/profile";
import { addDept, removeDept, addTeam, removeTeam, addPart, removePart } from "$lib/server/admin/user-actions/org";
import { addAssignment, revokeAssignment, updateAssignmentExpiry, setAssignmentEntitlements } from "$lib/server/admin/user-actions/service";
import { forceLogout } from "$lib/server/admin/user-actions/security";
import { adminError } from "$lib/server/admin/errors";

export const load: PageServerLoad = async ({ locals, params }) => {
    const { db, tenant } = requireAdminContext(locals);
    const userId = params.id;

    // 유저 조회
    const [user] = await db
        .select()
        .from(users)
        .where(and(eq(users.id, userId), eq(users.tenantId, tenant.id)))
        .limit(1);

    if (!user) error(404, adminError(locals.locale, "user_not_found"));

    // 아래 조회는 서로 독립적이므로 병렬 실행한다. 순차 await 워터폴을 제거해
    // 관리자 상세 페이지 로드 지연을 대폭 단축한다.
    const [
        deptMemberships,
        teamMemberships,
        partMemberships,
        allDepts,
        allTeams,
        allParts,
        allPositions,
        assignments,
        allOidcClients,
        allSamlSps,
        allServiceRoles,
        allServiceEntitlements,
        grantedEntitlements,
    ] = await Promise.all([
        // 현재 부서 소속
        db
            .select({
                id: userDepartments.id,
                departmentId: userDepartments.departmentId,
                departmentName: departments.name,
                positionId: userDepartments.positionId,
                positionName: positions.name,
                jobTitle: userDepartments.jobTitle,
                isPrimary: userDepartments.isPrimary,
                startedAt: userDepartments.startedAt,
            })
            .from(userDepartments)
            .innerJoin(departments, eq(userDepartments.departmentId, departments.id))
            .leftJoin(positions, eq(userDepartments.positionId, positions.id))
            .where(and(eq(userDepartments.userId, userId), isNull(userDepartments.endedAt))),

        // 현재 팀 소속
        db
            .select({
                id: userTeams.id,
                teamId: userTeams.teamId,
                teamName: teams.name,
                departmentName: departments.name,
                jobTitle: userTeams.jobTitle,
                isPrimary: userTeams.isPrimary,
                startedAt: userTeams.startedAt,
            })
            .from(userTeams)
            .innerJoin(teams, eq(userTeams.teamId, teams.id))
            .leftJoin(departments, eq(teams.departmentId, departments.id))
            .where(and(eq(userTeams.userId, userId), isNull(userTeams.endedAt))),

        // 현재 파트 소속
        db
            .select({
                id: userParts.id,
                partId: userParts.partId,
                partName: parts.name,
                teamName: teams.name,
                jobTitle: userParts.jobTitle,
                isPrimary: userParts.isPrimary,
                startedAt: userParts.startedAt,
            })
            .from(userParts)
            .innerJoin(parts, eq(userParts.partId, parts.id))
            .leftJoin(teams, eq(parts.teamId, teams.id))
            .where(and(eq(userParts.userId, userId), isNull(userParts.endedAt))),

        // 선택 목록
        db
            .select({ id: departments.id, name: departments.name })
            .from(departments)
            .where(and(eq(departments.tenantId, tenant.id), eq(departments.status, "active")))
            .orderBy(asc(departments.name)),

        db
            .select({ id: teams.id, name: teams.name, departmentName: departments.name })
            .from(teams)
            .leftJoin(departments, eq(teams.departmentId, departments.id))
            .where(and(eq(teams.tenantId, tenant.id), eq(teams.status, "active")))
            .orderBy(asc(departments.name), asc(teams.name)),

        db
            .select({ id: parts.id, name: parts.name, teamName: teams.name })
            .from(parts)
            .leftJoin(teams, eq(parts.teamId, teams.id))
            .where(and(eq(parts.tenantId, tenant.id), eq(parts.status, "active")))
            .orderBy(asc(teams.name), asc(parts.name)),

        db.select({ id: positions.id, name: positions.name, level: positions.level }).from(positions).where(eq(positions.tenantId, tenant.id)).orderBy(asc(positions.level)),

        // 서비스 권한 — 활성/만료/취소 모두 함께 보여 줌. 필터링은 UI 에서.
        db
            .select({
                id: userServiceAssignments.id,
                serviceType: userServiceAssignments.serviceType,
                serviceRefId: userServiceAssignments.serviceRefId,
                serviceRoleId: userServiceAssignments.serviceRoleId,
                roleKey: serviceRoles.key,
                roleLabel: serviceRoles.label,
                attributesJson: userServiceAssignments.attributesJson,
                grantedAt: userServiceAssignments.grantedAt,
                expiresAt: userServiceAssignments.expiresAt,
                revokedAt: userServiceAssignments.revokedAt,
            })
            .from(userServiceAssignments)
            .leftJoin(serviceRoles, eq(userServiceAssignments.serviceRoleId, serviceRoles.id))
            .where(and(eq(userServiceAssignments.tenantId, tenant.id), eq(userServiceAssignments.userId, userId))),

        db
            .select({ id: oidcClients.id, name: oidcClients.name, clientId: oidcClients.clientId })
            .from(oidcClients)
            .where(and(eq(oidcClients.tenantId, tenant.id), eq(oidcClients.enabled, true)))
            .orderBy(asc(oidcClients.name)),

        db
            .select({ id: samlSps.id, name: samlSps.name, entityId: samlSps.entityId })
            .from(samlSps)
            .where(and(eq(samlSps.tenantId, tenant.id), eq(samlSps.enabled, true)))
            .orderBy(asc(samlSps.name)),

        db
            .select({
                id: serviceRoles.id,
                serviceType: serviceRoles.serviceType,
                serviceRefId: serviceRoles.serviceRefId,
                key: serviceRoles.key,
                label: serviceRoles.label,
                isDefault: serviceRoles.isDefault,
                displayOrder: serviceRoles.displayOrder,
            })
            .from(serviceRoles)
            .where(eq(serviceRoles.tenantId, tenant.id))
            .orderBy(asc(serviceRoles.displayOrder), asc(serviceRoles.key)),

        // 테넌트의 모든 권한 정의. UI 에서 배정의 service 로 걸러 쓴다.
        // displayOrder 순서가 곧 관리자가 의존 관계를 읽는 순서다(시스템은 강제하지 않는다).
        db
            .select({
                id: serviceEntitlements.id,
                serviceType: serviceEntitlements.serviceType,
                serviceRefId: serviceEntitlements.serviceRefId,
                key: serviceEntitlements.key,
                label: serviceEntitlements.label,
                description: serviceEntitlements.description,
                displayOrder: serviceEntitlements.displayOrder,
            })
            .from(serviceEntitlements)
            .where(eq(serviceEntitlements.tenantId, tenant.id))
            .orderBy(asc(serviceEntitlements.displayOrder), asc(serviceEntitlements.key)),

        // 이 사용자의 배정에 실제로 부여된 권한(배정 id 기준). 체크박스 초기 상태.
        db
            .select({ assignmentId: userServiceEntitlements.assignmentId, serviceEntitlementId: userServiceEntitlements.serviceEntitlementId })
            .from(userServiceEntitlements)
            .innerJoin(userServiceAssignments, eq(userServiceEntitlements.assignmentId, userServiceAssignments.id))
            .where(and(eq(userServiceAssignments.tenantId, tenant.id), eq(userServiceAssignments.userId, userId))),
    ]);

    // 표시용 — service ref 별 이름 매핑
    const serviceLabelMap: Record<string, string> = {};
    for (const c of allOidcClients) serviceLabelMap[`oidc:${c.id}`] = `OIDC · ${c.name}`;
    for (const s of allSamlSps) serviceLabelMap[`saml:${s.id}`] = `SAML · ${s.name}`;

    return {
        user,
        deptMemberships,
        teamMemberships,
        partMemberships,
        allDepts,
        allTeams,
        allParts,
        allPositions,
        assignments,
        allOidcClients,
        allSamlSps,
        allServiceRoles,
        allServiceEntitlements,
        // assignmentId → 부여된 entitlement id 목록. 체크박스 checked 판정에 쓴다.
        grantedEntitlementsByAssignment: grantedEntitlements.reduce<Record<string, string[]>>((acc, row) => {
            (acc[row.assignmentId] ??= []).push(row.serviceEntitlementId);
            return acc;
        }, {}),
        serviceLabelMap,
    };
};

// 액션은 도메인별 모듈로 분리돼 있고(순수 이동), 여기서는 이름-계약만 조립한다.
// profile: 프로필/역할/상태 · org: 부서/팀/파트 소속 · service: 서비스 권한 · security: 강제 로그아웃
export const actions: Actions = {
    updateProfile,
    addDept,
    removeDept,
    addTeam,
    removeTeam,
    addPart,
    removePart,
    addAssignment,
    revokeAssignment,
    updateAssignmentExpiry,
    setAssignmentEntitlements,
    forceLogout,
};
