import { and, asc, eq, gt, isNull, or } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { serviceEntitlements, serviceRoles, userServiceAssignments, userServiceEntitlements } from "$lib/server/db/schema";

export type ServiceType = "oidc" | "saml";

export interface ServicePermissionQuery {
    tenantId: string;
    userId: string;
    serviceType: ServiceType;
    serviceRefId: string;
}

export interface ActiveAssignment {
    id: string;
    serviceType: ServiceType;
    serviceRefId: string;
    attributesJson: string | null;
    expiresAt: Date | null;
    role: { id: string; key: string; label: string; description: string | null } | null;
}

/**
 * 사용자의 서비스 매핑(활성) 1개 조회. revokedAt 이 null 이고 expiresAt 이 미래(또는 null)인 row 만.
 * role 정보는 left join 으로 같이 가져온다 (role 미지정도 허용).
 */
export async function getActiveAssignment(db: DB, query: ServicePermissionQuery): Promise<ActiveAssignment | null> {
    const now = new Date();
    const [row] = await db
        .select({
            id: userServiceAssignments.id,
            serviceType: userServiceAssignments.serviceType,
            serviceRefId: userServiceAssignments.serviceRefId,
            attributesJson: userServiceAssignments.attributesJson,
            expiresAt: userServiceAssignments.expiresAt,
            roleId: serviceRoles.id,
            roleKey: serviceRoles.key,
            roleLabel: serviceRoles.label,
            roleDescription: serviceRoles.description,
        })
        .from(userServiceAssignments)
        .leftJoin(serviceRoles, eq(userServiceAssignments.serviceRoleId, serviceRoles.id))
        .where(
            and(
                eq(userServiceAssignments.tenantId, query.tenantId),
                eq(userServiceAssignments.userId, query.userId),
                eq(userServiceAssignments.serviceType, query.serviceType),
                eq(userServiceAssignments.serviceRefId, query.serviceRefId),
                isNull(userServiceAssignments.revokedAt),
                or(isNull(userServiceAssignments.expiresAt), gt(userServiceAssignments.expiresAt, now)),
            ),
        )
        .limit(1);

    if (!row) return null;

    return {
        id: row.id,
        serviceType: row.serviceType as ServiceType,
        serviceRefId: row.serviceRefId,
        attributesJson: row.attributesJson,
        expiresAt: row.expiresAt,
        role: row.roleId
            ? {
                  id: row.roleId,
                  key: row.roleKey ?? "",
                  label: row.roleLabel ?? "",
                  description: row.roleDescription,
              }
            : null,
    };
}

export async function hasServiceAccess(db: DB, query: ServicePermissionQuery): Promise<boolean> {
    const a = await getActiveAssignment(db, query);
    return a !== null;
}

export async function listServiceRoles(
    db: DB,
    args: { tenantId: string; serviceType: ServiceType; serviceRefId: string },
): Promise<{ id: string; key: string; label: string; description: string | null; isDefault: boolean; displayOrder: number }[]> {
    const rows = await db
        .select({
            id: serviceRoles.id,
            key: serviceRoles.key,
            label: serviceRoles.label,
            description: serviceRoles.description,
            isDefault: serviceRoles.isDefault,
            displayOrder: serviceRoles.displayOrder,
        })
        .from(serviceRoles)
        .where(and(eq(serviceRoles.tenantId, args.tenantId), eq(serviceRoles.serviceType, args.serviceType), eq(serviceRoles.serviceRefId, args.serviceRefId)))
        .orderBy(asc(serviceRoles.displayOrder), asc(serviceRoles.key));
    return rows;
}

/**
 * 배정에 부여된 **활성 권한(entitlement) 키** 목록. `roles` 와 직교하는 축이다.
 *
 * 만료된 부여는 제외한다 — `getActiveAssignment()` 의 expiresAt 필터와 같은 시맨틱.
 * 배정 자체의 유효성(revoked/expired)은 호출 전에 `getActiveAssignment()` 로 판정된 것을
 * 전제한다. 배정 행이 사라지면 FK cascade 로 권한 행도 함께 사라지므로 여기서 재검증하지 않는다.
 *
 * 정렬은 displayOrder → key. 관리 UI 의 체크박스 순서와 클레임 순서를 일치시켜, 권한 간 의존을
 * 관리자가 읽은 그 순서가 RP 에도 그대로 전달되게 한다.
 * (unique index (assignment_id, service_entitlement_id) 가 있어 중복 제거는 불필요.)
 */
export async function listActiveEntitlements(db: DB, assignmentId: string): Promise<string[]> {
    const now = new Date();
    const rows = await db
        .select({ key: serviceEntitlements.key })
        .from(userServiceEntitlements)
        .innerJoin(serviceEntitlements, eq(userServiceEntitlements.serviceEntitlementId, serviceEntitlements.id))
        .where(and(eq(userServiceEntitlements.assignmentId, assignmentId), or(isNull(userServiceEntitlements.expiresAt), gt(userServiceEntitlements.expiresAt, now))))
        .orderBy(asc(serviceEntitlements.displayOrder), asc(serviceEntitlements.key));
    return rows.map((r) => r.key);
}

/**
 * assignment 의 attributesJson 을 안전하게 객체로 파싱. 잘못된 JSON 또는 비-객체이면 빈 객체 반환.
 */
export function parseAssignmentAttributes(attributesJson: string | null | undefined): Record<string, unknown> {
    if (!attributesJson) return {};
    try {
        const parsed = JSON.parse(attributesJson) as unknown;
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            return parsed as Record<string, unknown>;
        }
    } catch {
        /* ignore */
    }
    return {};
}
