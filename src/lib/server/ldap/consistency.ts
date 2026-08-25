import { eq, isNull, ne, or } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { identities, users } from "$lib/server/db/schema";

export interface TenantConsistencyViolation {
    identityId: string;
    identityTenantId: string;
    userId: string;
    userTenantId: string | null;
}

/** Find LDAP/federated identities whose user is missing or belongs to another tenant. */
export async function findTenantConsistencyViolations(db: DB): Promise<TenantConsistencyViolation[]> {
    return db
        .select({ identityId: identities.id, identityTenantId: identities.tenantId, userId: identities.userId, userTenantId: users.tenantId })
        .from(identities)
        .leftJoin(users, eq(identities.userId, users.id))
        .where(or(isNull(users.id), ne(identities.tenantId, users.tenantId)));
}

/** Periodic, non-destructive health check used by GC and operational scripts. */
export async function checkTenantConsistency(db: DB): Promise<number> {
    const violations = await findTenantConsistencyViolations(db);
    if (violations.length > 0) {
        console.error(
            JSON.stringify({
                event: "tenant_consistency_violation",
                count: violations.length,
                identities: violations.slice(0, 20).map((v) => ({ id: v.identityId, userId: v.userId, tenantId: v.identityTenantId })),
            }),
        );
    }
    return violations.length;
}
