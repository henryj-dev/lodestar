import { error, json, type RequestHandler } from "@sveltejs/kit";
import { eq, and } from "drizzle-orm";
import { requireServiceToken } from "$lib/server/auth/service-token";
import { BACKUP_CODE_CREDENTIAL_TYPE, TOTP_CREDENTIAL_TYPE } from "$lib/server/auth/constants";
import { requireDbContext } from "$lib/server/auth/guards";
import { credentials, users } from "$lib/server/db/schema";

/**
 * Phase 7.3 — TOTP enroll 여부 + last-used 조회.
 * 활성(active)이 아닌 사용자는 403 — verify 와 같은 기준이라, 호출자가 status 만 보고
 * "등록돼 있으니 OTP 를 받으면 된다" 고 판단하지 않게 한다.
 */
export const GET: RequestHandler = async (event) => {
    const { url, locals } = event;
    await requireServiceToken(event, "totp.status");
    const { db, tenant } = requireDbContext(locals);

    const userId = url.searchParams.get("userId")?.trim();
    if (!userId) throw error(400, "userId required");

    const [user] = await db
        .select({ id: users.id, status: users.status })
        .from(users)
        .where(and(eq(users.id, userId), eq(users.tenantId, tenant.id)))
        .limit(1);
    if (!user) throw error(404, "user not found");
    if (user.status !== "active") throw error(403, "user not active");

    const totp = await db
        .select({ id: credentials.id, lastUsedAt: credentials.lastUsedAt, createdAt: credentials.createdAt })
        .from(credentials)
        .where(and(eq(credentials.userId, userId), eq(credentials.type, TOTP_CREDENTIAL_TYPE)))
        .limit(1);

    const backupRows = await db
        .select({ id: credentials.id })
        .from(credentials)
        .where(and(eq(credentials.userId, userId), eq(credentials.type, BACKUP_CODE_CREDENTIAL_TYPE)));

    return json({
        enrolled: totp.length > 0,
        backupCodeCount: backupRows.length,
        lastUsedAt: totp[0]?.lastUsedAt ?? null,
        enrolledAt: totp[0]?.createdAt ?? null,
    });
};
