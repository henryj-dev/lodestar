import { error, json, type RequestHandler } from "@sveltejs/kit";
import { eq, and } from "drizzle-orm";
import { requireServiceToken } from "$lib/server/auth/service-token";
import { BACKUP_CODE_CREDENTIAL_TYPE, TOTP_CREDENTIAL_TYPE } from "$lib/server/auth/constants";
import { requireDbContext } from "$lib/server/auth/guards";
import { credentials } from "$lib/server/db/schema";

/**
 * Phase 7.3 — TOTP enroll 여부 + last-used 조회.
 */
export const GET: RequestHandler = async (event) => {
    const { url, locals } = event;
    await requireServiceToken(event, "totp.status");
    const { db } = requireDbContext(locals);

    const userId = url.searchParams.get("userId")?.trim();
    if (!userId) throw error(400, "userId required");

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
