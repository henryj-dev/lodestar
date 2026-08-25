import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { and, eq } from "drizzle-orm";
import { actions } from "../../src/routes/(auth)/reset-password/+page.server";
import { credentials, passwordResetTokens } from "../../src/lib/server/db/schema";
import { hashToken } from "../../src/lib/server/email";
import { openMemoryDb, makeEvent, seedTenantAndSigningKey, seedUser, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Tenant, User } from "../../src/lib/server/db/schema";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;
let token: string;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, { tenantId: tenant.id, email: "reset@test.example", username: "resetuser", password: "old-password-123" });
    token = `reset-token-${crypto.randomUUID()}`;
    await mem.db.insert(passwordResetTokens).values({
        id: crypto.randomUUID(),
        userId: user.id,
        tokenHash: await hashToken(token),
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    });
});

afterEach(() => mem.close());

function resetEvent(password: string) {
    return makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/reset-password`,
        form: { token, password, confirmPassword: password },
        locals: { db: mem.db, tenant, env: mem.env },
    });
}

type ResetResult = { status?: number };

async function runReset(password: string): Promise<ResetResult> {
    try {
        return (await actions.default!(resetEvent(password))) as ResetResult;
    } catch (error) {
        if (typeof error === "object" && error !== null && "status" in error && (error as ResetResult).status === 302) return error as ResetResult;
        throw error;
    }
}

describe("password reset atomic token consumption", () => {
    it("consumes the token before completing the password write", async () => {
        await runReset("new-password-123");
        const [row] = await mem.db.select().from(passwordResetTokens).where(eq(passwordResetTokens.userId, user.id));
        expect(row.usedAt).not.toBeNull();

        const second = (await actions.default!(resetEvent("another-password-123"))) as { status?: number };
        expect(second.status).toBe(400);
    });

    it("allows exactly one winner for concurrent submissions", async () => {
        const results = await Promise.all([runReset("new-password-123"), runReset("another-password-123")]);

        expect(results.filter((result) => result.status === 302)).toHaveLength(1);
        expect(results.filter((result) => result.status !== 302)).toHaveLength(1);
        const [row] = await mem.db.select().from(passwordResetTokens).where(eq(passwordResetTokens.userId, user.id));
        expect(row.usedAt).not.toBeNull();
        expect(
            await mem.db
                .select()
                .from(credentials)
                .where(and(eq(credentials.userId, user.id), eq(credentials.type, "password"))),
        ).toHaveLength(1);
    });
});
