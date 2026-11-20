import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { eq } from "drizzle-orm";
import { updateProfile } from "../../src/lib/server/admin/user-actions/profile";
import { auditEvents, users } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, seedMfaSession, makeEvent, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Tenant, User, Session } from "../../src/lib/server/db/schema";

// 관리자가 사용자 상세 페이지에서 "이메일 인증됨" 체크박스로 emailVerifiedAt 을 임의로
// 켜고/끌 수 있는지. 체크 해제 → NULL, 체크 → 이미 인증돼 있었으면 기존 시각 유지(매 저장마다
// "최초 인증 시각" 이 갱신되면 의미가 사라진다), 아니면 지금 시각.

vi.mock("../../src/lib/server/security-notify", () => ({ dispatchSecurityAlert: vi.fn() }));

let mem: MemoryDb;
let tenant: Tenant;
let admin: User;
let adminSession: Session;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    admin = await seedUser(mem.db, { tenantId: tenant.id, email: "admin@test.example", role: "admin" });
    adminSession = (await seedMfaSession(mem.db, { tenantId: tenant.id, userId: admin.id })).session;
});

afterEach(() => {
    mem.close();
});

function profileEvent(targetId: string, form: Record<string, string>) {
    const event = makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/admin/users/${targetId}`,
        form: { role: "user", status: "active", ...form },
        locals: { db: mem.db, tenant, user: admin, session: adminSession, env: mem.env },
    });
    (event as unknown as { params: { id: string } }).params = { id: targetId };
    return event as Parameters<typeof updateProfile>[0];
}

async function emailVerifiedAtOf(userId: string): Promise<Date | null> {
    const [row] = await mem.db.select({ emailVerifiedAt: users.emailVerifiedAt }).from(users).where(eq(users.id, userId));
    return row?.emailVerifiedAt ?? null;
}

describe("관리자 - 이메일 인증 여부 수동 변경", () => {
    it("미인증 사용자를 체크하면 지금 시각으로 인증 처리한다", async () => {
        const target = await seedUser(mem.db, { tenantId: tenant.id, email: "unverified@test.example", emailVerifiedAt: null });

        await updateProfile(profileEvent(target.id, { emailVerified: "true" }));

        const at = await emailVerifiedAtOf(target.id);
        expect(at).not.toBeNull();
    });

    it("체크를 해제하면 NULL(미인증)로 되돌린다", async () => {
        const target = await seedUser(mem.db, { tenantId: tenant.id, email: "verified@test.example", emailVerifiedAt: new Date() });

        await updateProfile(profileEvent(target.id, {}));

        expect(await emailVerifiedAtOf(target.id)).toBeNull();
    });

    it("이미 인증된 사용자를 체크 상태로 다시 저장해도 최초 인증 시각을 유지한다", async () => {
        const originalAt = new Date("2026-01-01T00:00:00Z");
        const target = await seedUser(mem.db, { tenantId: tenant.id, email: "already-verified@test.example", emailVerifiedAt: originalAt });

        await updateProfile(profileEvent(target.id, { emailVerified: "true", displayName: "New Name" }));

        expect(await emailVerifiedAtOf(target.id)).toEqual(originalAt);
    });

    it("감사 로그 detail 에 emailVerified 를 남긴다", async () => {
        const target = await seedUser(mem.db, { tenantId: tenant.id, email: "audited@test.example", emailVerifiedAt: null });

        await updateProfile(profileEvent(target.id, { emailVerified: "true" }));

        const [audit] = await mem.db.select().from(auditEvents).where(eq(auditEvents.kind, "user_profile_updated"));
        expect(JSON.parse(audit.detailJson!)).toMatchObject({ emailVerified: true });
    });
});
