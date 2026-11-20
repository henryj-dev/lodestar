import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { and, eq } from "drizzle-orm";
import { resetMfa } from "../../src/lib/server/admin/user-actions/security";
import { createTrustedDevice } from "../../src/lib/server/auth/trusted-device";
import { TOTP_CREDENTIAL_TYPE, BACKUP_CODE_CREDENTIAL_TYPE } from "../../src/lib/server/auth/constants";
import { auditEvents, credentials, tenants, trustedDevices } from "../../src/lib/server/db/schema";
import { dispatchSecurityAlert } from "../../src/lib/server/security-notify";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, seedMfaSession, makeEvent, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Tenant, User, Session } from "../../src/lib/server/db/schema";

// 관리자 "MFA 초기화" — OTP 분실 시 self-service delete(현재 TOTP 코드 재인증 필수)를
// 쓸 수 없는 사용자를, 관리자가 재인증 없이 풀어 준다.

vi.mock("../../src/lib/server/security-notify", () => ({ dispatchSecurityAlert: vi.fn() }));

let mem: MemoryDb;
let tenant: Tenant;
let admin: User;
let adminSession: Session;
let target: User;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    admin = await seedUser(mem.db, { tenantId: tenant.id, email: "admin@test.example", role: "admin" });
    adminSession = (await seedMfaSession(mem.db, { tenantId: tenant.id, userId: admin.id })).session;
    target = await seedUser(mem.db, { tenantId: tenant.id, email: "member@test.example" });

    await mem.db.insert(credentials).values({ id: crypto.randomUUID(), userId: target.id, type: TOTP_CREDENTIAL_TYPE, secret: "encrypted-seed", totpOwnerId: target.id });
    await mem.db.insert(credentials).values({ id: crypto.randomUUID(), userId: target.id, type: BACKUP_CODE_CREDENTIAL_TYPE, secret: "hash-1" });
    await mem.db.insert(credentials).values({ id: crypto.randomUUID(), userId: target.id, type: BACKUP_CODE_CREDENTIAL_TYPE, secret: "hash-2" });
    await createTrustedDevice(mem.db, { tenantId: tenant.id, userId: target.id });

    vi.clearAllMocks();
});

afterEach(() => {
    mem.close();
});

function adminEvent(opts: { csrf?: boolean } = {}) {
    const event = makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/admin/users/${target.id}`,
        form: {},
        csrf: opts.csrf,
        locals: { db: mem.db, tenant, user: admin, session: adminSession, env: mem.env },
    });
    (event as unknown as { params: { id: string } }).params = { id: target.id };
    return event as Parameters<typeof resetMfa>[0];
}

async function remainingMfaCredentials() {
    return mem.db
        .select({ type: credentials.type })
        .from(credentials)
        .where(and(eq(credentials.userId, target.id), eq(credentials.type, TOTP_CREDENTIAL_TYPE)));
}

describe("관리자 MFA 초기화", () => {
    it("TOTP·백업코드를 지우고 신뢰 기기를 폐기한다", async () => {
        const res = await resetMfa(adminEvent());

        expect(res).toMatchObject({ mfaReset: true });

        const remainingTotp = await remainingMfaCredentials();
        expect(remainingTotp).toHaveLength(0);

        const remainingBackup = await mem.db
            .select({ type: credentials.type })
            .from(credentials)
            .where(and(eq(credentials.userId, target.id), eq(credentials.type, BACKUP_CODE_CREDENTIAL_TYPE)));
        expect(remainingBackup).toHaveLength(0);

        const devices = await mem.db.select({ revokedAt: trustedDevices.revokedAt }).from(trustedDevices).where(eq(trustedDevices.userId, target.id));
        expect(devices).toHaveLength(1);
        expect(devices[0].revokedAt).not.toBeNull();
    });

    it("감사 로그에 actorId=관리자, userId=대상으로 남긴다", async () => {
        await resetMfa(adminEvent());

        const [audit] = await mem.db.select().from(auditEvents).where(eq(auditEvents.kind, "mfa_deleted"));
        expect(audit).toMatchObject({ outcome: "success", actorId: admin.id, userId: target.id });
    });

    it("대상에게 관리자 초기화 보안 알림을 보낸다", async () => {
        await resetMfa(adminEvent());

        expect(dispatchSecurityAlert).toHaveBeenCalledWith(expect.objectContaining({ to: target.email, kind: "mfa_reset_by_admin" }));
    });

    it("다른 사용자의 비밀번호/계정 상태는 건드리지 않는다", async () => {
        await mem.db.insert(credentials).values({ id: crypto.randomUUID(), userId: target.id, type: "password", secret: "hash" });

        await resetMfa(adminEvent());

        const [pw] = await mem.db
            .select({ type: credentials.type })
            .from(credentials)
            .where(and(eq(credentials.userId, target.id), eq(credentials.type, "password")));
        expect(pw).toBeDefined();
    });

    it("CSRF 토큰이 없으면 거부하고 아무것도 지우지 않는다", async () => {
        const result = (await resetMfa(adminEvent({ csrf: false }))) as { status: number };

        expect(result.status).toBe(403);
        expect(await remainingMfaCredentials()).toHaveLength(1);
    });

    it("다른 테넌트의 사용자는 404 로 거부한다", async () => {
        const otherTenantId = crypto.randomUUID();
        await mem.db.insert(tenants).values({ id: otherTenantId, slug: `other-${otherTenantId.slice(0, 8)}`, name: "Other Tenant" });
        const foreign = await seedUser(mem.db, { tenantId: otherTenantId, email: "foreign@test.example" });
        const event = makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/admin/users/${foreign.id}`,
            form: {},
            locals: { db: mem.db, tenant, user: admin, session: adminSession, env: mem.env },
        });
        (event as unknown as { params: { id: string } }).params = { id: foreign.id };

        const result = (await resetMfa(event as Parameters<typeof resetMfa>[0])) as { status: number };
        expect(result.status).toBe(404);
    });
});
