import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { and, eq } from "drizzle-orm";
import { POST as enrollInitPOST } from "../../src/routes/api/totp/enroll/init/+server";
import { POST as enrollConfirmPOST } from "../../src/routes/api/totp/enroll/confirm/+server";
import { POST as verifyPOST } from "../../src/routes/api/totp/verify/+server";
import { GET as statusGET } from "../../src/routes/api/totp/status/+server";
import { encryptTotpSecret, generateTotpCode, generateTotpSecret } from "../../src/lib/server/auth/totp";
import { auditEvents, credentials, users } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, makeEvent, catchError, TEST_ISSUER_URL, TEST_SIGNING_SECRET, type MemoryDb } from "./harness";
import type { Tenant, User } from "../../src/lib/server/db/schema";

// Service-to-Service TOTP API 의 두 가드를 고정한다.
//   1. 활성(active)이 아닌 사용자는 네 엔드포인트 모두 거부한다. IdP 로그인이 막힌 계정이
//      이 API 로는 RP 의 2단계 승인을 계속 통과하던 공백.
//   2. confirm 은 init 이 발급한 (userId, secret) 에만 등록한다(등록 티켓). 예전에는 body 의
//      secret 을 그대로 믿어 호출자가 아무 secret·userId 로 등록할 수 있었다.

const SERVICE_TOKEN = "test-dispatcher-service-token-0123456789abcdef";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;

async function setup(env: Record<string, string> = {}) {
    mem = await openMemoryDb({ DISPATCHER_SERVICE_TOKEN: SERVICE_TOKEN, ...env });
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, { tenantId: tenant.id, email: "guard@test.example", username: "guarduser" });
}

afterEach(() => {
    mem.close();
});

function svcPost(path: string, json: unknown) {
    return makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}${path}`,
        headers: { authorization: `Bearer ${SERVICE_TOKEN}` },
        json,
        locals: { db: mem.db, tenant, env: mem.env },
    });
}

function svcGet(path: string) {
    return makeEvent({
        method: "GET",
        url: `${TEST_ISSUER_URL}${path}`,
        headers: { authorization: `Bearer ${SERVICE_TOKEN}` },
        locals: { db: mem.db, tenant, env: mem.env },
    });
}

async function enrollDirectly(userId: string): Promise<string> {
    const secret = generateTotpSecret();
    await mem.db.insert(credentials).values({
        id: crypto.randomUUID(),
        userId,
        type: "totp",
        secret: await encryptTotpSecret(secret, TEST_SIGNING_SECRET, userId),
        totpOwnerId: userId,
    });
    return secret;
}

async function hasTotp(userId: string): Promise<boolean> {
    const rows = await mem.db
        .select({ id: credentials.id })
        .from(credentials)
        .where(and(eq(credentials.userId, userId), eq(credentials.type, "totp")));
    return rows.length > 0;
}

async function auditDetails(kind: string): Promise<Record<string, unknown>[]> {
    const rows = await mem.db.select({ detailJson: auditEvents.detailJson }).from(auditEvents).where(eq(auditEvents.kind, kind));
    return rows.map((r) => (r.detailJson ? (JSON.parse(r.detailJson) as Record<string, unknown>) : {}));
}

async function init(): Promise<{ secret: string; enrollmentTicket: string }> {
    const res = (await enrollInitPOST(svcPost("/api/totp/enroll/init", { userId: user.id }))) as Response;
    expect(res.status).toBe(200);
    return (await res.json()) as { secret: string; enrollmentTicket: string };
}

describe("비활성 사용자 거부", () => {
    beforeEach(() => setup());

    for (const status of ["disabled", "locked", "deletion_pending"] as const) {
        it(`${status} 사용자는 verify 가 403 이고 감사에 user_inactive 를 남긴다`, async () => {
            const secret = await enrollDirectly(user.id);
            await mem.db.update(users).set({ status }).where(eq(users.id, user.id));

            const res = (await verifyPOST(svcPost("/api/totp/verify", { userId: user.id, code: await generateTotpCode(secret) }))) as Response;
            expect(res.status).toBe(403);
            expect(await res.json()).toMatchObject({ ok: false, reason: "user_inactive" });
            expect(await auditDetails("service_totp_verified")).toEqual([{ reason: "user_inactive" }]);
        });
    }

    it("status 는 비활성 사용자에게 403 이다", async () => {
        await enrollDirectly(user.id);
        await mem.db.update(users).set({ status: "disabled" }).where(eq(users.id, user.id));
        const { status } = await catchError(async () => statusGET(svcGet(`/api/totp/status?userId=${user.id}`)));
        expect(status).toBe(403);
    });

    it("enroll/init 은 비활성 사용자에게 403 이다", async () => {
        await mem.db.update(users).set({ status: "locked" }).where(eq(users.id, user.id));
        const { status } = await catchError(async () => enrollInitPOST(svcPost("/api/totp/enroll/init", { userId: user.id })));
        expect(status).toBe(403);
    });

    it("enroll/confirm 은 init 이후 비활성화된 사용자를 403 으로 거부한다", async () => {
        const { secret, enrollmentTicket } = await init();
        await mem.db.update(users).set({ status: "disabled" }).where(eq(users.id, user.id));

        const { status } = await catchError(async () => enrollConfirmPOST(svcPost("/api/totp/enroll/confirm", { userId: user.id, secret, code: "000000", enrollmentTicket })));
        expect(status).toBe(403);
        expect(await hasTotp(user.id)).toBe(false);
        expect(await auditDetails("service_totp_enroll_rejected")).toEqual([{ reason: "user_inactive" }]);
    });

    it("활성 사용자는 그대로 통과한다", async () => {
        const secret = await enrollDirectly(user.id);
        const res = (await verifyPOST(svcPost("/api/totp/verify", { userId: user.id, code: await generateTotpCode(secret) }))) as Response;
        expect(res.status).toBe(200);
        const statusRes = (await statusGET(svcGet(`/api/totp/status?userId=${user.id}`))) as Response;
        expect(statusRes.status).toBe(200);
    });
});

describe("등록 티켓 (기본: optional)", () => {
    beforeEach(() => setup());

    it("init 응답에 enrollmentTicket 이 있고, 그대로 보내면 등록된다", async () => {
        const { secret, enrollmentTicket } = await init();
        expect(enrollmentTicket).toEqual(expect.any(String));

        const res = (await enrollConfirmPOST(svcPost("/api/totp/enroll/confirm", { userId: user.id, secret, code: await generateTotpCode(secret), enrollmentTicket }))) as Response;
        expect(res.status).toBe(200);
        expect(await hasTotp(user.id)).toBe(true);
        expect(await auditDetails("service_totp_enrolled")).toEqual([{ ticket: "verified" }]);
    });

    it("발급하지 않은 secret 으로 바꾸면 코드가 맞아도 거부한다", async () => {
        const { enrollmentTicket } = await init();
        const foreign = generateTotpSecret();

        const { status } = await catchError(async () => enrollConfirmPOST(svcPost("/api/totp/enroll/confirm", { userId: user.id, secret: foreign, code: "000000", enrollmentTicket })));
        expect(status).toBe(400);
        expect(await hasTotp(user.id)).toBe(false);
        expect(await auditDetails("service_totp_enroll_rejected")).toEqual([{ reason: "ticket_mismatch" }]);
    });

    it("다른 사용자의 티켓으로는 등록하지 못한다", async () => {
        const { secret, enrollmentTicket } = await init();
        const other = await seedUser(mem.db, { tenantId: tenant.id, email: "other@test.example", username: "otheruser" });

        const { status } = await catchError(async () => enrollConfirmPOST(svcPost("/api/totp/enroll/confirm", { userId: other.id, secret, code: await generateTotpCode(secret), enrollmentTicket })));
        expect(status).toBe(400);
        expect(await hasTotp(other.id)).toBe(false);
    });

    it("티켓 없이 오면 이행 모드라 등록하되, 감사에 missing 을 남긴다", async () => {
        const { secret } = await init();
        const res = (await enrollConfirmPOST(svcPost("/api/totp/enroll/confirm", { userId: user.id, secret, code: await generateTotpCode(secret) }))) as Response;
        expect(res.status).toBe(200);
        expect(await auditDetails("service_totp_enrolled")).toEqual([{ ticket: "missing" }]);
    });

    it("이미 등록된 사용자는 티켓이 있어도 409 다 (기존 TOTP 를 덮어쓰지 않는다)", async () => {
        const { secret, enrollmentTicket } = await init();
        await enrollDirectly(user.id);
        const { status } = await catchError(async () => enrollConfirmPOST(svcPost("/api/totp/enroll/confirm", { userId: user.id, secret, code: await generateTotpCode(secret), enrollmentTicket })));
        expect(status).toBe(409);
    });
});

describe("등록 티켓 (TOTP_ENROLL_TICKET=required)", () => {
    beforeEach(() => setup({ TOTP_ENROLL_TICKET: "required" }));

    it("티켓 없는 confirm 을 400 으로 거부한다", async () => {
        const { secret } = await init();
        const { status } = await catchError(async () => enrollConfirmPOST(svcPost("/api/totp/enroll/confirm", { userId: user.id, secret, code: await generateTotpCode(secret) })));
        expect(status).toBe(400);
        expect(await hasTotp(user.id)).toBe(false);
        expect(await auditDetails("service_totp_enroll_rejected")).toEqual([{ reason: "ticket_missing" }]);
    });

    it("티켓이 있으면 등록된다", async () => {
        const { secret, enrollmentTicket } = await init();
        const res = (await enrollConfirmPOST(svcPost("/api/totp/enroll/confirm", { userId: user.id, secret, code: await generateTotpCode(secret), enrollmentTicket }))) as Response;
        expect(res.status).toBe(200);
    });
});
