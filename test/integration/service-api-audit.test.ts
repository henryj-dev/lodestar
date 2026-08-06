import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { POST as enrollInitPOST } from "../../src/routes/api/totp/enroll/init/+server";
import { POST as enrollConfirmPOST } from "../../src/routes/api/totp/enroll/confirm/+server";
import { POST as verifyPOST } from "../../src/routes/api/totp/verify/+server";
import { encryptTotpSecret, generateTotpCode, generateTotpSecret } from "../../src/lib/server/auth/totp";
import { auditEvents, credentials } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, makeEvent, catchError, TEST_ISSUER_URL, TEST_SIGNING_SECRET, type MemoryDb } from "./harness";
import type { Tenant, User } from "../../src/lib/server/db/schema";

// Service-to-Service TOTP API 는 서비스 토큰 경계 안에서 동작하고 requireServiceToken 은
// 성공 시 조용히 반환한다. 그래서 **성공 호출이 감사에 전혀 남지 않는 상태**였다 —
// /api/totp/verify 는 호출자에게 방화벽 변경 승인의 2단계 검증인데 흔적이 없었다.
// 이 테스트는 그 기록이 실제로 남는지를 고정한다.

const SERVICE_TOKEN = "test-dispatcher-service-token-0123456789abcdef";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;

beforeEach(async () => {
    mem = await openMemoryDb({ DISPATCHER_SERVICE_TOKEN: SERVICE_TOKEN });
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, { tenantId: tenant.id, email: "svc@test.example", username: "svcuser" });
});

afterEach(() => {
    mem.close();
});

function svcEvent(path: string, json: unknown, token: string = SERVICE_TOKEN) {
    return makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}${path}`,
        headers: { authorization: `Bearer ${token}` },
        json,
        locals: { db: mem.db, tenant, env: mem.env },
    });
}

async function audits(kind: string): Promise<{ outcome: string; userId: string | null; detailJson: string | null }[]> {
    return mem.db.select({ outcome: auditEvents.outcome, userId: auditEvents.userId, detailJson: auditEvents.detailJson }).from(auditEvents).where(eq(auditEvents.kind, kind));
}

/** confirm 을 거치지 않고 TOTP 크레덴셜을 직접 심는다(코드 재사용 제한을 피해 fresh code 로 검증하기 위함). */
async function enrollDirectly(): Promise<string> {
    const secret = generateTotpSecret();
    const encrypted = await encryptTotpSecret(secret, TEST_SIGNING_SECRET, user.id);
    await mem.db.insert(credentials).values({
        id: crypto.randomUUID(),
        userId: user.id,
        type: "totp",
        secret: encrypted,
        totpOwnerId: user.id,
    });
    return secret;
}

describe("service TOTP API 감사", () => {
    it("enroll/init 성공을 남긴다 (시드가 밖으로 나간 사건)", async () => {
        const res = (await enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }))) as Response;
        expect(res.status).toBe(200);

        const rows = await audits("service_totp_enroll_started");
        expect(rows).toHaveLength(1);
        expect(rows[0].outcome).toBe("success");
        expect(rows[0].userId).toBe(user.id);
    });

    it("enroll/confirm 성공을 남긴다 (2단계 크레덴셜 생성)", async () => {
        const init = (await enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }))) as Response;
        const { secret } = (await init.json()) as { secret: string };
        const code = await generateTotpCode(secret);

        const res = (await enrollConfirmPOST(svcEvent("/api/totp/enroll/confirm", { userId: user.id, secret, code }))) as Response;
        expect(res.status).toBe(200);

        const rows = await audits("service_totp_enrolled");
        expect(rows).toHaveLength(1);
        expect(rows[0].outcome).toBe("success");
        expect(rows[0].userId).toBe(user.id);
    });

    it("verify 성공을 남긴다 — 이게 없으면 승인 2단계가 무기록이다", async () => {
        const secret = await enrollDirectly();
        const code = await generateTotpCode(secret);

        const res = (await verifyPOST(svcEvent("/api/totp/verify", { userId: user.id, code }))) as Response;
        expect(res.status).toBe(200);
        expect(await res.json()).toMatchObject({ ok: true });

        const rows = await audits("service_totp_verified");
        expect(rows).toHaveLength(1);
        expect(rows[0].outcome).toBe("success");
        expect(rows[0].userId).toBe(user.id);
    });

    it("잘못된 코드는 failure 로 남긴다", async () => {
        await enrollDirectly();

        const res = (await verifyPOST(svcEvent("/api/totp/verify", { userId: user.id, code: "000000" }))) as Response;
        expect(res.status).toBe(401);

        const rows = await audits("service_totp_verified");
        expect(rows).toHaveLength(1);
        expect(rows[0].outcome).toBe("failure");
        expect(JSON.parse(rows[0].detailJson!)).toMatchObject({ reason: "invalid_code" });
    });

    it("미등록 사용자 검증 시도도 failure 로 남긴다", async () => {
        const { status } = await catchError(() => verifyPOST(svcEvent("/api/totp/verify", { userId: user.id, code: "000000" })));
        expect(status).toBe(404);

        const rows = await audits("service_totp_verified");
        expect(rows).toHaveLength(1);
        expect(rows[0].outcome).toBe("failure");
        expect(JSON.parse(rows[0].detailJson!)).toMatchObject({ reason: "not_enrolled" });
    });

    it("잘못된 서비스 토큰은 거부되고 감사에도 성공이 남지 않는다", async () => {
        await enrollDirectly();

        const { status } = await catchError(() => verifyPOST(svcEvent("/api/totp/verify", { userId: user.id, code: "000000" }, "wrong-token")));
        expect(status).toBe(401);

        expect(await audits("service_totp_verified")).toHaveLength(0);
        const rejected = await audits("service_token_rejected");
        expect(rejected).toHaveLength(1);
    });
});
