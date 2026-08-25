import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { POST as enrollInitPOST } from "../../src/routes/api/totp/enroll/init/+server";
import { POST as enrollConfirmPOST } from "../../src/routes/api/totp/enroll/confirm/+server";
import { POST as verifyPOST } from "../../src/routes/api/totp/verify/+server";
import { GET as lookupGET } from "../../src/routes/api/users/lookup/+server";
import { GET as statusGET } from "../../src/routes/api/totp/status/+server";
import { encryptTotpSecret, generateTotpCode, generateTotpSecret } from "../../src/lib/server/auth/totp";
import { generateServiceToken, hashServiceToken } from "../../src/lib/server/auth/service-token";
import { actions as tokenPageActions } from "../../src/routes/admin/service-tokens/+page.server";
import { auditEvents, credentials, serviceApiTokens, tenants } from "../../src/lib/server/db/schema";
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

function lookupEvent(path: string, token: string = SERVICE_TOKEN) {
    return makeEvent({
        method: "GET",
        url: `${TEST_ISSUER_URL}${path}`,
        headers: { authorization: `Bearer ${token}` },
        locals: { db: mem.db, tenant, env: mem.env },
    });
}

function statusEvent(path: string, token: string = SERVICE_TOKEN) {
    return makeEvent({
        method: "GET",
        url: `${TEST_ISSUER_URL}${path}`,
        headers: { authorization: `Bearer ${token}` },
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

describe("users lookup tenant isolation", () => {
    it("env service token cannot select another tenant through query parameter", async () => {
        const otherTenantId = crypto.randomUUID();
        const otherSlug = `other-${otherTenantId.slice(0, 8)}`;
        await mem.db.insert(tenants).values({ id: otherTenantId, slug: otherSlug, name: "Other" });
        const otherUser = await seedUser(mem.db, { tenantId: otherTenantId, email: "other@test.example", username: "other" });

        const { status } = await catchError(() => lookupGET(lookupEvent(`/api/users/lookup?tenant=${otherSlug}&email=${encodeURIComponent(otherUser.email)}`)));
        expect(status).toBe(403);
    });

    it("default tenant lookup still works when tenant is omitted", async () => {
        const response = (await lookupGET(lookupEvent(`/api/users/lookup?email=${encodeURIComponent(user.email)}`))) as Response;
        expect(response.status).toBe(200);
        expect(await response.json()).toMatchObject({ id: user.id, tenantId: tenant.id, email: user.email });
    });

    it("keeps the lookup rate limit and throttling audit event", { timeout: 30_000 }, async () => {
        for (let i = 0; i < 120; i++) {
            const response = (await lookupGET(lookupEvent(`/api/users/lookup?email=${encodeURIComponent(user.email)}`))) as Response;
            expect(response.status).toBe(200);
        }
        const { status } = await catchError(() => lookupGET(lookupEvent(`/api/users/lookup?email=${encodeURIComponent(user.email)}`)));
        expect(status).toBe(429);
        expect(await audits("service_lookup_throttled")).toHaveLength(1);
    });
});

describe("service TOTP tenant isolation", () => {
    it("rejects a user ID belonging to another tenant on all four endpoints", async () => {
        const otherTenantId = crypto.randomUUID();
        await mem.db.insert(tenants).values({ id: otherTenantId, slug: `totp-other-${otherTenantId.slice(0, 8)}`, name: "Other" });
        const otherUser = await seedUser(mem.db, { tenantId: otherTenantId, email: "totp-other@test.example", username: "totpother" });
        const secret = generateTotpSecret();
        const code = await generateTotpCode(secret);

        await expect(catchError(() => enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: otherUser.id })))).resolves.toMatchObject({ status: 404 });
        await expect(catchError(() => enrollConfirmPOST(svcEvent("/api/totp/enroll/confirm", { userId: otherUser.id, secret, code })))).resolves.toMatchObject({ status: 404 });
        await expect(catchError(() => verifyPOST(svcEvent("/api/totp/verify", { userId: otherUser.id, code })))).resolves.toMatchObject({ status: 404 });
        await expect(catchError(() => statusGET(statusEvent(`/api/totp/status?userId=${otherUser.id}`)))).resolves.toMatchObject({ status: 404 });
    });
});

// 스코프 있는 서비스 토큰.
//
// 예전에는 DISPATCHER_SERVICE_TOKEN 단일 공유 시크릿 하나로 다섯 엔드포인트가 전부 열렸다.
// 이제 호출자별 토큰에 스코프를 달고, 필요한 것만 준다.
describe("서비스 API 토큰 스코프", () => {
    /** 평문을 만들어 해시로 저장하고 평문을 돌려준다(발급 화면이 하는 일과 같다). */
    async function issueToken(opts: { name: string; scopes: string; tenantId?: string; expiresAt?: Date }): Promise<string> {
        const plain = generateServiceToken();
        await mem.db.insert(serviceApiTokens).values({
            id: crypto.randomUUID(),
            tenantId: opts.tenantId ?? tenant.id,
            name: opts.name,
            tokenHash: await hashServiceToken(plain),
            tokenPrefix: plain.slice(0, 8),
            scopes: opts.scopes,
            expiresAt: opts.expiresAt ?? null,
        });
        return plain;
    }

    it("스코프가 있으면 통과한다", async () => {
        const token = await issueToken({ name: "heliopause", scopes: "totp.verify" });
        await enrollDirectly();

        const res = (await verifyPOST(svcEvent("/api/totp/verify", { userId: user.id, code: "000000" }, token))) as Response;
        // 코드가 틀린 것이지 인증은 통과했다(401 Invalid service token 이 아니라 {ok:false}).
        expect(res.status).toBe(401);
        expect(await res.json()).toMatchObject({ ok: false });
    });

    it("**다른 스코프 엔드포인트는 거부한다** — 이게 이 작업의 핵심", async () => {
        const token = await issueToken({ name: "heliopause", scopes: "totp.verify" });

        // totp.verify 만 가진 토큰으로 enroll 을 시도한다.
        const { status } = await catchError(() => enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }, token)));
        expect(status).toBe(401);

        // 사용자에게 TOTP 가 심어지지 않았다.
        const creds = await mem.db.select().from(credentials).where(eq(credentials.userId, user.id));
        expect(creds).toEqual([]);
    });

    it("여러 스코프를 공백으로 나눠 가질 수 있다", async () => {
        const token = await issueToken({ name: "dispatcher", scopes: "totp.verify totp.enroll" });

        const res = (await enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }, token))) as Response;
        expect(res.status).toBe(200);
    });

    it("만료된 토큰은 거부한다", async () => {
        const token = await issueToken({ name: "expired", scopes: "totp.enroll", expiresAt: new Date(Date.now() - 1000) });

        const { status } = await catchError(() => enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }, token)));
        expect(status).toBe(401);
    });

    it("다른 테넌트의 토큰은 거부한다", async () => {
        const otherTenantId = crypto.randomUUID();
        await mem.db.insert(tenants).values({ id: otherTenantId, slug: `t-${otherTenantId.slice(0, 8)}`, name: "Other" });
        const token = await issueToken({ name: "cross", scopes: "totp.enroll", tenantId: otherTenantId });

        const { status } = await catchError(() => enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }, token)));
        expect(status).toBe(401);
    });

    it("삭제된 토큰은 거부한다 (폐기 = 행 삭제)", async () => {
        const token = await issueToken({ name: "revoked", scopes: "totp.enroll" });
        await mem.db.delete(serviceApiTokens);

        const { status } = await catchError(() => enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }, token)));
        expect(status).toBe(401);
    });

    it("env 토큰은 전 스코프로 계속 동작한다 (기존 dispatcher 무중단)", async () => {
        // SERVICE_TOKEN 은 env(DISPATCHER_SERVICE_TOKEN)로 주입돼 있다 — 스코프 없이 enroll 통과.
        const res = (await enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }))) as Response;
        expect(res.status).toBe(200);
    });

    it("lastUsedAt 을 기록하되 매 호출 쓰지 않는다 (throttle)", async () => {
        const token = await issueToken({ name: "throttle", scopes: "totp.enroll" });

        await enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }, token));
        const [first] = await mem.db.select().from(serviceApiTokens);
        expect(first.lastUsedAt).not.toBeNull();

        // 곧바로 다시 호출 — throttle 창(5분) 안이라 값이 그대로여야 한다.
        await enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }, token));
        const [second] = await mem.db.select().from(serviceApiTokens);
        expect(second.lastUsedAt?.getTime()).toBe(first.lastUsedAt?.getTime());
    });
});

// 발급·폐기 화면.
describe("서비스 토큰 발급 UI", () => {
    const create = tokenPageActions.create!;
    const revoke = tokenPageActions.revoke!;
    let admin: User;

    beforeEach(async () => {
        admin = await seedUser(mem.db, { tenantId: tenant.id, email: "tkadmin@test.example", role: "admin" });
    });

    function adminEvent(form: Record<string, string | string[]>) {
        return makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/admin/service-tokens`,
            form,
            locals: { db: mem.db, tenant, user: admin, env: mem.env },
        }) as Parameters<typeof create>[0];
    }

    it("평문은 응답에만 나오고 DB 에는 해시만 저장된다", async () => {
        const res = (await create(adminEvent({ name: "heliopause", scopes: ["totp.verify"] }))) as { token?: string };

        expect(res.token).toBeTruthy();
        const [row] = await mem.db.select().from(serviceApiTokens);
        // 저장된 어느 컬럼에도 평문이 없다.
        expect(row.tokenHash).not.toContain(res.token!);
        expect(row.tokenHash).toBe(await hashServiceToken(res.token!));
        expect(res.token!.startsWith(row.tokenPrefix)).toBe(true);
        expect(row.scopes).toBe("totp.verify");
    });

    it("발급된 토큰이 실제로 통한다 (해시 왕복)", async () => {
        const res = (await create(adminEvent({ name: "heliopause", scopes: ["totp.enroll"] }))) as { token: string };

        const ok = (await enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }, res.token))) as Response;
        expect(ok.status).toBe(200);
    });

    it("체크하지 않은 스코프는 부여되지 않는다", async () => {
        const res = (await create(adminEvent({ name: "heliopause", scopes: ["totp.verify"] }))) as { token: string };

        const { status } = await catchError(() => enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }, res.token)));
        expect(status).toBe(401);
    });

    it("정의되지 않은 스코프는 400", async () => {
        const res = (await create(adminEvent({ name: "bad", scopes: ["totp.verify", "admin.everything"] }))) as { status?: number };
        expect(res.status).toBe(400);
        expect(await mem.db.select().from(serviceApiTokens)).toEqual([]);
    });

    it("스코프를 하나도 안 고르면 400", async () => {
        const res = (await create(adminEvent({ name: "bad" }))) as { status?: number };
        expect(res.status).toBe(400);
    });

    it("감사에 평문을 남기지 않는다", async () => {
        const res = (await create(adminEvent({ name: "heliopause", scopes: ["totp.verify"] }))) as { token: string };

        const rows = await mem.db.select({ detailJson: auditEvents.detailJson }).from(auditEvents).where(eq(auditEvents.kind, "service_api_token_created"));
        expect(rows).toHaveLength(1);
        const detail = rows[0].detailJson!;
        expect(detail).not.toContain(res.token);
        expect(JSON.parse(detail)).toMatchObject({ name: "heliopause", scopes: ["totp.verify"] });
    });

    it("폐기하면 그 토큰은 즉시 거부된다", async () => {
        const res = (await create(adminEvent({ name: "heliopause", scopes: ["totp.enroll"] }))) as { token: string };
        const [row] = await mem.db.select().from(serviceApiTokens);

        await revoke(adminEvent({ tokenId: row.id }));

        expect(await mem.db.select().from(serviceApiTokens)).toEqual([]);
        const { status } = await catchError(() => enrollInitPOST(svcEvent("/api/totp/enroll/init", { userId: user.id }, res.token)));
        expect(status).toBe(401);
    });

    it("다른 테넌트의 토큰은 폐기되지 않는다", async () => {
        const otherTenantId = crypto.randomUUID();
        await mem.db.insert(tenants).values({ id: otherTenantId, slug: `x-${otherTenantId.slice(0, 8)}`, name: "Other" });
        const foreignId = crypto.randomUUID();
        await mem.db.insert(serviceApiTokens).values({
            id: foreignId,
            tenantId: otherTenantId,
            name: "foreign",
            tokenHash: await hashServiceToken("kst_foreign"),
            tokenPrefix: "kst_foreig",
            scopes: "totp.verify",
        });

        const res = (await revoke(adminEvent({ tokenId: foreignId }))) as { status?: number };
        expect(res.status).toBe(404);
        expect(await mem.db.select().from(serviceApiTokens)).toHaveLength(1);
    });
});
