import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { and, eq, isNull } from "drizzle-orm";
import { addAssignment, revokeAssignment, setAssignmentEntitlements } from "../../src/lib/server/admin/user-actions/service";
import { b64uDecode, getActiveSigningKey } from "../../src/lib/server/crypto/keys";
import { getRuntimeConfig } from "../../src/lib/server/auth/runtime";
import { ROLE_CHANGE_EVENT, sendRoleChangeSet } from "../../src/lib/server/oidc/role-change";
import { auditEvents, oidcClients, oidcRefreshTokens, serviceEntitlements, serviceRoles, userServiceAssignments } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, seedOidcClient, seedSamlSp, makeEvent, makePlatform, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Tenant, User } from "../../src/lib/server/db/schema";

// role 부여/회수 시 대상 OIDC 클라이언트의 role_change_uri 로 서명된 SET 이 발행되는지를
// 실 DB + 실 admin 액션(addAssignment/revokeAssignment)으로 검증한다.
// 계약(§1): iss / aud(=clientId) / sub / iat / jti / events[ROLE_CHANGE_EVENT].{roles,entitlements}, nonce 금지, typ=secevent+jwt.

const CLIENT_ID = "role-change-client-abc123";
const ROLE_CHANGE_URI = "https://rp.test.example/auth/oidc/role-change";

let mem: MemoryDb;
let tenant: Tenant;
let admin: User;
let target: User;

// 캡처된 outbound POST (role_change_uri 전송).
interface CapturedPost {
    url: string;
    body: string;
    contentType: string | null;
}
let captured: CapturedPost[];
let originalFetch: typeof globalThis.fetch;
let failFetch: boolean;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    admin = await seedUser(mem.db, { tenantId: tenant.id, email: "admin@test.example", role: "admin" });
    target = await seedUser(mem.db, { tenantId: tenant.id, email: "member@test.example", role: "user" });

    captured = [];
    failFetch = false;
    originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        captured.push({
            url: String(input),
            body: String(init?.body ?? ""),
            contentType: new Headers(init?.headers).get("content-type"),
        });
        if (failFetch) throw new Error("network down");
        return new Response(null, { status: 200 });
    }) as typeof globalThis.fetch;
});

afterEach(() => {
    globalThis.fetch = originalFetch;
    mem.close();
});

/** roleChangeUri 를 갖춘 OIDC 클라이언트 + (선택) role 을 시드한다. */
async function seedClientWithRole(opts: { roleChangeUri?: string | null; roleKey?: string } = {}): Promise<{ clientDbId: string; roleId: string | null }> {
    const client = await seedOidcClient(mem.db, {
        tenantId: tenant.id,
        clientId: CLIENT_ID,
        secret: "role-change-secret-0123456789abcdef",
        redirectUris: ["https://rp.test.example/callback"],
    });
    await mem.db
        .update(oidcClients)
        .set({ roleChangeUri: opts.roleChangeUri === undefined ? ROLE_CHANGE_URI : opts.roleChangeUri })
        .where(eq(oidcClients.id, client.id));

    let roleId: string | null = null;
    if (opts.roleKey) {
        roleId = crypto.randomUUID();
        await mem.db.insert(serviceRoles).values({
            id: roleId,
            tenantId: tenant.id,
            serviceType: "oidc",
            serviceRefId: client.id,
            key: opts.roleKey,
            label: opts.roleKey,
        });
    }
    return { clientDbId: client.id, roleId };
}

/** admin 컨텍스트의 POST 액션 이벤트를 만든다(params.id = 대상 사용자). */
function makeAdminEvent(form: Record<string, string>) {
    const event = makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/admin/users/${target.id}`,
        form,
        locals: { db: mem.db, tenant, user: admin, env: mem.env },
    });
    (event as unknown as { params: { id: string } }).params = { id: target.id };
    return event as Parameters<typeof addAssignment>[0];
}

function decodeJwt(jwt: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
    const [h, p] = jwt.split(".");
    const dec = new TextDecoder();
    return {
        header: JSON.parse(dec.decode(b64uDecode(h))) as Record<string, unknown>,
        payload: JSON.parse(dec.decode(b64uDecode(p))) as Record<string, unknown>,
    };
}

/** 캡처된 form body 에서 role_change_token 을 뽑는다. */
function extractToken(body: string): string {
    const params = new URLSearchParams(body);
    return params.get("role_change_token") ?? "";
}

/** role_change_set_sent audit 이벤트를 조회한다. */
async function roleChangeAudits(): Promise<{ outcome: string; detailJson: string | null }[]> {
    return mem.db.select({ outcome: auditEvents.outcome, detailJson: auditEvents.detailJson }).from(auditEvents).where(eq(auditEvents.kind, "role_change_set_sent"));
}

/** 활성 서명키 공개 JWK 로 SET 서명을 검증한다. */
async function verifySignature(jwt: string): Promise<boolean> {
    const config = getRuntimeConfig(makePlatform(mem.env));
    const key = await getActiveSigningKey(mem.db, tenant.id, config.signingKeySecrets);
    if (!key) throw new Error("활성 서명키 없음");
    const publicKey = await crypto.subtle.importKey("jwk", key.publicJwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const [h, p, s] = jwt.split(".");
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, b64uDecode(s), new TextEncoder().encode(`${h}.${p}`));
}

describe("role-change SET 발행", () => {
    it("addAssignment(role 부여): 대상 role_change_uri 로 정확히 1건 POST, 계약대로 서명된 SET", async () => {
        const { clientDbId, roleId } = await seedClientWithRole({ roleKey: "admin" });

        const before = Math.floor(Date.now() / 1000);
        const res = await addAssignment(makeAdminEvent({ service: `oidc:${clientDbId}`, serviceRoleId: roleId! }));
        const after = Math.floor(Date.now() / 1000);

        expect(res).toMatchObject({ addedAssignment: true });
        expect(captured).toHaveLength(1);
        expect(captured[0].url).toBe(ROLE_CHANGE_URI);
        expect(captured[0].contentType).toBe("application/x-www-form-urlencoded");

        const token = extractToken(captured[0].body);
        expect(token).not.toBe("");
        expect(await verifySignature(token)).toBe(true);

        const { header, payload } = decodeJwt(token);
        expect(header.typ).toBe("secevent+jwt");
        expect(header.alg).toBe("RS256");
        expect(payload.iss).toBe(TEST_ISSUER_URL);
        expect(payload.aud).toBe(CLIENT_ID); // ⚠️ clientId 문자열 (oidcClients.id uuid 아님)
        expect(payload.sub).toBe(target.id);
        expect(typeof payload.jti).toBe("string");
        expect(typeof payload.iat).toBe("number");
        expect(payload.iat as number).toBeGreaterThanOrEqual(before);
        expect(payload.iat as number).toBeLessThanOrEqual(after);
        expect(payload.nonce).toBeUndefined(); // nonce 금지
        expect(payload.events).toEqual({ [ROLE_CHANGE_EVENT]: { roles: ["admin"], entitlements: [] } });

        // 발행 성공 audit 기록
        const audits = await roleChangeAudits();
        expect(audits).toHaveLength(1);
        expect(audits[0].outcome).toBe("success");
        expect(JSON.parse(audits[0].detailJson!)).toMatchObject({ clientId: CLIENT_ID, roles: ["admin"], entitlements: [] });
    });

    it("addAssignment(role 없이 access 만): roles: [] 로 발행 (로그인 roles 클레임과 동일)", async () => {
        const { clientDbId } = await seedClientWithRole({ roleKey: "admin" });

        await addAssignment(makeAdminEvent({ service: `oidc:${clientDbId}` }));

        expect(captured).toHaveLength(1);
        const { payload } = decodeJwt(extractToken(captured[0].body));
        expect(payload.events).toEqual({ [ROLE_CHANGE_EVENT]: { roles: [], entitlements: [] } });
    });

    it("revokeAssignment(회수): roles: [] SET 을 발행한다", async () => {
        const { clientDbId, roleId } = await seedClientWithRole({ roleKey: "moderator" });
        await addAssignment(makeAdminEvent({ service: `oidc:${clientDbId}`, serviceRoleId: roleId! }));
        captured = []; // 부여 SET 은 무시하고 회수만 관찰

        const [assignment] = await mem.db.select({ id: userServiceAssignments.id }).from(userServiceAssignments).where(eq(userServiceAssignments.userId, target.id)).limit(1);
        const res = await revokeAssignment(makeAdminEvent({ assignmentId: assignment.id }));

        expect(res).toMatchObject({ revokedAssignment: true });
        expect(captured).toHaveLength(1);
        expect(captured[0].url).toBe(ROLE_CHANGE_URI);
        const { payload } = decodeJwt(extractToken(captured[0].body));
        expect(payload.sub).toBe(target.id);
        expect(payload.events).toEqual({ [ROLE_CHANGE_EVENT]: { roles: [], entitlements: [] } });
    });

    it("role_change_uri 미설정 클라이언트면 발행하지 않는다", async () => {
        const { clientDbId, roleId } = await seedClientWithRole({ roleChangeUri: null, roleKey: "admin" });

        const res = await addAssignment(makeAdminEvent({ service: `oidc:${clientDbId}`, serviceRoleId: roleId! }));

        expect(res).toMatchObject({ addedAssignment: true });
        expect(captured).toHaveLength(0);
    });

    it("serviceType !== 'oidc' (saml) 이면 발행하지 않는다", async () => {
        const sp = await seedSamlSp(mem.db, { tenantId: tenant.id, entityId: "https://sp.test.example/metadata", acsUrl: "https://sp.test.example/acs" });

        const res = await addAssignment(makeAdminEvent({ service: `saml:${sp.id}` }));

        expect(res).toMatchObject({ addedAssignment: true });
        expect(captured).toHaveLength(0);
    });

    it("전송(fetch) 실패해도 액션 자체는 성공한다 (발행 실패는 삼킨다)", async () => {
        const { clientDbId, roleId } = await seedClientWithRole({ roleKey: "admin" });
        failFetch = true;

        const res = await addAssignment(makeAdminEvent({ service: `oidc:${clientDbId}`, serviceRoleId: roleId! }));

        expect(res).toMatchObject({ addedAssignment: true });
        expect(captured).toHaveLength(1); // 시도는 했으나 던진다

        // 전송 실패는 outcome=failure audit 로 남는다
        const audits = await roleChangeAudits();
        expect(audits).toHaveLength(1);
        expect(audits[0].outcome).toBe("failure");
    });
});

// 권한(entitlement)만 바뀌어도 SET 이 나가야 한다. 이게 P6 의 본체 — 없으면 권한 회수가
// RP 세션 수명 동안 조용히 남는다.
describe("권한 변경 시 SET 발행", () => {
    async function seedEntitlement(clientDbId: string, key: string): Promise<string> {
        const id = crypto.randomUUID();
        await mem.db.insert(serviceEntitlements).values({ id, tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key, label: key });
        return id;
    }

    function userEvent(form: Record<string, string | string[]>) {
        const event = makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/admin/users/${target.id}`,
            form,
            locals: { db: mem.db, tenant, user: admin, env: mem.env },
        });
        (event as unknown as { params: { id: string } }).params = { id: target.id };
        return event as Parameters<typeof setAssignmentEntitlements>[0];
    }

    it("권한 추가만으로도 SET 이 나가고 entitlements 가 실린다", async () => {
        const { clientDbId, roleId } = await seedClientWithRole({ roleKey: "approver" });
        await addAssignment(makeAdminEvent({ service: `oidc:${clientDbId}`, serviceRoleId: roleId! }));
        const entId = await seedEntitlement(clientDbId, "site.read");
        const [assignment] = await mem.db.select().from(userServiceAssignments).where(eq(userServiceAssignments.userId, target.id));
        captured = []; // 배정 부여 시 발행분은 제외하고 본다

        await setAssignmentEntitlements(userEvent({ assignmentId: assignment.id, entitlementId: [entId] }));

        expect(captured).toHaveLength(1);
        const { payload } = decodeJwt(extractToken(captured[0].body));
        expect(payload.events).toEqual({ [ROLE_CHANGE_EVENT]: { roles: ["approver"], entitlements: ["site.read"] } });
    });

    it("권한 전부 회수 시 entitlements: [] 로 발행한다", async () => {
        const { clientDbId, roleId } = await seedClientWithRole({ roleKey: "approver" });
        await addAssignment(makeAdminEvent({ service: `oidc:${clientDbId}`, serviceRoleId: roleId! }));
        const entId = await seedEntitlement(clientDbId, "site.read");
        const [assignment] = await mem.db.select().from(userServiceAssignments).where(eq(userServiceAssignments.userId, target.id));
        await setAssignmentEntitlements(userEvent({ assignmentId: assignment.id, entitlementId: [entId] }));
        captured = [];

        await setAssignmentEntitlements(userEvent({ assignmentId: assignment.id }));

        expect(captured).toHaveLength(1);
        const { payload } = decodeJwt(extractToken(captured[0].body));
        expect(payload.events).toEqual({ [ROLE_CHANGE_EVENT]: { roles: ["approver"], entitlements: [] } });
    });

    it("바뀐 것이 없으면 발행하지 않는다 (같은 집합 재제출)", async () => {
        const { clientDbId, roleId } = await seedClientWithRole({ roleKey: "approver" });
        await addAssignment(makeAdminEvent({ service: `oidc:${clientDbId}`, serviceRoleId: roleId! }));
        const entId = await seedEntitlement(clientDbId, "site.read");
        const [assignment] = await mem.db.select().from(userServiceAssignments).where(eq(userServiceAssignments.userId, target.id));
        await setAssignmentEntitlements(userEvent({ assignmentId: assignment.id, entitlementId: [entId] }));
        captured = [];

        await setAssignmentEntitlements(userEvent({ assignmentId: assignment.id, entitlementId: [entId] }));

        expect(captured).toHaveLength(0);
    });

    // 정책 C — 제거는 refresh family 를 폐기하고, 추가는 폐기하지 않는다(재로그인 강요 없음).
    it("권한 제거 시에만 refresh token 이 폐기된다", async () => {
        const { clientDbId, roleId } = await seedClientWithRole({ roleKey: "approver" });
        await addAssignment(makeAdminEvent({ service: `oidc:${clientDbId}`, serviceRoleId: roleId! }));
        const entId = await seedEntitlement(clientDbId, "site.read");
        const [assignment] = await mem.db.select().from(userServiceAssignments).where(eq(userServiceAssignments.userId, target.id));

        async function liveRefreshCount(): Promise<number> {
            const rows = await mem.db
                .select()
                .from(oidcRefreshTokens)
                .where(and(eq(oidcRefreshTokens.userId, target.id), isNull(oidcRefreshTokens.revokedAt)));
            return rows.length;
        }
        async function issueRefresh(): Promise<void> {
            await mem.db.insert(oidcRefreshTokens).values({
                id: crypto.randomUUID(),
                tenantId: tenant.id,
                userId: target.id,
                clientId: CLIENT_ID,
                tokenHash: crypto.randomUUID(),
                scope: "openid",
                expiresAt: new Date(Date.now() + 86_400_000),
            });
        }

        // 추가 → 폐기되지 않아야 한다
        await issueRefresh();
        await setAssignmentEntitlements(userEvent({ assignmentId: assignment.id, entitlementId: [entId] }));
        expect(await liveRefreshCount()).toBe(1);

        // 제거 → 폐기돼야 한다
        await setAssignmentEntitlements(userEvent({ assignmentId: assignment.id }));
        expect(await liveRefreshCount()).toBe(0);
    });
});

// SET payload 의 **wire 계약**을 직접 검증한다.
//
// 관리 액션 경로(addAssignment/revokeAssignment)로는 entitlements 가 비어 있는 경우밖에 만들 수
// 없다 — 권한 행이 배정을 FK 로 참조하므로, 배정이 막 생겼거나(부여) 막 사라진(회수) 시점에는
// 부여된 권한이 존재할 수 없기 때문이다. 권한만 바뀌는 발행 경로는 관리 UI 단계에서 붙는다.
// 그때까지 RP(소비자)가 파서를 만들 대상은 이 함수의 출력이므로, 여기서 두 키를 모두 검증한다.
describe("role-change SET wire 계약", () => {
    it("roles 와 entitlements 를 같은 event 객체에 함께 싣는다", async () => {
        const config = getRuntimeConfig(makePlatform(mem.env));
        const key = await getActiveSigningKey(mem.db, tenant.id, config.signingKeySecrets);
        if (!key) throw new Error("활성 서명키 없음");

        await sendRoleChangeSet({ clientId: CLIENT_ID, roleChangeUri: ROLE_CHANGE_URI }, target.id, ["approver"], ["site.read", "plan.approve"], TEST_ISSUER_URL, key.privateKey, key.kid);

        expect(captured).toHaveLength(1);
        const { header, payload } = decodeJwt(extractToken(captured[0].body));
        expect(header.typ).toBe("secevent+jwt");
        expect(payload.sub).toBe(target.id);
        expect(payload.nonce).toBeUndefined();
        // 기존 RP 가 읽던 roles 의 위치·형태가 그대로이고, 같은 객체에 키가 하나 늘었을 뿐이다.
        expect(payload.events).toEqual({
            [ROLE_CHANGE_EVENT]: { roles: ["approver"], entitlements: ["site.read", "plan.approve"] },
        });
    });

    it("권한 전부 회수는 빈 배열로 전달된다 (키 생략이 아님)", async () => {
        const config = getRuntimeConfig(makePlatform(mem.env));
        const key = await getActiveSigningKey(mem.db, tenant.id, config.signingKeySecrets);
        if (!key) throw new Error("활성 서명키 없음");

        await sendRoleChangeSet({ clientId: CLIENT_ID, roleChangeUri: ROLE_CHANGE_URI }, target.id, [], [], TEST_ISSUER_URL, key.privateKey, key.kid);

        const { payload } = decodeJwt(extractToken(captured[0].body));
        const event = (payload.events as Record<string, unknown>)[ROLE_CHANGE_EVENT] as Record<string, unknown>;
        // 키가 있어야 RP 가 "전부 회수됨"과 "변경 없음"을 구분할 수 있다.
        expect("entitlements" in event).toBe(true);
        expect(event.entitlements).toEqual([]);
    });
});
