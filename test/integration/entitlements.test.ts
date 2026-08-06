import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { asc, eq } from "drizzle-orm";
import { GET as authorizeGET } from "../../src/routes/oidc/authorize/+server";
import { POST as tokenPOST } from "../../src/routes/oidc/token/+server";
import { GET as userinfoGET } from "../../src/routes/oidc/userinfo/+server";
import { actions as clientDetailActions } from "../../src/routes/admin/oidc-clients/[id]/+page.server";
import { verifyIdToken } from "../../src/lib/server/crypto/keys";
import { listActiveEntitlements } from "../../src/lib/server/access/service-permissions";
import { auditEvents, serviceEntitlements, userServiceAssignments, userServiceEntitlements } from "../../src/lib/server/db/schema";
import {
    openMemoryDb,
    seedTenantAndSigningKey,
    seedUser,
    seedOidcClient,
    seedServiceAssignment,
    seedServiceEntitlement,
    grantEntitlement,
    seedSession,
    makeEvent,
    pkceChallengeS256,
    catchRedirect,
    TEST_ISSUER_URL,
    type MemoryDb,
} from "./harness";
import type { Tenant, User, Session } from "../../src/lib/server/db/schema";

// service entitlement — roles 와 직교하는 권한 축이 id_token / userinfo 에 실리는지 검증한다.
// 핵심 회귀 방어: 권한이 0개인 기존 RP 의 페이로드에 entitlements 키가 **생기지 않아야** 한다.

const CLIENT_ID = "ent-web-client";
const CLIENT_SECRET = "s3cr3t-client-secret-value-0123456789";
const REDIRECT_URI = "https://app.test.example/callback";
const SCOPE = "openid profile email";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;
let session: Session;
let clientDbId: string;
let assignmentId: string;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, {
        tenantId: tenant.id,
        email: "ent@test.example",
        username: "ent",
        password: "correct horse battery staple",
        displayName: "Ent Example",
    });
    const client = await seedOidcClient(mem.db, {
        tenantId: tenant.id,
        clientId: CLIENT_ID,
        secret: CLIENT_SECRET,
        redirectUris: [REDIRECT_URI],
        scopes: SCOPE,
    });
    clientDbId = client.id;
    assignmentId = await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "oidc", serviceRefId: clientDbId });
    const seeded = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id });
    session = seeded.session;
});

afterEach(() => {
    mem.close();
});

async function runAuthorize(verifier: string): Promise<string> {
    const challenge = await pkceChallengeS256(verifier);
    const params = new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        scope: SCOPE,
        code_challenge: challenge,
        code_challenge_method: "S256",
    });
    const event = makeEvent({
        method: "GET",
        url: `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`,
        locals: { db: mem.db, tenant, user, session, env: mem.env },
    });
    const { location } = await catchRedirect(() => authorizeGET(event));
    const code = new URL(location).searchParams.get("code");
    expect(code).toBeTruthy();
    return code!;
}

/** authorize → token 을 한 번 돌려 id_token 클레임과 access_token 을 돌려준다. */
async function issueTokens(): Promise<{ claims: Record<string, unknown>; accessToken: string }> {
    const verifier = "pkce-verifier-abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFG";
    const code = await runAuthorize(verifier);
    const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
    const res = (await tokenPOST(
        makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/oidc/token`,
            headers: { authorization: `Basic ${basic}` },
            form: { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier },
            locals: { db: mem.db, tenant, env: mem.env },
        }),
    )) as Response;
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, string>;
    const claims = await verifyIdToken(mem.db, tenant.id, body.id_token, { expectedIssuer: TEST_ISSUER_URL, expectedAud: CLIENT_ID });
    expect(claims).not.toBeNull();
    return { claims: claims as unknown as Record<string, unknown>, accessToken: body.access_token };
}

async function fetchUserinfo(accessToken: string): Promise<Record<string, unknown>> {
    const res = (await userinfoGET(
        makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/userinfo`,
            headers: { authorization: `Bearer ${accessToken}` },
            locals: { db: mem.db, tenant, env: mem.env },
        }),
    )) as Response;
    expect(res.status).toBe(200);
    return (await res.json()) as Record<string, unknown>;
}

describe("listActiveEntitlements", () => {
    it("권한이 없으면 빈 배열", async () => {
        expect(await listActiveEntitlements(mem.db, assignmentId)).toEqual([]);
    });

    it("displayOrder → key 순으로 정렬한다", async () => {
        // 삽입 순서를 정렬 결과와 다르게 두어 정렬이 실제로 동작하는지 본다.
        const publish = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "plan.publish", displayOrder: 30 });
        const read = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "site.read", displayOrder: 10 });
        const propose = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "plan.propose", displayOrder: 20 });
        for (const id of [publish, read, propose]) {
            await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: id });
        }

        expect(await listActiveEntitlements(mem.db, assignmentId)).toEqual(["site.read", "plan.propose", "plan.publish"]);
    });

    it("displayOrder 가 같으면 key 로 정렬한다", async () => {
        const b = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "b.key", displayOrder: 0 });
        const a = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "a.key", displayOrder: 0 });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: b });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: a });

        expect(await listActiveEntitlements(mem.db, assignmentId)).toEqual(["a.key", "b.key"]);
    });

    it("만료된 부여는 제외하고, 미래 만료는 포함한다", async () => {
        const expired = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "gone", displayOrder: 1 });
        const future = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "kept", displayOrder: 2 });
        const never = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "forever", displayOrder: 3 });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: expired, expiresAt: new Date(Date.now() - 60_000) });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: future, expiresAt: new Date(Date.now() + 60_000) });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: never });

        expect(await listActiveEntitlements(mem.db, assignmentId)).toEqual(["kept", "forever"]);
    });

    it("다른 배정의 권한은 섞이지 않는다", async () => {
        const other = await seedOidcClient(mem.db, {
            tenantId: tenant.id,
            clientId: "other-client",
            secret: CLIENT_SECRET,
            redirectUris: [REDIRECT_URI],
            scopes: SCOPE,
        });
        const otherAssignment = await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "oidc", serviceRefId: other.id });
        const mine = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "mine" });
        const theirs = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: other.id, key: "theirs" });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: mine });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId: otherAssignment, serviceEntitlementId: theirs });

        expect(await listActiveEntitlements(mem.db, assignmentId)).toEqual(["mine"]);
        expect(await listActiveEntitlements(mem.db, otherAssignment)).toEqual(["theirs"]);
    });

    it("배정이 삭제되면 권한 행도 cascade 로 사라진다", async () => {
        const ent = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "site.read" });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: ent });
        expect(await listActiveEntitlements(mem.db, assignmentId)).toEqual(["site.read"]);

        // 관리 콘솔의 회수 경로와 동일하게 하드 삭제한다.
        await mem.db.delete(userServiceAssignments).where(eq(userServiceAssignments.id, assignmentId));

        const left = await mem.db.select().from(userServiceEntitlements).where(eq(userServiceEntitlements.assignmentId, assignmentId));
        expect(left).toEqual([]);
    });
});

describe("entitlements 클레임 발행", () => {
    it("권한이 0개면 id_token·userinfo 에 entitlements 키가 없다 (기존 RP 무회귀)", async () => {
        const { claims, accessToken } = await issueTokens();
        expect("entitlements" in claims).toBe(false);

        const ui = await fetchUserinfo(accessToken);
        expect("entitlements" in ui).toBe(false);
    });

    it("권한이 있으면 id_token 과 userinfo 에 같은 값이 실린다", async () => {
        const read = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "site.read", displayOrder: 10 });
        const approve = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "plan.approve", displayOrder: 20 });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: read });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: approve });

        const { claims, accessToken } = await issueTokens();
        expect(claims.entitlements).toEqual(["site.read", "plan.approve"]);

        const ui = await fetchUserinfo(accessToken);
        expect(ui.entitlements).toEqual(claims.entitlements);
    });

    it("scope 를 요청하지 않아도 발행된다 (roles 와 같은 규칙, groups 와 다름)", async () => {
        // SCOPE 에 entitlements 관련 scope 가 없는데도 실려야 한다.
        const ent = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "site.read" });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: ent });

        const { claims } = await issueTokens();
        expect(claims.entitlements).toEqual(["site.read"]);
    });

    it("attributesJson 이 entitlements 를 덮어쓰지 못한다 (예약 클레임)", async () => {
        // 배정을 지우고, attributesJson 으로 권한을 위조하려는 배정을 새로 만든다.
        await mem.db.delete(userServiceAssignments).where(eq(userServiceAssignments.id, assignmentId));
        assignmentId = await seedServiceAssignment(mem.db, {
            tenantId: tenant.id,
            userId: user.id,
            serviceType: "oidc",
            serviceRefId: clientDbId,
            attributesJson: JSON.stringify({ entitlements: ["plan.approve_own"], harmless: "ok" }),
        });
        const ent = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "site.read" });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: ent });

        const { claims, accessToken } = await issueTokens();
        // 위조가 아니라 실제 부여된 권한만 실린다.
        expect(claims.entitlements).toEqual(["site.read"]);
        // 예약되지 않은 키는 정상 머지된다(기존 동작 무회귀).
        expect(claims.harmless).toBe("ok");

        const ui = await fetchUserinfo(accessToken);
        expect(ui.entitlements).toEqual(["site.read"]);
        expect(ui.harmless).toBe("ok");
    });

    it("만료된 권한은 클레임에 실리지 않는다", async () => {
        const gone = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: clientDbId, key: "gone" });
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: gone, expiresAt: new Date(Date.now() - 1000) });

        const { claims } = await issueTokens();
        expect("entitlements" in claims).toBe(false);
    });
});

// 관리 콘솔의 권한 정의 CRUD (클라이언트 상세 화면 액션).
describe("entitlement 정의 액션 (admin)", () => {
    // page.server 의 actions 객체에서 꺼내 실제 액션 함수를 그대로 호출한다.
    const addEntitlement = clientDetailActions.addEntitlement!;
    const updateEntitlement = clientDetailActions.updateEntitlement!;
    const deleteEntitlement = clientDetailActions.deleteEntitlement!;

    let admin: User;

    beforeEach(async () => {
        admin = await seedUser(mem.db, { tenantId: tenant.id, email: "admin@test.example", role: "admin" });
    });

    /** params.id = 대상 OIDC 클라이언트(oidcClients.id) 인 admin POST 이벤트. */
    function adminEvent(form: Record<string, string>) {
        const event = makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/admin/oidc-clients/${clientDbId}`,
            form,
            locals: { db: mem.db, tenant, user: admin, env: mem.env },
        });
        (event as unknown as { params: { id: string } }).params = { id: clientDbId };
        return event as Parameters<typeof addEntitlement>[0];
    }

    async function listKeys(): Promise<string[]> {
        const rows = await mem.db
            .select({ key: serviceEntitlements.key })
            .from(serviceEntitlements)
            .where(eq(serviceEntitlements.serviceRefId, clientDbId))
            .orderBy(asc(serviceEntitlements.displayOrder), asc(serviceEntitlements.key));
        return rows.map((r) => r.key);
    }

    it("점을 포함한 네임스페이스 키를 생성한다 (site.read 형태)", async () => {
        const res = await addEntitlement(adminEvent({ key: "site.read", label: "사이트 조회", displayOrder: "10" }));

        expect(res).toMatchObject({ entitlementAdded: true });
        expect(await listKeys()).toEqual(["site.read"]);

        const audits = await mem.db.select({ kind: auditEvents.kind, outcome: auditEvents.outcome }).from(auditEvents).where(eq(auditEvents.kind, "service_entitlement_created"));
        expect(audits).toHaveLength(1);
        expect(audits[0].outcome).toBe("success");
    });

    it("밑줄 포함 키도 통과한다 (plan.approve_own)", async () => {
        const res = await addEntitlement(adminEvent({ key: "plan.approve_own", label: "자기 플랜 승인" }));
        expect(res).toMatchObject({ entitlementAdded: true });
        expect(await listKeys()).toEqual(["plan.approve_own"]);
    });

    it("허용되지 않는 문자는 400 으로 거부한다", async () => {
        const res = (await addEntitlement(adminEvent({ key: "site read!", label: "bad" }))) as { status?: number };
        expect(res.status).toBe(400);
        expect(await listKeys()).toEqual([]);
    });

    it("label 이 비면 400", async () => {
        const res = (await addEntitlement(adminEvent({ key: "site.read", label: "  " }))) as { status?: number };
        expect(res.status).toBe(400);
        expect(await listKeys()).toEqual([]);
    });

    it("같은 서비스에 중복 key 는 409", async () => {
        await addEntitlement(adminEvent({ key: "site.read", label: "첫 번째" }));
        const res = (await addEntitlement(adminEvent({ key: "site.read", label: "두 번째" }))) as { status?: number };

        expect(res.status).toBe(409);
        expect(await listKeys()).toEqual(["site.read"]);
    });

    it("label·description·displayOrder 를 수정한다 (key 는 불변)", async () => {
        await addEntitlement(adminEvent({ key: "site.read", label: "before", displayOrder: "0" }));
        const [row] = await mem.db.select().from(serviceEntitlements).where(eq(serviceEntitlements.serviceRefId, clientDbId));

        const res = await updateEntitlement(adminEvent({ entitlementId: row.id, label: "after", description: "설명", displayOrder: "7" }));
        expect(res).toMatchObject({ entitlementUpdated: true });

        const [updated] = await mem.db.select().from(serviceEntitlements).where(eq(serviceEntitlements.id, row.id));
        expect(updated.label).toBe("after");
        expect(updated.description).toBe("설명");
        expect(updated.displayOrder).toBe(7);
        expect(updated.key).toBe("site.read"); // key 는 폼에 없으므로 그대로
    });

    it("삭제하면 이미 부여된 사용자 권한도 cascade 로 사라진다", async () => {
        await addEntitlement(adminEvent({ key: "site.read", label: "사이트 조회" }));
        const [row] = await mem.db.select().from(serviceEntitlements).where(eq(serviceEntitlements.serviceRefId, clientDbId));
        await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: row.id });
        expect(await listActiveEntitlements(mem.db, assignmentId)).toEqual(["site.read"]);

        const res = await deleteEntitlement(adminEvent({ entitlementId: row.id }));
        expect(res).toMatchObject({ entitlementDeleted: true });

        expect(await listKeys()).toEqual([]);
        // 부여 행이 남아 있으면 클레임에 유령 권한이 실린다.
        expect(await listActiveEntitlements(mem.db, assignmentId)).toEqual([]);
        const left = await mem.db.select().from(userServiceEntitlements).where(eq(userServiceEntitlements.serviceEntitlementId, row.id));
        expect(left).toEqual([]);
    });

    it("다른 테넌트/다른 서비스의 권한은 수정·삭제되지 않는다", async () => {
        const other = await seedOidcClient(mem.db, {
            tenantId: tenant.id,
            clientId: "other-client-2",
            secret: CLIENT_SECRET,
            redirectUris: [REDIRECT_URI],
            scopes: SCOPE,
        });
        const foreignId = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "oidc", serviceRefId: other.id, key: "theirs" });

        // adminEvent 의 params.id 는 clientDbId 이므로 다른 서비스의 행에는 닿지 않아야 한다.
        await updateEntitlement(adminEvent({ entitlementId: foreignId, label: "hijacked" }));
        await deleteEntitlement(adminEvent({ entitlementId: foreignId }));

        const [still] = await mem.db.select().from(serviceEntitlements).where(eq(serviceEntitlements.id, foreignId));
        expect(still).toBeDefined();
        expect(still.label).toBe("theirs");
    });
});
