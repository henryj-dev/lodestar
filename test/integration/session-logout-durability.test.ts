import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { GET as authorizeGET } from "../../src/routes/oidc/authorize/+server";
import { POST as tokenPOST } from "../../src/routes/oidc/token/+server";
import { getOidcBackchannelTargets, getOidcFrontchannelTargets } from "../../src/lib/server/oidc/logout";
import { oidcClientSessions, oidcClients, oidcGrants, oidcRefreshTokens } from "../../src/lib/server/db/schema";
import {
    openMemoryDb,
    seedTenantAndSigningKey,
    seedUser,
    seedOidcClient,
    seedServiceAssignment,
    seedSession,
    makeEvent,
    pkceChallengeS256,
    catchRedirect,
    TEST_ISSUER_URL,
    type MemoryDb,
} from "./harness";
import type { Tenant, User, Session } from "../../src/lib/server/db/schema";

// 세션 단위 로그아웃 통지의 **내구성**.
//
// 예전에는 대상을 oidcGrants(authorization code, 수 분 TTL — GC 가 삭제)와 미폐기
// oidcRefreshTokens(offline_access 필요)로만 역추적했다. 그래서 offline_access 를 쓰지 않고
// 자체 세션을 오래 유지하는 RP 는 **로그인 몇 분 뒤부터 로그아웃 통지를 아예 받지 못했다** —
// 사용자가 로그아웃해도 그 RP 세션은 그대로 남았고, 아무도 그걸 알 수 없었다.
//
// 이제 토큰 발급 시 (세션, 클라이언트) 를 기록하고 그 기록으로도 찾는다.

const CLIENT_ID = "durable-logout-client";
const CLIENT_SECRET = "durable-secret-0123456789abcdef";
const REDIRECT_URI = "https://rp.test.example/callback";
const SCOPE = "openid profile email"; // offline_access 없음 = heliopause 형태

let mem: MemoryDb;
let tenant: Tenant;
let user: User;
let session: Session;
let clientDbId: string;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, { tenantId: tenant.id, email: "durable@test.example", username: "durable" });
    const client = await seedOidcClient(mem.db, {
        tenantId: tenant.id,
        clientId: CLIENT_ID,
        secret: CLIENT_SECRET,
        redirectUris: [REDIRECT_URI],
        scopes: SCOPE,
    });
    clientDbId = client.id;
    await mem.db
        .update(oidcClients)
        .set({ backchannelLogoutUri: "https://rp.test.example/bc-logout", frontchannelLogoutUri: "https://rp.test.example/fc-logout" })
        .where(eq(oidcClients.id, client.id));
    await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "oidc", serviceRefId: clientDbId });
    const seeded = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id });
    session = seeded.session;
});

afterEach(() => {
    mem.close();
});

/** authorize → token 을 완주해 실제 로그인 상태를 만든다. */
async function login(): Promise<void> {
    const verifier = "pkce-verifier-abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFG";
    const challenge = await pkceChallengeS256(verifier);
    const params = new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        scope: SCOPE,
        code_challenge: challenge,
        code_challenge_method: "S256",
    });
    const { location } = await catchRedirect(() =>
        authorizeGET(
            makeEvent({
                method: "GET",
                url: `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`,
                locals: { db: mem.db, tenant, user, session, env: mem.env },
            }),
        ),
    );
    const code = new URL(location).searchParams.get("code")!;
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
}

/** grant 가 GC 된 뒤의 상태를 만든다(refresh 는 애초에 없다 — offline_access 미요청). */
async function simulateGrantGc(): Promise<void> {
    await mem.db.delete(oidcGrants);
    const refresh = await mem.db.select().from(oidcRefreshTokens);
    expect(refresh).toEqual([]); // offline_access 를 안 썼으므로 원래 없다
}

describe("세션 단위 로그아웃 통지 내구성", () => {
    it("토큰 발급이 (세션, 클라이언트) 연결을 기록한다", async () => {
        await login();

        const rows = await mem.db.select().from(oidcClientSessions).where(eq(oidcClientSessions.sessionId, session.id));
        expect(rows).toHaveLength(1);
        expect(rows[0].clientId).toBe(CLIENT_ID);
        expect(rows[0].tenantId).toBe(tenant.id);
    });

    it("grant 가 GC 된 뒤에도 back-channel 대상으로 찾힌다", async () => {
        await login();
        await simulateGrantGc();

        const targets = await getOidcBackchannelTargets(mem.db, tenant.id, session.id);
        expect(targets).toHaveLength(1);
        expect(targets[0].clientId).toBe(CLIENT_ID);
    });

    it("grant 가 GC 된 뒤에도 front-channel 대상으로 찾힌다", async () => {
        await login();
        await simulateGrantGc();

        const targets = await getOidcFrontchannelTargets(mem.db, tenant.id, session.id, session.idpSessionId, TEST_ISSUER_URL);
        expect(targets).toHaveLength(1);
        expect(targets[0].uri).toContain("https://rp.test.example/fc-logout");
    });

    it("기록이 없으면(이 테이블 이전 세션) 예전처럼 grant 로 찾는다 — 합집합이라 회귀가 없다", async () => {
        await login();
        // 기록만 지우고 grant 는 남긴다 = 이 기능 도입 전에 만들어진 세션의 모습
        await mem.db.delete(oidcClientSessions);

        const targets = await getOidcBackchannelTargets(mem.db, tenant.id, session.id);
        expect(targets).toHaveLength(1);
    });

    it("같은 세션·클라이언트로 재발급해도 기록이 중복되지 않는다", async () => {
        await login();
        await login();

        const rows = await mem.db.select().from(oidcClientSessions).where(eq(oidcClientSessions.sessionId, session.id));
        expect(rows).toHaveLength(1);
    });

    it("다른 세션의 기록은 섞이지 않는다", async () => {
        await login();
        const other = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id });

        const targets = await getOidcBackchannelTargets(mem.db, tenant.id, other.session.id);
        expect(targets).toEqual([]);
    });

    it("세션이 삭제되면 기록도 cascade 로 사라진다", async () => {
        await login();
        const { sessions } = await import("../../src/lib/server/db/schema");
        await mem.db.delete(sessions).where(eq(sessions.id, session.id));

        const rows = await mem.db.select().from(oidcClientSessions).where(eq(oidcClientSessions.sessionId, session.id));
        expect(rows).toEqual([]);
    });
});
