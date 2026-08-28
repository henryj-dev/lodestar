import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { GET as endSessionGET, POST as endSessionPOST } from "../../src/routes/oidc/end-session/+server";
import { b64uEncode, getActiveSigningKey, signJwt } from "../../src/lib/server/crypto/keys";
import { getRuntimeConfig } from "../../src/lib/server/auth/runtime";
import { oidcClients, sessions } from "../../src/lib/server/db/schema";
import {
    openMemoryDb,
    seedTenantAndSigningKey,
    seedUser,
    seedOidcClient,
    seedServiceAssignment,
    seedSession,
    makeEvent,
    makeCookieJar,
    makePlatform,
    catchRedirect,
    TEST_ISSUER_URL,
    type MemoryDb,
} from "./harness";
import type { Tenant, User, Session } from "../../src/lib/server/db/schema";

// RP-Initiated Logout (end-session) 을 실 DB + 실 라우트 핸들러로 검증한다.
// 핵심: id_token_hint 는 만료돼도 유효한 힌트다(OIDC RP-Initiated Logout §2) — 만료만 무시하고
// 서명/issuer/sub/aud/events 검증은 유지되는지 확인한다.

const CLIENT_ID = "test-logout-client";
const POST_LOGOUT_URI = "https://app.test.example/logged-out";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;
let session: Session;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, {
        tenantId: tenant.id,
        email: "alice@test.example",
        username: "alice",
        password: "correct horse battery staple",
    });
    const client = await seedOidcClient(mem.db, {
        tenantId: tenant.id,
        clientId: CLIENT_ID,
        secret: "s3cr3t-client-secret-value-0123456789",
        redirectUris: ["https://app.test.example/callback"],
    });
    await mem.db
        .update(oidcClients)
        .set({ postLogoutRedirectUris: JSON.stringify([POST_LOGOUT_URI]) })
        .where(eq(oidcClients.id, client.id));
    await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "oidc", serviceRefId: client.id });
    const seeded = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id });
    session = seeded.session;
});

afterEach(() => {
    mem.close();
});

const nowSec = () => Math.floor(Date.now() / 1000);

/** 활성 서명키로 id_token 을 직접 서명한다(만료 등 클레임 임의 제어용). */
async function mintIdToken(claims: Record<string, unknown>): Promise<string> {
    const config = getRuntimeConfig(makePlatform(mem.env));
    const key = await getActiveSigningKey(mem.db, tenant.id, config.signingKeySecrets);
    if (!key) throw new Error("활성 서명키가 없습니다.");
    return signJwt(claims, key.privateKey, key.kid);
}

/** 로그인 시점 발급 후 TTL 이 지난 형태의 id_token 클레임. */
function expiredClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        iss: TEST_ISSUER_URL,
        sub: user.id,
        aud: CLIENT_ID,
        iat: nowSec() - 4200,
        exp: nowSec() - 3600,
        ...overrides,
    };
}

function makeGetEvent(params: Record<string, string>) {
    const qs = new URLSearchParams(params);
    return makeEvent({
        method: "GET",
        url: `${TEST_ISSUER_URL}/oidc/end-session?${qs.toString()}`,
        locals: { db: mem.db, tenant, user, session, env: mem.env },
    });
}

async function isSessionRevoked(): Promise<boolean> {
    const [row] = await mem.db.select({ revokedAt: sessions.revokedAt }).from(sessions).where(eq(sessions.id, session.id)).limit(1);
    return row?.revokedAt != null;
}

describe("end-session: 만료 id_token_hint 수용 (RP-Initiated Logout §2)", () => {
    it("GET: 만료된 id_token_hint 로도 로그아웃 + 등록된 post_logout_redirect_uri 로 302", async () => {
        const hint = await mintIdToken(expiredClaims());
        const event = makeGetEvent({
            id_token_hint: hint,
            client_id: CLIENT_ID,
            post_logout_redirect_uri: POST_LOGOUT_URI,
            state: "xyz-state",
        });
        const { status, location } = await catchRedirect(() => endSessionGET(event));
        expect(status).toBe(302);
        const loc = new URL(location);
        expect(`${loc.origin}${loc.pathname}`).toBe(POST_LOGOUT_URI);
        expect(loc.searchParams.get("state")).toBe("xyz-state");
        expect(await isSessionRevoked()).toBe(true);
    });

    it("POST: 만료된 id_token_hint 로도 로그아웃 수행", async () => {
        const hint = await mintIdToken(expiredClaims());
        const event = makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/oidc/end-session`,
            headers: { Origin: TEST_ISSUER_URL },
            form: {
                id_token_hint: hint,
                client_id: CLIENT_ID,
                post_logout_redirect_uri: POST_LOGOUT_URI,
            },
            locals: { db: mem.db, tenant, user, session, env: mem.env },
        });
        const { status, location } = await catchRedirect(() => endSessionPOST(event));
        expect(status).toBe(302);
        expect(location).toBe(POST_LOGOUT_URI);
        expect(await isSessionRevoked()).toBe(true);
    });
});

describe("end-session: 만료 무시는 만료 검사에만 한정 — 나머지 검증 유지", () => {
    it("서명 위조(payload 교체) 토큰은 만료 여부와 무관하게 거부", async () => {
        const token = await mintIdToken(expiredClaims());
        const [header, , sig] = token.split(".");
        const forgedPayload = b64uEncode(new TextEncoder().encode(JSON.stringify(expiredClaims({ sub: "attacker" }))));
        const event = makeGetEvent({ id_token_hint: `${header}.${forgedPayload}.${sig}` });
        const res = (await endSessionGET(event)) as Response;
        expect(res.status).toBe(400);
        expect(((await res.json()) as { error: string }).error).toBe("invalid_id_token_hint");
        expect(await isSessionRevoked()).toBe(false);
    });

    it("issuer 불일치 토큰은 거부", async () => {
        const hint = await mintIdToken(expiredClaims({ iss: "https://evil.example" }));
        const event = makeGetEvent({ id_token_hint: hint });
        const res = (await endSessionGET(event)) as Response;
        expect(res.status).toBe(400);
        expect(((await res.json()) as { error: string }).error).toBe("invalid_id_token_hint");
    });

    it("sub 가 현재 세션 사용자와 다르면 거부", async () => {
        const hint = await mintIdToken(expiredClaims({ sub: crypto.randomUUID() }));
        const event = makeGetEvent({ id_token_hint: hint });
        const res = (await endSessionGET(event)) as Response;
        expect(res.status).toBe(400);
        expect(((await res.json()) as { error: string }).error).toBe("id_token_hint_mismatch");
        expect(await isSessionRevoked()).toBe(false);
    });

    it("client_id 명시 시 aud 불일치는 거부", async () => {
        const hint = await mintIdToken(expiredClaims({ aud: "some-other-client" }));
        const event = makeGetEvent({ id_token_hint: hint, client_id: CLIENT_ID });
        const res = (await endSessionGET(event)) as Response;
        expect(res.status).toBe(400);
        expect(((await res.json()) as { error: string }).error).toBe("invalid_id_token_hint");
    });

    it("events claim 보유(BC logout token) 는 미만료여도 거부 (type-confusion 방어)", async () => {
        const hint = await mintIdToken({
            iss: TEST_ISSUER_URL,
            sub: user.id,
            aud: CLIENT_ID,
            iat: nowSec(),
            exp: nowSec() + 3600,
            events: { "http://schemas.openid.net/event/backchannel-logout": {} },
        });
        const event = makeGetEvent({ id_token_hint: hint });
        const res = (await endSessionGET(event)) as Response;
        expect(res.status).toBe(400);
        expect(((await res.json()) as { error: string }).error).toBe("invalid_id_token_hint");
    });
});

// ── id_token_hint 없는 경로 (OIDC RP-Initiated Logout §2: client_id 만 보내는 RP) ──────────
//
// 규격은 id_token_hint 를 RECOMMENDED 로 두고, client_id 를 "post_logout_redirect_uri 는 쓰지만
// id_token_hint 는 쓰지 않을 때" 의 수단으로 규정한다. 소유 증명이 없으므로 즉시 로그아웃하지
// 않고 확인 화면을 거치며, 그 폼 제출에는 double-submit CSRF 토큰을 요구한다.

const CSRF_COOKIE = "idp_csrf";

/** 확인 화면 폼을 POST 하는 이벤트. 같은 쿠키 jar 를 써 CSRF 쿠키를 이어받는다. */
function makeConfirmPostEvent(cookies: ReturnType<typeof makeCookieJar>["cookies"], fields: Record<string, string>) {
    return makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/oidc/end-session`,
        headers: { Origin: TEST_ISSUER_URL },
        form: fields,
        locals: { db: mem.db, tenant, user, session, env: mem.env },
        cookies,
        csrf: false, // 이 스위트는 CSRF 동작 자체를 검증하므로 자동 주입을 끈다.
    });
}

describe("end-session: id_token_hint 없이 client_id 만 온 경우", () => {
    it("GET: 즉시 로그아웃하지 않고 확인 화면을 렌더한다", async () => {
        const jar = makeCookieJar();
        const event = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/end-session?client_id=${CLIENT_ID}&post_logout_redirect_uri=${encodeURIComponent(POST_LOGOUT_URI)}`,
            locals: { db: mem.db, tenant, user, session, env: mem.env },
            cookies: jar.cookies,
        });

        const res = (await endSessionGET(event)) as Response;
        expect(res.status).toBe(200);
        expect(res.headers.get("content-type")).toContain("text/html");
        const html = await res.text();

        // 확인 폼과 CSRF 토큰, 되돌려줄 파라미터가 실려야 한다.
        expect(html).toContain('method="POST"');
        expect(html).toContain('name="csrf"');
        expect(html).toContain(`name="client_id" value="${CLIENT_ID}"`);
        expect(html).toContain(POST_LOGOUT_URI);
        // CSRF 토큰은 쿠키로도 심겨야 double-submit 이 성립한다.
        expect(jar.has(CSRF_COOKIE)).toBe(true);
        // 아직 로그아웃되지 않았다.
        expect(await isSessionRevoked()).toBe(false);
    });

    it("확인 폼을 제출하면 로그아웃되고 등록된 post_logout_redirect_uri 로 302", async () => {
        const jar = makeCookieJar();
        const getEvent = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/end-session?client_id=${CLIENT_ID}&post_logout_redirect_uri=${encodeURIComponent(POST_LOGOUT_URI)}&state=xyz`,
            locals: { db: mem.db, tenant, user, session, env: mem.env },
            cookies: jar.cookies,
        });
        await endSessionGET(getEvent);
        const csrf = jar.snapshot()[CSRF_COOKIE];
        expect(csrf).toBeTruthy();

        const { status, location } = await catchRedirect(() =>
            endSessionPOST(
                makeConfirmPostEvent(jar.cookies, {
                    csrf,
                    client_id: CLIENT_ID,
                    post_logout_redirect_uri: POST_LOGOUT_URI,
                    state: "xyz",
                }),
            ),
        );
        expect(status).toBe(302);
        const dest = new URL(location);
        expect(`${dest.origin}${dest.pathname}`).toBe(POST_LOGOUT_URI);
        expect(dest.searchParams.get("state")).toBe("xyz");
        expect(await isSessionRevoked()).toBe(true);
    });

    it("CSRF 토큰이 없으면 403 이고 로그아웃되지 않는다 (drive-by logout 방어)", async () => {
        const jar = makeCookieJar();
        const res = (await endSessionPOST(makeConfirmPostEvent(jar.cookies, { client_id: CLIENT_ID }))) as Response;
        expect(res.status).toBe(403);
        expect(await isSessionRevoked()).toBe(false);
    });

    it("CSRF 토큰이 쿠키와 다르면 403 이고 로그아웃되지 않는다", async () => {
        const jar = makeCookieJar();
        const getEvent = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/end-session?client_id=${CLIENT_ID}`,
            locals: { db: mem.db, tenant, user, session, env: mem.env },
            cookies: jar.cookies,
        });
        await endSessionGET(getEvent);

        const res = (await endSessionPOST(makeConfirmPostEvent(jar.cookies, { csrf: "f".repeat(64), client_id: CLIENT_ID }))) as Response;
        expect(res.status).toBe(403);
        expect(await isSessionRevoked()).toBe(false);
    });

    it("등록되지 않은 client_id 는 400", async () => {
        const jar = makeCookieJar();
        const event = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/end-session?client_id=not-registered`,
            locals: { db: mem.db, tenant, user, session, env: mem.env },
            cookies: jar.cookies,
        });
        const res = (await endSessionGET(event)) as Response;
        expect(res.status).toBe(400);
        expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
    });

    it("id_token_hint 도 client_id 도 없으면 400", async () => {
        const res = (await endSessionGET(makeGetEvent({ post_logout_redirect_uri: POST_LOGOUT_URI }))) as Response;
        expect(res.status).toBe(400);
        expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
    });

    it("미로그인 상태에서는 확인 화면을 그리지 않는다 (204 — phishing/clickjacking 표면 차단)", async () => {
        const event = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/end-session?client_id=${CLIENT_ID}`,
            locals: { db: mem.db, tenant, user: null, session: null, env: mem.env },
        });
        const res = (await endSessionGET(event)) as Response;
        expect(res.status).toBe(204);
    });

    it("임베드된 요청(Sec-Fetch-Dest != document)은 확인 화면도 그리지 않는다", async () => {
        const event = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/end-session?client_id=${CLIENT_ID}`,
            headers: { "sec-fetch-dest": "iframe" },
            locals: { db: mem.db, tenant, user, session, env: mem.env },
        });
        const res = (await endSessionGET(event)) as Response;
        expect(res.status).toBe(204);
        expect(await isSessionRevoked()).toBe(false);
    });

    it("확인 화면의 클라이언트 이름은 HTML 이스케이프된다", async () => {
        await mem.db.update(oidcClients).set({ name: '<img src=x onerror="alert(1)">' }).where(eq(oidcClients.clientId, CLIENT_ID));
        const event = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/end-session?client_id=${CLIENT_ID}`,
            locals: { db: mem.db, tenant, user, session, env: mem.env },
        });
        const html = await ((await endSessionGET(event)) as Response).text();
        expect(html).not.toContain("<img src=x");
        expect(html).toContain("&lt;img src=x");
    });
});
