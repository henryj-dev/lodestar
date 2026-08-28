import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { GET as authorizeGET } from "../../src/routes/oidc/authorize/+server";
import { POST as tokenPOST } from "../../src/routes/oidc/token/+server";
import { GET as userinfoGET } from "../../src/routes/oidc/userinfo/+server";
import { verifyIdToken } from "../../src/lib/server/crypto/keys";
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
    makeCookieJar,
    TEST_ISSUER_URL,
    type MemoryDb,
} from "./harness";
import type { Tenant, User, Session } from "../../src/lib/server/db/schema";

// OIDC Authorization Code + PKCE 풀플로우를 실 DB(libSQL :memory:) + 실 라우트 핸들러로 검증한다.
// authorize(PKCE) → code → token(id_token/access_token/refresh_token) → userinfo, 그리고 code 1회 소진.

const CLIENT_ID = "test-web-client";
const CLIENT_SECRET = "s3cr3t-client-secret-value-0123456789";
const REDIRECT_URI = "https://app.test.example/callback";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;
let session: Session;
let clientDbId: string;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, {
        tenantId: tenant.id,
        email: "alice@test.example",
        username: "alice",
        password: "correct horse battery staple",
        displayName: "Alice Example",
    });
    const client = await seedOidcClient(mem.db, {
        tenantId: tenant.id,
        clientId: CLIENT_ID,
        secret: CLIENT_SECRET,
        redirectUris: [REDIRECT_URI],
        scopes: "openid profile email offline_access",
    });
    clientDbId = client.id;
    await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "oidc", serviceRefId: clientDbId });
    const seeded = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id });
    session = seeded.session;
});

afterEach(() => {
    mem.close();
});

/** authorize 를 호출하고 발급된 authorization code 를 돌려준다. */
async function runAuthorize(verifier: string, opts: { state?: string; nonce?: string } = {}): Promise<string> {
    const challenge = await pkceChallengeS256(verifier);
    const params = new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        scope: "openid profile email offline_access",
        code_challenge: challenge,
        code_challenge_method: "S256",
    });
    if (opts.state) params.set("state", opts.state);
    if (opts.nonce) params.set("nonce", opts.nonce);

    const event = makeEvent({
        method: "GET",
        url: `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`,
        locals: { db: mem.db, tenant, user, session, env: mem.env },
    });

    const { status, location } = await catchRedirect(() => authorizeGET(event));
    expect(status).toBe(302);
    const dest = new URL(location);
    expect(`${dest.origin}${dest.pathname}`).toBe(REDIRECT_URI);
    const code = dest.searchParams.get("code");
    expect(code).toBeTruthy();
    if (opts.state) expect(dest.searchParams.get("state")).toBe(opts.state);
    return code!;
}

async function runToken(form: Record<string, string>): Promise<Response> {
    const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
    return (await tokenPOST(
        makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/oidc/token`,
            headers: { authorization: `Basic ${basic}` },
            form,
            locals: { db: mem.db, tenant, env: mem.env },
        }),
    )) as Response;
}

describe("OIDC 풀플로우 (authorize → token → userinfo)", () => {
    it("PKCE 인가코드 교환으로 id_token/access_token/refresh_token 을 발급하고 검증한다", async () => {
        const verifier = "pkce-verifier-abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFG";
        const code = await runAuthorize(verifier, { state: "xyz-state", nonce: "nonce-123" });

        const res = await runToken({
            grant_type: "authorization_code",
            code,
            redirect_uri: REDIRECT_URI,
            code_verifier: verifier,
        });
        expect(res.status).toBe(200);
        const body = (await res.json()) as Record<string, string>;
        expect(body.token_type).toBe("Bearer");
        expect(body.access_token).toBeTruthy();
        expect(body.id_token).toBeTruthy();
        // offline_access 요청 + refresh_token grant 허용 → refresh token 발급
        expect(body.refresh_token).toBeTruthy();

        // 실 서명키로 id_token 서명 검증 + 클레임 확인
        const claims = await verifyIdToken(mem.db, tenant.id, body.id_token, { expectedIssuer: TEST_ISSUER_URL, expectedAud: CLIENT_ID });
        expect(claims).not.toBeNull();
        expect(claims!.sub).toBe(user.id);
        expect(claims!.iss).toBe(TEST_ISSUER_URL);
        expect(claims!.aud).toBe(CLIENT_ID);
        expect(claims!.nonce).toBe("nonce-123");
        expect(claims!.email).toBe("alice@test.example");
        expect(claims!.sid).toBe(session.id);

        // access token 으로 userinfo 조회
        const uinfo = (await userinfoGET(
            makeEvent({
                method: "GET",
                url: `${TEST_ISSUER_URL}/oidc/userinfo`,
                headers: { authorization: `Bearer ${body.access_token}` },
                locals: { db: mem.db, tenant, env: mem.env },
            }),
        )) as Response;
        expect(uinfo.status).toBe(200);
        const ui = (await uinfo.json()) as Record<string, unknown>;
        expect(ui.sub).toBe(user.id);
        expect(ui.email).toBe("alice@test.example");
        expect(ui.name).toBe("Alice Example");
    });

    it("authorization code 는 1회만 소진된다(재사용 거부)", async () => {
        const verifier = "verifier-second-case-zzzzzzzzzzzzzzzzzzzzzzzzz-000111222333";
        const code = await runAuthorize(verifier);

        const first = await runToken({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier });
        expect(first.status).toBe(200);

        const second = await runToken({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier });
        expect(second.status).toBe(400);
        const err = (await second.json()) as Record<string, string>;
        expect(err.error).toBe("invalid_grant");
    });

    it("PKCE code_verifier 불일치 시 거부한다", async () => {
        const verifier = "verifier-correct-value-mismatch-case-4444555566667777";
        const code = await runAuthorize(verifier);
        const res = await runToken({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: "wrong-verifier-value" });
        expect(res.status).toBe(400);
        expect(((await res.json()) as Record<string, string>).error).toBe("invalid_grant");
    });

    it("서비스 접근 권한 매핑이 없으면 SSO 를 거부한다(기본 deny)", async () => {
        // 권한 없는 별도 유저 + 세션으로 authorize 시도
        const other = await seedUser(mem.db, { tenantId: tenant.id, email: "mallory@test.example", username: "mallory", password: "pw" });
        const otherSession = (await seedSession(mem.db, { tenantId: tenant.id, userId: other.id })).session;
        const challenge = await pkceChallengeS256("verifier-denied-user-8888999900001111aaaa");
        const params = new URLSearchParams({
            client_id: CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            response_type: "code",
            scope: "openid",
            code_challenge: challenge,
            code_challenge_method: "S256",
        });
        const event = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`,
            locals: { db: mem.db, tenant, user: other, session: otherSession, env: mem.env },
        });
        const { location } = await catchRedirect(() => authorizeGET(event));
        const dest = new URL(location);
        expect(dest.searchParams.get("error")).toBe("access_denied");
        expect(dest.searchParams.get("code")).toBeNull();
    });

    it("allowAllUsers 클라이언트는 서비스 매핑 없는 사용자도 SSO 를 허용한다", async () => {
        await seedOidcClient(mem.db, {
            tenantId: tenant.id,
            clientId: "open-client",
            secret: CLIENT_SECRET,
            redirectUris: [REDIRECT_URI],
            allowAllUsers: true,
        });
        // 매핑 없는 별도 유저 + 세션으로 authorize → allowAllUsers 게이트 통과, code 발급.
        const other = await seedUser(mem.db, { tenantId: tenant.id, email: "bob@test.example", username: "bob", password: "pw" });
        const otherSession = (await seedSession(mem.db, { tenantId: tenant.id, userId: other.id })).session;
        const challenge = await pkceChallengeS256("verifier-allow-all-users-2222333344445555bbbb");
        const params = new URLSearchParams({
            client_id: "open-client",
            redirect_uri: REDIRECT_URI,
            response_type: "code",
            scope: "openid",
            code_challenge: challenge,
            code_challenge_method: "S256",
        });
        const event = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`,
            locals: { db: mem.db, tenant, user: other, session: otherSession, env: mem.env },
        });
        const { status, location } = await catchRedirect(() => authorizeGET(event));
        expect(status).toBe(302);
        const dest = new URL(location);
        expect(dest.searchParams.get("error")).toBeNull();
        expect(dest.searchParams.get("code")).toBeTruthy();
    });

    it("requireVerifiedEmail 클라이언트는 이메일 미인증 사용자를 access_denied 로 거부한다(R6)", async () => {
        await seedOidcClient(mem.db, {
            tenantId: tenant.id,
            clientId: "verified-email-client",
            secret: CLIENT_SECRET,
            redirectUris: [REDIRECT_URI],
            allowAllUsers: true, // 서비스 게이트를 통과시켜 이메일 인증 게이트만 검증
            requireVerifiedEmail: true,
        });
        const unverified = await seedUser(mem.db, { tenantId: tenant.id, email: "unverified@test.example", username: "unverified", password: "pw", emailVerifiedAt: null });
        const sess = (await seedSession(mem.db, { tenantId: tenant.id, userId: unverified.id })).session;
        const challenge = await pkceChallengeS256("verifier-unverified-email-3333444455556666cccc");
        const params = new URLSearchParams({
            client_id: "verified-email-client",
            redirect_uri: REDIRECT_URI,
            response_type: "code",
            scope: "openid",
            code_challenge: challenge,
            code_challenge_method: "S256",
        });
        const event = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`,
            locals: { db: mem.db, tenant, user: unverified, session: sess, env: mem.env },
        });
        const { location } = await catchRedirect(() => authorizeGET(event));
        const dest = new URL(location);
        expect(dest.searchParams.get("error")).toBe("access_denied");
        expect(dest.searchParams.get("code")).toBeNull();
    });

    it("requireVerifiedEmail 클라이언트도 이메일 인증된 사용자는 허용한다(R6)", async () => {
        await seedOidcClient(mem.db, {
            tenantId: tenant.id,
            clientId: "verified-email-client-ok",
            secret: CLIENT_SECRET,
            redirectUris: [REDIRECT_URI],
            allowAllUsers: true,
            requireVerifiedEmail: true,
        });
        // seedUser 는 emailVerifiedAt 를 기본 now(=인증됨)로 설정한다.
        const verified = await seedUser(mem.db, { tenantId: tenant.id, email: "verified@test.example", username: "verifieduser", password: "pw" });
        const sess = (await seedSession(mem.db, { tenantId: tenant.id, userId: verified.id })).session;
        const challenge = await pkceChallengeS256("verifier-verified-email-7777888899990000dddd");
        const params = new URLSearchParams({
            client_id: "verified-email-client-ok",
            redirect_uri: REDIRECT_URI,
            response_type: "code",
            scope: "openid",
            code_challenge: challenge,
            code_challenge_method: "S256",
        });
        const event = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`,
            locals: { db: mem.db, tenant, user: verified, session: sess, env: mem.env },
        });
        const { status, location } = await catchRedirect(() => authorizeGET(event));
        expect(status).toBe(302);
        const dest = new URL(location);
        expect(dest.searchParams.get("error")).toBeNull();
        expect(dest.searchParams.get("code")).toBeTruthy();
    });
});

describe("OIDC authorize 재인증(prompt=login / max_age)", () => {
    /** authorize 요청 URL 을 만든다. extra 로 prompt/max_age 등을 덧붙인다. */
    async function authorizeUrl(verifier: string, extra: Record<string, string> = {}): Promise<string> {
        const challenge = await pkceChallengeS256(verifier);
        const params = new URLSearchParams({
            client_id: CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            response_type: "code",
            scope: "openid",
            code_challenge: challenge,
            code_challenge_method: "S256",
            ...extra,
        });
        return `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`;
    }

    it("미로그인 + prompt=login 이면 /login 리다이렉트에 forceAuthn=true 를 붙인다", async () => {
        const url = await authorizeUrl("verifier-anon-prompt-login-aaaabbbbccccdddd0000", { prompt: "login" });
        const event = makeEvent({ method: "GET", url, locals: { db: mem.db, tenant, user: null, session: null, env: mem.env } });

        const { status, location } = await catchRedirect(() => authorizeGET(event));
        expect(status).toBe(302);
        const dest = new URL(location);
        expect(dest.pathname).toBe("/login");
        // 신뢰 기기가 OTP 를 건너뛰지 않도록 RP 의 재인증 요구가 반드시 전달돼야 한다.
        expect(dest.searchParams.get("forceAuthn")).toBe("true");
    });

    it("로그인 + prompt=login: 1회차는 forceAuthn 리다이렉트, 재인증 후 복귀한 2회차는 통과한다", async () => {
        const url = await authorizeUrl("verifier-loop-guard-1111222233334444eeee", { prompt: "login" });
        const jar = makeCookieJar();
        // 마커 발급 시각과의 비교가 명확하도록 기존 세션은 확실히 과거로 둔다.
        // 재인증 판정의 기준은 createdAt 이 아니라 authTime 이다(step-up 은 세션 행을 유지하면서
        // authTime 만 갱신하므로 둘이 갈라진다) — 두 값을 함께 옮겨 의도를 명확히 한다.
        const hourAgo = new Date(Date.now() - 3600 * 1000);
        const oldSession = { ...session, createdAt: hourAgo, authTime: hourAgo };

        // 1회차 — 재인증 요구로 /login 리다이렉트 + 마커 쿠키 설정
        const first = makeEvent({ method: "GET", url, locals: { db: mem.db, tenant, user, session: oldSession, env: mem.env }, cookies: jar.cookies });
        const { location: loginLocation } = await catchRedirect(() => authorizeGET(first));
        const loginDest = new URL(loginLocation);
        expect(loginDest.pathname).toBe("/login");
        expect(loginDest.searchParams.get("forceAuthn")).toBe("true");
        const markers = Object.keys(jar.snapshot()).filter((n) => n.startsWith("oidc_reauth_"));
        expect(markers).toHaveLength(1);

        // 2회차 — 재인증으로 새 세션이 생긴 뒤 동일 URL 로 복귀. 루프에 빠지지 않고 code 를 발급해야 한다.
        const reauthedSession = { ...session, createdAt: new Date(), authTime: new Date() };
        const second = makeEvent({
            method: "GET",
            url,
            locals: { db: mem.db, tenant, user, session: reauthedSession, env: mem.env },
            cookies: jar.cookies,
        });
        const { location: callbackLocation } = await catchRedirect(() => authorizeGET(second));
        const callbackDest = new URL(callbackLocation);
        expect(`${callbackDest.origin}${callbackDest.pathname}`).toBe(REDIRECT_URI);
        expect(callbackDest.searchParams.get("code")).toBeTruthy();
        // 마커 쿠키는 소진돼야 한다.
        expect(Object.keys(jar.snapshot()).filter((n) => n.startsWith("oidc_reauth_"))).toHaveLength(0);
    });

    it("로그인 + prompt=login: 재인증 없이 같은 URL 로 되돌아오면 마커가 있어도 다시 forceAuthn 을 요구한다", async () => {
        // 마커 존재 여부만 보는 가드였다면, /login 에서 아무것도 하지 않고 뒤로가기만 해도
        // prompt=login 이 소진돼 RP 의 재인증 요구를 우회할 수 있다.
        const url = await authorizeUrl("verifier-reauth-bypass-9999aaaabbbbcccc1234", { prompt: "login" });
        const jar = makeCookieJar();
        const bypassHourAgo = new Date(Date.now() - 3600 * 1000);
        const oldSession = { ...session, createdAt: bypassHourAgo, authTime: bypassHourAgo };

        const first = makeEvent({ method: "GET", url, locals: { db: mem.db, tenant, user, session: oldSession, env: mem.env }, cookies: jar.cookies });
        await catchRedirect(() => authorizeGET(first));
        expect(Object.keys(jar.snapshot()).filter((n) => n.startsWith("oidc_reauth_"))).toHaveLength(1);

        // 세션이 그대로(= 재인증하지 않음)인 채 복귀 — code 가 아니라 다시 /login 으로 가야 한다.
        const second = makeEvent({ method: "GET", url, locals: { db: mem.db, tenant, user, session: oldSession, env: mem.env }, cookies: jar.cookies });
        const { location } = await catchRedirect(() => authorizeGET(second));
        const dest = new URL(location);
        expect(dest.pathname).toBe("/login");
        expect(dest.searchParams.get("forceAuthn")).toBe("true");
    });

    it("prompt=none + max_age 초과는 login_required 오류이며 마커 쿠키를 설정하지 않는다", async () => {
        const url = await authorizeUrl("verifier-prompt-none-maxage-5555666677778888ffff", { prompt: "none", max_age: "60" });
        const jar = makeCookieJar();
        // 세션이 max_age(60초)보다 오래된 상태를 만든다. max_age 는 authTime 을 기준으로 판정한다.
        const staleAuthTime = new Date(Date.now() - 3600 * 1000);
        const staleSession = { ...session, createdAt: staleAuthTime, authTime: staleAuthTime };
        const event = makeEvent({
            method: "GET",
            url,
            locals: { db: mem.db, tenant, user, session: staleSession, env: mem.env },
            cookies: jar.cookies,
        });

        const { location } = await catchRedirect(() => authorizeGET(event));
        const dest = new URL(location);
        expect(`${dest.origin}${dest.pathname}`).toBe(REDIRECT_URI);
        expect(dest.searchParams.get("error")).toBe("login_required");
        expect(Object.keys(jar.snapshot()).filter((n) => n.startsWith("oidc_reauth_"))).toHaveLength(0);
    });
});
