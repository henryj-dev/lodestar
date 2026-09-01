import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { GET as authorizeGET } from "../../src/routes/oidc/authorize/+server";
import { POST as ssoPOST } from "../../src/routes/saml/sso/+server";
import { load as mfaLoad, actions as mfaActions } from "../../src/routes/(auth)/mfa/+page.server";
import { credentials, sessions } from "../../src/lib/server/db/schema";
import { encryptTotpSecret, generateTotpCode, generateTotpSecret } from "../../src/lib/server/auth/totp";
import { TOTP_CREDENTIAL_TYPE, ACR_MFA } from "../../src/lib/server/auth/constants";
import {
    openMemoryDb,
    seedTenantAndSigningKey,
    seedUser,
    seedOidcClient,
    seedConsent,
    seedSamlSp,
    seedServiceAssignment,
    seedSession,
    makeEvent,
    makeCookieJar,
    makeKeyCert,
    buildAuthnRequestXml,
    encodePostBindingSamlRequest,
    pkceChallengeS256,
    catchRedirect,
    TEST_ISSUER_URL,
    TEST_SIGNING_SECRET,
    type MemoryDb,
    type KeyCert,
} from "./harness";
import type { Tenant, User, Session, SamlSp } from "../../src/lib/server/db/schema";

// reauthPolicy=mfa_only 의 핵심 계약을 실 DB + 실 라우트로 검증한다.
//   1. requireMfa 클라이언트가 password-only 세션을 /mfa?stepUp=mfa 로 보낸다(정책 full 이면 /login).
//   2. /mfa load 가 세션에 바인딩된 pending 토큰을 스스로 발급한다.
//   3. OTP 통과 시 **세션 행이 유지된 채** amr/acr/authTime 만 승격된다(id·idpSessionId 불변).
//   4. 승격된 세션으로 authorize 에 복귀하면 게이트를 통과한다(무한 왕복 없음).

const MFA_PENDING_COOKIE = "idp_mfa_pending";
const SESSION_COOKIE = "idp_session";
const REDIRECT_URI = "https://heliopause.test.example/callback";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;
let session: Session;
let totpSecret: string;

/** password-only 세션(ACR 이 MFA 에 못 미치는 상태)을 만든다. */
async function seedPasswordOnlySession(): Promise<Session> {
    const { session: s } = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id, amr: ["pwd"] });
    return s;
}

async function seedClient(opts: { clientId: string; requireMfa?: boolean; reauthPolicy?: "full" | "mfa_only" }) {
    const client = await seedOidcClient(mem.db, {
        tenantId: tenant.id,
        clientId: opts.clientId,
        redirectUris: [REDIRECT_URI],
        requireMfa: opts.requireMfa,
        reauthPolicy: opts.reauthPolicy,
    });
    await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "oidc", serviceRefId: client.id });
    await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientRefId: client.id });
    return client;
}

async function authorizeUrl(clientId: string, verifier: string, extra: Record<string, string> = {}): Promise<string> {
    const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        scope: "openid",
        code_challenge: await pkceChallengeS256(verifier),
        code_challenge_method: "S256",
        ...extra,
    });
    return `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`;
}

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, {
        tenantId: tenant.id,
        email: "stepup@test.example",
        username: "stepupuser",
        password: "step-up-user-strong-password",
        displayName: "Step Up User",
    });
    totpSecret = generateTotpSecret();
    await mem.db.insert(credentials).values({
        id: crypto.randomUUID(),
        userId: user.id,
        type: TOTP_CREDENTIAL_TYPE,
        secret: await encryptTotpSecret(totpSecret, TEST_SIGNING_SECRET, user.id),
        label: "authenticator",
    });
    session = await seedPasswordOnlySession();
});

afterEach(() => mem.close());

describe("클라이언트 정책에 따른 재인증 분기", () => {
    it("requireMfa + reauthPolicy=mfa_only 는 /mfa?stepUp=mfa 로 보낸다", async () => {
        const client = await seedClient({ clientId: "heliopause-mfaonly", requireMfa: true, reauthPolicy: "mfa_only" });
        const url = await authorizeUrl(client.clientId, "verifier-stepup-mfaonly-0000111122223333");
        const event = makeEvent({ method: "GET", url, locals: { db: mem.db, tenant, user, session, env: mem.env } });

        const { status, location } = await catchRedirect(() => authorizeGET(event));
        expect(status).toBe(302);
        const dest = new URL(location);
        expect(dest.pathname).toBe("/mfa");
        expect(dest.searchParams.get("stepUp")).toBe("mfa");
        // 복귀 지점과 스킨 힌트가 보존돼야 한다.
        expect(dest.searchParams.get("redirectTo")).toContain("/oidc/authorize");
        expect(dest.searchParams.get("skinHint")).toBe(`oidc:${client.id}`);
    });

    it("requireMfa + reauthPolicy=full(기본) 은 /login?forceAuthn=true 로 보낸다", async () => {
        const client = await seedClient({ clientId: "heliopause-full", requireMfa: true });
        const url = await authorizeUrl(client.clientId, "verifier-stepup-full-4444555566667777");
        const event = makeEvent({ method: "GET", url, locals: { db: mem.db, tenant, user, session, env: mem.env } });

        const { location } = await catchRedirect(() => authorizeGET(event));
        const dest = new URL(location);
        expect(dest.pathname).toBe("/login");
        // 신뢰 기기로 OTP 를 건너뛰면 ACR 이 올라가지 않아 되돌아와서 다시 걸린다.
        expect(dest.searchParams.get("forceAuthn")).toBe("true");
    });

    it("requireMfa 클라이언트도 이미 MFA 세션이면 그대로 통과한다(패밀리 앱 재방문)", async () => {
        const client = await seedClient({ clientId: "heliopause-already-mfa", requireMfa: true, reauthPolicy: "mfa_only" });
        const { session: mfaSession } = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id, amr: ["pwd", "totp"], acr: ACR_MFA });
        const url = await authorizeUrl(client.clientId, "verifier-stepup-already-8888999900001111");
        const event = makeEvent({ method: "GET", url, locals: { db: mem.db, tenant, user, session: mfaSession, env: mem.env } });

        const { location } = await catchRedirect(() => authorizeGET(event));
        const dest = new URL(location);
        // 인증 화면을 거치지 않고 바로 code 를 발급해야 한다 — 이것이 prompt=login 과의 차이다.
        expect(`${dest.origin}${dest.pathname}`).toBe(REDIRECT_URI);
        expect(dest.searchParams.get("code")).toBeTruthy();
    });

    it("requireMfa 를 켜지 않은 클라이언트는 password-only 세션도 통과시킨다", async () => {
        const client = await seedClient({ clientId: "stardust-plain" });
        const url = await authorizeUrl(client.clientId, "verifier-stepup-plain-2222333344445555");
        const event = makeEvent({ method: "GET", url, locals: { db: mem.db, tenant, user, session, env: mem.env } });

        const { location } = await catchRedirect(() => authorizeGET(event));
        expect(new URL(location).searchParams.get("code")).toBeTruthy();
    });

    it("mfa_only 라도 id_token_hint 의 sub 가 다르면(계정 전환) 전체 로그인을 요구한다", async () => {
        const client = await seedClient({ clientId: "heliopause-hint-mismatch", requireMfa: true, reauthPolicy: "mfa_only" });
        // 서명 검증에 실패하는 hint 는 "불일치" 와 동일하게 취급된다(verifyIdToken → null).
        const url = await authorizeUrl(client.clientId, "verifier-stepup-hint-6666777788889999", { id_token_hint: "not.a.valid.jwt" });
        const event = makeEvent({ method: "GET", url, locals: { db: mem.db, tenant, user, session, env: mem.env } });

        const { location } = await catchRedirect(() => authorizeGET(event));
        const dest = new URL(location);
        // OTP 로는 계정을 바꿀 수 없으므로 step-up 이 아니라 /login 이어야 한다.
        expect(dest.pathname).toBe("/login");
        expect(dest.searchParams.get("forceAuthn")).toBe("true");
    });
});

describe("/mfa step-up 진입", () => {
    function stepUpLoadEvent(cookies: ReturnType<typeof makeCookieJar>["cookies"], redirectTo: string) {
        return makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/mfa?stepUp=mfa&redirectTo=${encodeURIComponent(redirectTo)}`,
            locals: { db: mem.db, tenant, user, session, env: mem.env },
            cookies,
        });
    }

    it("세션이 있으면 비밀번호 없이 pending 토큰을 발급하고 step-up 화면을 보여준다", async () => {
        const jar = makeCookieJar();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const data = (await mfaLoad(stepUpLoadEvent(jar.cookies, "/oidc/authorize?client_id=x") as any)) as {
            stepUp: boolean;
            canRememberDevice: boolean;
            redirectTo: string | null;
        };

        expect(jar.has(MFA_PENDING_COOKIE)).toBe(true);
        expect(data.stepUp).toBe(true);
        // step-up 은 RP 가 요구한 것이므로 신뢰 기기 옵션을 노출하지 않는다.
        expect(data.canRememberDevice).toBe(false);
        expect(data.redirectTo).toBe("/oidc/authorize?client_id=x");
    });

    it("먼저 있던 pending 토큰이 새 로그인의 목적지를 가로채지 않는다", async () => {
        const jar = makeCookieJar();
        const FIRST = "/oidc/authorize?client_id=x&state=first-login&nonce=n1";
        const SECOND = "/oidc/authorize?client_id=x&state=second-login&nonce=n2";

        // 1) 첫 로그인이 step-up 에 걸려 pending 토큰을 남긴다.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const firstData = (await mfaLoad(stepUpLoadEvent(jar.cookies, FIRST) as any)) as { redirectTo: string | null };
        expect(firstData.redirectTo).toBe(FIRST);
        const firstToken = jar.get(MFA_PENDING_COOKIE);

        // 2) 토큰이 살아 있는 동안(5분) 같은 사용자가 같은 앱에 로그인을 다시 시작한다.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const secondData = (await mfaLoad(stepUpLoadEvent(jar.cookies, SECOND) as any)) as { redirectTo: string | null };

        // 3) 화면은 **두 번째** 요청으로 돌아가야 한다. 첫 번째로 가면 RP 가 기다리는
        //    state/nonce/PKCE 와 달라 콜백이 거부된다("이 브라우저에서 시작한 로그인이 아니다").
        expect(secondData.redirectTo).toBe(SECOND);
        expect(jar.get(MFA_PENDING_COOKIE)).not.toBe(firstToken); // 목적지를 갱신해 재발급
    });

    it("목적지가 같으면 pending 토큰을 재발급하지 않는다 (불필요한 갱신 없음)", async () => {
        const jar = makeCookieJar();
        const SAME = "/oidc/authorize?client_id=x&state=same";

        await mfaLoad(stepUpLoadEvent(jar.cookies, SAME) as never);
        const token = jar.get(MFA_PENDING_COOKIE);

        await mfaLoad(stepUpLoadEvent(jar.cookies, SAME) as never);
        expect(jar.get(MFA_PENDING_COOKIE)).toBe(token);
    });

    it("미로그인 상태의 stepUp 요청은 전체 재인증으로 되돌린다", async () => {
        const jar = makeCookieJar();
        const event = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/mfa?stepUp=mfa&redirectTo=%2Foidc%2Fauthorize`,
            locals: { db: mem.db, tenant, user: null, session: null, env: mem.env },
            cookies: jar.cookies,
        });

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { location } = await catchRedirect(() => mfaLoad(event as any));
        const dest = new URL(location, TEST_ISSUER_URL);
        expect(dest.pathname).toBe("/login");
        expect(dest.searchParams.get("forceAuthn")).toBe("true");
        expect(jar.has(MFA_PENDING_COOKIE)).toBe(false);
    });

    it("TOTP 미등록 사용자는 승격할 수단이 없으므로 전체 재인증으로 되돌린다", async () => {
        await mem.db.delete(credentials).where(eq(credentials.type, TOTP_CREDENTIAL_TYPE));
        const jar = makeCookieJar();

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { location } = await catchRedirect(() => mfaLoad(stepUpLoadEvent(jar.cookies, "/oidc/authorize") as any));
        const dest = new URL(location, TEST_ISSUER_URL);
        expect(dest.pathname).toBe("/login");
        expect(dest.searchParams.get("forceAuthn")).toBe("true");
        expect(jar.has(MFA_PENDING_COOKIE)).toBe(false);
    });

    it("외부 절대 URL redirectTo 는 폐기한다(open redirect 방지)", async () => {
        const jar = makeCookieJar();
        const event = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/mfa?stepUp=mfa&redirectTo=${encodeURIComponent("https://evil.example/steal")}`,
            locals: { db: mem.db, tenant, user, session, env: mem.env },
            cookies: jar.cookies,
        });

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const data = (await mfaLoad(event as any)) as { redirectTo: string | null };
        expect(data.redirectTo).toBeNull();
    });
});

describe("step-up 완료 시 세션 승격", () => {
    /** step-up pending 쿠키를 확보한 상태의 쿠키 jar 를 만든다. */
    async function primeStepUp(redirectTo: string): Promise<ReturnType<typeof makeCookieJar>> {
        const jar = makeCookieJar();
        const event = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/mfa?stepUp=mfa&redirectTo=${encodeURIComponent(redirectTo)}`,
            locals: { db: mem.db, tenant, user, session, env: mem.env },
            cookies: jar.cookies,
        });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        await mfaLoad(event as any);
        expect(jar.has(MFA_PENDING_COOKIE)).toBe(true);
        return jar;
    }

    function submitEvent(cookies: ReturnType<typeof makeCookieJar>["cookies"], form: Record<string, string>, sessionOverride?: Session) {
        return makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/mfa`,
            form,
            locals: { db: mem.db, tenant, user, session: sessionOverride ?? session, env: mem.env },
            cookies,
        });
    }

    it("OTP 통과 시 세션 행을 유지한 채 amr/acr/authTime 만 승격한다", async () => {
        const jar = await primeStepUp("/oidc/authorize?client_id=heliopause");
        const before = (await mem.db.select().from(sessions).where(eq(sessions.id, session.id)))[0];
        const code = await generateTotpCode(totpSecret);

        const { status, location } = await catchRedirect(() => mfaActions.default(submitEvent(jar.cookies, { code })));
        expect(status).toBe(303);
        expect(location).toBe("/oidc/authorize?client_id=heliopause");

        // 세션 행은 하나뿐이어야 한다 — 새 세션을 만들면 유령 세션이 남는다.
        const rows = await mem.db.select().from(sessions).where(eq(sessions.userId, user.id));
        expect(rows).toHaveLength(1);

        const after = rows[0];
        // sid(OIDC sid)와 토큰 해시(로그아웃 통지의 sid)는 반드시 그대로여야 한다.
        expect(after.id).toBe(before.id);
        expect(after.idpSessionId).toBe(before.idpSessionId);
        expect(after.expiresAt.getTime()).toBe(before.expiresAt.getTime());
        // 세션 시작 시각은 보존되고, 인증 시각만 갱신된다.
        expect(after.createdAt.getTime()).toBe(before.createdAt.getTime());
        expect(after.authTime!.getTime()).toBeGreaterThanOrEqual(before.authTime!.getTime());
        // 기존 1차 인증 수단이 유지된 채 totp 가 더해지고 ACR 이 올라간다.
        expect(after.amr).toBe("pwd totp");
        expect(after.acr).toBe(ACR_MFA);

        // 세션 쿠키를 재발급하지 않는다.
        expect(jar.has(SESSION_COOKIE)).toBe(false);
        expect(jar.has(MFA_PENDING_COOKIE)).toBe(false);
    });

    it("승격된 세션으로 authorize 에 복귀하면 게이트를 통과한다(무한 왕복 없음)", async () => {
        const client = await seedClient({ clientId: "heliopause-roundtrip", requireMfa: true, reauthPolicy: "mfa_only" });
        const url = await authorizeUrl(client.clientId, "verifier-stepup-roundtrip-aaaabbbbcccc");

        // 1회차 — step-up 으로 리다이렉트
        const first = makeEvent({ method: "GET", url, locals: { db: mem.db, tenant, user, session, env: mem.env } });
        expect(new URL((await catchRedirect(() => authorizeGET(first))).location).pathname).toBe("/mfa");

        // step-up 수행
        const jar = await primeStepUp(url);
        const code = await generateTotpCode(totpSecret);
        await catchRedirect(() => mfaActions.default(submitEvent(jar.cookies, { code })));
        const elevated = (await mem.db.select().from(sessions).where(eq(sessions.id, session.id)))[0];

        // 2회차 — 승격된 세션으로 복귀. code 가 발급돼야 한다.
        const second = makeEvent({ method: "GET", url, locals: { db: mem.db, tenant, user, session: elevated, env: mem.env } });
        const dest = new URL((await catchRedirect(() => authorizeGET(second))).location);
        expect(`${dest.origin}${dest.pathname}`).toBe(REDIRECT_URI);
        expect(dest.searchParams.get("code")).toBeTruthy();
    });

    it("다른 세션의 step-up 토큰으로는 승격되지 않는다(sid 바인딩)", async () => {
        const jar = await primeStepUp("/oidc/authorize");
        // 같은 사용자의 다른 세션으로 제출 — 토큰의 sid 와 현재 세션 id 가 어긋난다.
        const other = await seedPasswordOnlySession();
        const code = await generateTotpCode(totpSecret);

        const { location } = await catchRedirect(() => mfaActions.default(submitEvent(jar.cookies, { code }, other)));
        expect(location).toBe("/login");

        // 어느 세션도 승격되지 않아야 한다.
        for (const id of [session.id, other.id]) {
            const row = (await mem.db.select().from(sessions).where(eq(sessions.id, id)))[0];
            expect(row.acr).not.toBe(ACR_MFA);
        }
    });

    it("승격 도중 세션이 폐기되면 승격하지 않고 로그인으로 보낸다", async () => {
        const jar = await primeStepUp("/oidc/authorize");
        await mem.db.update(sessions).set({ revokedAt: new Date() }).where(eq(sessions.id, session.id));
        const code = await generateTotpCode(totpSecret);

        const { location } = await catchRedirect(() => mfaActions.default(submitEvent(jar.cookies, { code })));
        expect(location).toBe("/login");

        const row = (await mem.db.select().from(sessions).where(eq(sessions.id, session.id)))[0];
        expect(row.acr).not.toBe(ACR_MFA);
    });

    it("잘못된 OTP 는 400 으로 거부하고 세션을 승격하지 않는다", async () => {
        const jar = await primeStepUp("/oidc/authorize");
        const valid = await generateTotpCode(totpSecret);
        const wrong = valid === "000000" ? "999999" : "000000";

        const result = (await mfaActions.default(submitEvent(jar.cookies, { code: wrong }))) as { status: number };
        expect(result.status).toBe(400);

        const row = (await mem.db.select().from(sessions).where(eq(sessions.id, session.id)))[0];
        expect(row.amr).toBe("pwd");
        expect(row.acr).not.toBe(ACR_MFA);
    });
});

describe("SAML SP 정책에 따른 재인증 분기", () => {
    const SP_ENTITY_ID = "https://heliopause-saml.test.example";
    const SP_ACS_URL = "https://heliopause-saml.test.example/acs";
    const SSO_DESTINATION = `${TEST_ISSUER_URL}/saml/sso`;

    /**
     * 서명된 AuthnRequest 를 POST 바인딩으로 제출하고, 리다이렉트 Location 을 돌려준다.
     *
     * 세션의 인증 시각을 명시적으로 과거로 둔다. `isPostReauth`(= 세션 인증 시각이 AuthnRequest
     * IssueInstant 이후인지) 판정이 "이미 재인증했는데도 ACR 이 부족하다 → NoAuthnContext" 분기를
     * 가르는데, AuthnRequest 의 IssueInstant 는 초 단위로 절삭되어 같은 초 안에서는 세션이 더
     * 나중으로 보일 수 있다. 실제 흐름(로그인 → 한참 뒤 SP 요청)에 맞춰 시각을 벌려 둔다.
     */
    async function postAuthnRequest(sp: SamlSp, kc: KeyCert, opts: { id: string; forceAuthn?: boolean; sessionOverride?: Session }): Promise<{ status: number; location: string }> {
        const xml = await buildAuthnRequestXml({
            id: opts.id,
            kc,
            issuer: sp.entityId,
            destination: SSO_DESTINATION,
            acsUrl: sp.acsUrl,
            sign: true,
            forceAuthn: opts.forceAuthn,
        });
        const hourAgo = new Date(Date.now() - 3600 * 1000);
        const event = makeEvent({
            method: "POST",
            url: SSO_DESTINATION,
            form: { SAMLRequest: encodePostBindingSamlRequest(xml) },
            locals: { db: mem.db, tenant, user, session: opts.sessionOverride ?? { ...session, createdAt: hourAgo, authTime: hourAgo }, env: mem.env },
        });
        return await catchRedirect(() => ssoPOST(event));
    }

    async function seedSp(opts: { requireMfa?: boolean; reauthPolicy?: "full" | "mfa_only" }): Promise<{ sp: SamlSp; kc: KeyCert }> {
        const kc = await makeKeyCert("Heliopause SAML SP");
        const sp = await seedSamlSp(mem.db, {
            tenantId: tenant.id,
            entityId: SP_ENTITY_ID,
            acsUrl: SP_ACS_URL,
            cert: kc.certPem,
            wantAuthnRequestsSigned: true,
            requireMfa: opts.requireMfa,
            reauthPolicy: opts.reauthPolicy,
        });
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "saml", serviceRefId: sp.id });
        await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientType: "saml", clientRefId: sp.id });
        return { sp, kc };
    }

    it("requireMfa + mfa_only SP 는 /mfa?stepUp=mfa 로 보낸다", async () => {
        const { sp, kc } = await seedSp({ requireMfa: true, reauthPolicy: "mfa_only" });
        const { location } = await postAuthnRequest(sp, kc, { id: "_req_saml_stepup_1" });

        const dest = new URL(location, TEST_ISSUER_URL);
        expect(dest.pathname).toBe("/mfa");
        expect(dest.searchParams.get("stepUp")).toBe("mfa");
        expect(dest.searchParams.get("skinHint")).toBe(`saml:${sp.id}`);
    });

    it("requireMfa + full(기본) SP 는 /login?forceAuthn=true 로 보낸다", async () => {
        const { sp, kc } = await seedSp({ requireMfa: true });
        const { location } = await postAuthnRequest(sp, kc, { id: "_req_saml_stepup_2" });

        const dest = new URL(location, TEST_ISSUER_URL);
        expect(dest.pathname).toBe("/login");
        expect(dest.searchParams.get("forceAuthn")).toBe("true");
    });

    it("mfa_only SP 는 ForceAuthn 도 OTP 승격으로 충족시킨다", async () => {
        const { sp, kc } = await seedSp({ reauthPolicy: "mfa_only" });
        const { location } = await postAuthnRequest(sp, kc, { id: "_req_saml_forceauthn_1", forceAuthn: true });

        const dest = new URL(location, TEST_ISSUER_URL);
        expect(dest.pathname).toBe("/mfa");
        expect(dest.searchParams.get("stepUp")).toBe("mfa");
    });

    it("full SP 의 ForceAuthn 은 여전히 전체 재인증이다", async () => {
        const { sp, kc } = await seedSp({});
        const { location } = await postAuthnRequest(sp, kc, { id: "_req_saml_forceauthn_2", forceAuthn: true });

        const dest = new URL(location, TEST_ISSUER_URL);
        expect(dest.pathname).toBe("/login");
        expect(dest.searchParams.get("forceAuthn")).toBe("true");
    });

    it("requireMfa SP 도 이미 MFA 세션이면 Assertion 을 발급한다", async () => {
        const { sp, kc } = await seedSp({ requireMfa: true, reauthPolicy: "mfa_only" });
        const { session: mfaSession } = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id, amr: ["pwd", "totp"], acr: ACR_MFA });

        const xml = await buildAuthnRequestXml({
            id: "_req_saml_already_mfa",
            kc,
            issuer: sp.entityId,
            destination: SSO_DESTINATION,
            acsUrl: sp.acsUrl,
            sign: true,
        });
        const event = makeEvent({
            method: "POST",
            url: SSO_DESTINATION,
            form: { SAMLRequest: encodePostBindingSamlRequest(xml) },
            locals: { db: mem.db, tenant, user, session: mfaSession, env: mem.env },
        });

        // 리다이렉트가 아니라 ACS auto-submit 폼이 나와야 한다.
        const res = (await ssoPOST(event)) as Response;
        expect(res.status).toBe(200);
        expect(await res.text()).toContain('name="SAMLResponse"');
    });
});
