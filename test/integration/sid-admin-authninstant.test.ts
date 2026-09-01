import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { load as adminLayoutLoad } from "../../src/routes/admin/+layout.server";
import { GET as authorizeGET } from "../../src/routes/oidc/authorize/+server";
import { POST as tokenPOST } from "../../src/routes/oidc/token/+server";
import { POST as ssoPOST } from "../../src/routes/saml/sso/+server";
import { getOidcFrontchannelTargets, sendOneBackchannelLogout } from "../../src/lib/server/oidc/logout";
import { requireAdminContext } from "../../src/lib/server/auth/guards";
import { credentials, oidcClients, sessions } from "../../src/lib/server/db/schema";
import { encryptTotpSecret, generateTotpSecret } from "../../src/lib/server/auth/totp";
import { TOTP_CREDENTIAL_TYPE, ACR_MFA, ACR_PASSWORD_TRANSPORT } from "../../src/lib/server/auth/constants";
import {
    openMemoryDb,
    seedTenantAndSigningKey,
    seedUser,
    seedOidcClient,
    seedConsent,
    seedSamlSp,
    seedServiceAssignment,
    seedSession,
    seedMfaSession,
    makeEvent,
    makeKeyCert,
    buildAuthnRequestXml,
    encodePostBindingSamlRequest,
    decodeSamlResponse,
    pkceChallengeS256,
    catchRedirect,
    catchError,
    TEST_ISSUER_URL,
    TEST_SIGNING_SECRET,
    type MemoryDb,
} from "./harness";
import type { Tenant, User, Session } from "../../src/lib/server/db/schema";

// 네 가지 수정의 계약을 고정한다.
//   1. sid 통일 — ID 토큰의 `sid` 와 로그아웃 통지의 `sid` 가 같은 값(sessions.id)이어야 한다.
//   2. /admin ACR 게이트 — MFA 세션만 콘솔에 들어갈 수 있고, action 직접 POST 도 막힌다.
//   3. SAML AuthnInstant — 발급 시각이 아니라 세션의 실제 인증 시각이 실린다.
//   4. isPostReauth 1초 관용 — IssueInstant 초 절삭으로 인한 오탐이 없다.

let mem: MemoryDb;
let tenant: Tenant;
let user: User;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, {
        tenantId: tenant.id,
        email: "fixes@test.example",
        username: "fixesuser",
        password: "fixes-user-strong-password",
        displayName: "Fixes User",
    });
});

afterEach(() => mem.close());

describe("sid 통일 — ID 토큰과 로그아웃 통지가 같은 값을 쓴다", () => {
    const REDIRECT_URI = "https://rp.test.example/callback";
    // 더미 client_secret. oidc-flow.test.ts 와 같은 형태로 둔다 — 시크릿 스캐너가
    // 테스트 픽스처를 진짜 유출로 오탐하지 않는 값 모양이다.
    const CLIENT_SECRET = "s3cr3t-sid-parity-value-0123456789";

    it("ID 토큰의 sid 가 sessions.id 이고, 백채널 logout_token 의 sid 도 같은 값이다", async () => {
        const client = await seedOidcClient(mem.db, {
            tenantId: tenant.id,
            clientId: "sid-parity-client",
            secret: CLIENT_SECRET,
            redirectUris: [REDIRECT_URI],
        });
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "oidc", serviceRefId: client.id });
        await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientRefId: client.id });
        await mem.db.update(oidcClients).set({ backchannelLogoutUri: "https://rp.test.example/bc-logout", backchannelLogoutSessionRequired: true }).where(eq(oidcClients.id, client.id));

        const { session } = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id });

        // authorize → code
        const verifier = "verifier-sid-parity-000011112222333344445555";
        const params = new URLSearchParams({
            client_id: client.clientId,
            redirect_uri: REDIRECT_URI,
            response_type: "code",
            scope: "openid",
            code_challenge: await pkceChallengeS256(verifier),
            code_challenge_method: "S256",
        });
        const authorizeEvent = makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`,
            locals: { db: mem.db, tenant, user, session, env: mem.env },
        });
        const { location } = await catchRedirect(() => authorizeGET(authorizeEvent));
        const code = new URL(location).searchParams.get("code")!;
        expect(code).toBeTruthy();

        // code → id_token
        const tokenEvent = makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/oidc/token`,
            headers: { authorization: `Basic ${btoa(`${client.clientId}:${CLIENT_SECRET}`)}` },
            form: { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier },
            locals: { db: mem.db, tenant, env: mem.env },
        });
        const tokenBody = (await (await tokenPOST(tokenEvent)).json()) as { id_token: string };
        const idTokenSid = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(tokenBody.id_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)))).sid;

        // ID 토큰의 sid 는 sessions.id — 세션 토큰 해시가 아니다.
        expect(idTokenSid).toBe(session.id);
        expect(idTokenSid).not.toBe(session.idpSessionId);

        // 백채널 logout_token 의 sid 도 같은 값이어야 RP 가 대상 세션을 찾을 수 있다.
        let capturedBody = "";
        const originalFetch = globalThis.fetch;
        globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
            capturedBody = String(init?.body ?? "");
            void input;
            return new Response(null, { status: 200 });
        }) as typeof globalThis.fetch;
        try {
            const { getActiveSigningKey } = await import("../../src/lib/server/crypto/keys");
            const key = (await getActiveSigningKey(mem.db, tenant.id, [TEST_SIGNING_SECRET]))!;
            await sendOneBackchannelLogout(
                { clientId: client.clientId, backchannelLogoutUri: "https://rp.test.example/bc-logout", backchannelLogoutSessionRequired: true },
                user.id,
                session.id,
                TEST_ISSUER_URL,
                key.privateKey,
                key.kid,
            );
        } finally {
            globalThis.fetch = originalFetch;
        }

        const logoutToken = new URLSearchParams(capturedBody).get("logout_token")!;
        const logoutSid = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(logoutToken.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)))).sid;
        expect(logoutSid).toBe(idTokenSid);
    });

    it("프론트채널 로그아웃 URL 의 sid 도 sessions.id 다", async () => {
        const client = await seedOidcClient(mem.db, { tenantId: tenant.id, clientId: "fc-sid-client", redirectUris: [REDIRECT_URI] });
        await mem.db.update(oidcClients).set({ frontchannelLogoutUri: "https://rp.test.example/fc-logout", frontchannelLogoutSessionRequired: true }).where(eq(oidcClients.id, client.id));
        const { session } = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id });
        // 이 세션에 클라이언트를 묶어 대상으로 잡히게 한다.
        const { recordClientSession } = await import("../../src/lib/server/oidc/logout");
        await recordClientSession(mem.db, tenant.id, session.id, client.clientId);

        const targets = await getOidcFrontchannelTargets(mem.db, tenant.id, session.id, TEST_ISSUER_URL);
        expect(targets).toHaveLength(1);
        const sid = new URL(targets[0].uri).searchParams.get("sid");
        expect(sid).toBe(session.id);
        expect(sid).not.toBe(session.idpSessionId);
    });
});

describe("/admin ACR 게이트", () => {
    /** 관리자 계정 + 지정한 ACR 의 세션. */
    async function seedAdmin(opts: { withTotp: boolean; mfaSession: boolean }): Promise<{ admin: User; session: Session }> {
        const admin = await seedUser(mem.db, {
            tenantId: tenant.id,
            email: `admin-${opts.withTotp}-${opts.mfaSession}@test.example`,
            username: `admin${opts.withTotp ? "t" : "n"}${opts.mfaSession ? "m" : "p"}`,
            password: "admin-strong-password",
            role: "admin",
        });
        if (opts.withTotp) {
            await mem.db.insert(credentials).values({
                id: crypto.randomUUID(),
                userId: admin.id,
                type: TOTP_CREDENTIAL_TYPE,
                secret: await encryptTotpSecret(generateTotpSecret(), TEST_SIGNING_SECRET, admin.id),
                label: "authenticator",
            });
        }
        const seeded = opts.mfaSession
            ? await seedMfaSession(mem.db, { tenantId: tenant.id, userId: admin.id })
            : await seedSession(mem.db, { tenantId: tenant.id, userId: admin.id, acr: ACR_PASSWORD_TRANSPORT });
        return { admin, session: seeded.session };
    }

    function layoutEvent(admin: User, session: Session) {
        return makeEvent({
            method: "GET",
            url: `${TEST_ISSUER_URL}/admin/users`,
            locals: { db: mem.db, tenant, user: admin, session, env: mem.env },
        });
    }

    it("MFA 세션이면 통과한다", async () => {
        const { admin, session } = await seedAdmin({ withTotp: true, mfaSession: true });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const data = (await adminLayoutLoad(layoutEvent(admin, session) as any)) as { currentUser: { role: string } | null };
        expect(data.currentUser?.role).toBe("admin");
    });

    it("password-only 세션은 /mfa?stepUp=mfa 로 보낸다 (TOTP 등록된 관리자)", async () => {
        const { admin, session } = await seedAdmin({ withTotp: true, mfaSession: false });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { status, location } = await catchRedirect(() => adminLayoutLoad(layoutEvent(admin, session) as any));
        expect(status).toBe(303);
        const dest = new URL(location, TEST_ISSUER_URL);
        expect(dest.pathname).toBe("/mfa");
        expect(dest.searchParams.get("stepUp")).toBe("mfa");
        expect(dest.searchParams.get("redirectTo")).toBe("/admin/users");
    });

    it("TOTP 미등록 관리자는 리다이렉트 대신 403 으로 등록을 안내한다 (무한 루프 방지)", async () => {
        const { admin, session } = await seedAdmin({ withTotp: false, mfaSession: false });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const err = await catchError(() => adminLayoutLoad(layoutEvent(admin, session) as any));
        expect(err.status).toBe(403);
    });

    it("requireAdminContext 도 password-only 세션을 403 으로 막는다 (action 직접 POST 백스톱)", async () => {
        const { admin, session } = await seedAdmin({ withTotp: true, mfaSession: false });
        // 레이아웃 load 를 거치지 않는 form action 경로를 흉내낸다.
        const err = await catchError(() =>
            requireAdminContext({
                db: mem.db,
                tenant,
                user: admin,
                session,
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
            } as any),
        );
        expect(err.status).toBe(403);
    });

    it("MFA 세션이면 requireAdminContext 를 통과한다", async () => {
        const { admin, session } = await seedAdmin({ withTotp: true, mfaSession: true });
        const ctx = requireAdminContext({
            db: mem.db,
            tenant,
            user: admin,
            session,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } as any);
        expect(ctx.user.id).toBe(admin.id);
    });
});

describe("SAML AuthnInstant — 실제 인증 시각", () => {
    const SP_ENTITY_ID = "https://authninstant-sp.test.example";
    const SP_ACS_URL = "https://authninstant-sp.test.example/acs";
    const SSO_DESTINATION = `${TEST_ISSUER_URL}/saml/sso`;

    it("발급 시각이 아니라 세션의 authTime 을 싣는다", async () => {
        const kc = await makeKeyCert("AuthnInstant SP");
        const sp = await seedSamlSp(mem.db, {
            tenantId: tenant.id,
            entityId: SP_ENTITY_ID,
            acsUrl: SP_ACS_URL,
            cert: kc.certPem,
            wantAuthnRequestsSigned: true,
        });
        await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientType: "saml", clientRefId: sp.id });
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "saml", serviceRefId: sp.id });

        // 2시간 전에 인증한 세션.
        const twoHoursAgo = new Date(Date.now() - 2 * 3600 * 1000);
        const { session } = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id, acr: ACR_MFA });
        await mem.db.update(sessions).set({ authTime: twoHoursAgo }).where(eq(sessions.id, session.id));
        const aged = (await mem.db.select().from(sessions).where(eq(sessions.id, session.id)))[0];

        const xml = await buildAuthnRequestXml({
            id: "_req_authninstant_1",
            kc,
            issuer: SP_ENTITY_ID,
            destination: SSO_DESTINATION,
            acsUrl: SP_ACS_URL,
            sign: true,
        });
        const event = makeEvent({
            method: "POST",
            url: SSO_DESTINATION,
            form: { SAMLRequest: encodePostBindingSamlRequest(xml) },
            locals: { db: mem.db, tenant, user, session: aged, env: mem.env },
        });
        const html = await ((await ssoPOST(event)) as Response).text();
        const samlResponse = html.match(/name="SAMLResponse" value="([^"]+)"/)![1];
        const responseXml = decodeSamlResponse(samlResponse);

        const authnInstant = responseXml.match(/AuthnInstant="([^"]+)"/)![1];
        const issueInstant = responseXml.match(/<samlp:Response[^>]*IssueInstant="([^"]+)"/)![1];

        // 인증 시각은 2시간 전, 발급 시각은 지금 — 둘이 달라야 한다.
        expect(Date.parse(authnInstant)).toBe(Math.floor(twoHoursAgo.getTime() / 1000) * 1000);
        expect(Date.parse(issueInstant) - Date.parse(authnInstant)).toBeGreaterThan(3600 * 1000);
    });

    it("ACR 미충족으로 첫 시도에서 재인증을 요구할 때 NoAuthnContext 로 조기 종료하지 않는다 (1초 관용)", async () => {
        const kc = await makeKeyCert("Truncation SP");
        const sp = await seedSamlSp(mem.db, {
            tenantId: tenant.id,
            entityId: "https://truncation-sp.test.example",
            acsUrl: "https://truncation-sp.test.example/acs",
            cert: kc.certPem,
            wantAuthnRequestsSigned: true,
            requireMfa: true,
        });
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "saml", serviceRefId: sp.id });

        // 세션 인증 시각을 "요청 IssueInstant 와 같은 초" 로 만든다. 관용이 없으면 초 절삭 때문에
        // 세션이 요청보다 나중으로 보여 NoAuthnContext(오류 응답)로 끝나버린다.
        const { session } = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id, acr: ACR_PASSWORD_TRANSPORT });
        const sameSecond = new Date(Math.floor(Date.now() / 1000) * 1000 + 900);
        await mem.db.update(sessions).set({ authTime: sameSecond }).where(eq(sessions.id, session.id));
        const s = (await mem.db.select().from(sessions).where(eq(sessions.id, session.id)))[0];

        const xml = await buildAuthnRequestXml({
            id: "_req_truncation_1",
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
            locals: { db: mem.db, tenant, user, session: s, env: mem.env },
        });

        // 오류 응답이 아니라 재인증 리다이렉트여야 한다.
        const { location } = await catchRedirect(() => ssoPOST(event));
        expect(new URL(location, TEST_ISSUER_URL).pathname).toBe("/login");
    });
});
