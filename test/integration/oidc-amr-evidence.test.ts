import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { GET as authorizeGET } from "../../src/routes/oidc/authorize/+server";
import { POST as tokenPOST } from "../../src/routes/oidc/token/+server";
import { GET as discoveryGET } from "../../src/routes/.well-known/openid-configuration/+server";
import { actions as loginActions } from "../../src/routes/(auth)/login/+page.server";
import { verifyIdToken } from "../../src/lib/server/crypto/keys";
import { createTrustedDevice, TRUSTED_DEVICE_COOKIE } from "../../src/lib/server/auth/trusted-device";
import { encryptTotpSecret, generateTotpSecret } from "../../src/lib/server/auth/totp";
import { ACR_MFA, ACR_PASSWORD_TRANSPORT, AMR_TRUSTED_DEVICE, amrToAcr } from "../../src/lib/server/auth/constants";
import { credentials, sessions } from "../../src/lib/server/db/schema";
import {
    openMemoryDb,
    seedTenantAndSigningKey,
    seedUser,
    seedOidcClient,
    seedConsent,
    seedServiceAssignment,
    seedSession,
    makeEvent,
    makeCookieJar,
    pkceChallengeS256,
    catchRedirect,
    TEST_ISSUER_URL,
    TEST_SIGNING_SECRET,
    type MemoryDb,
} from "./harness";
import type { Tenant, User, Session } from "../../src/lib/server/db/schema";

// RP 에 나가는 MFA 증거(amr)가 실제 인증 수단과 맞는지 고정한다.
//   1. 신뢰 기기로 TOTP 를 건너뛴 로그인은 amr 에 totp 가 아니라 trusted_device 를 싣는다(ACR 은 MFA 유지).
//   2. authorization_code 로 받은 첫 id_token 에도 amr 이 실린다(예전엔 refresh 로 재발급할 때만 실렸다).

const CLIENT_ID = "amr-client";
const CLIENT_SECRET = "amr-client-secret-0123456789abcdef";
const REDIRECT_URI = "https://app.test.example/callback";
const PASSWORD = "amr-user-strong-password";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, { tenantId: tenant.id, email: "amr@test.example", username: "amruser", password: PASSWORD });
    const client = await seedOidcClient(mem.db, {
        tenantId: tenant.id,
        clientId: CLIENT_ID,
        secret: CLIENT_SECRET,
        redirectUris: [REDIRECT_URI],
        scopes: "openid profile",
    });
    await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "oidc", serviceRefId: client.id });
    await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientRefId: client.id });
});

afterEach(() => mem.close());

async function authorize(session: Session): Promise<{ code: string; verifier: string }> {
    const verifier = "amr-pkce-verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
    const params = new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        scope: "openid profile",
        code_challenge: await pkceChallengeS256(verifier),
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
    return { code: new URL(location).searchParams.get("code")!, verifier };
}

async function exchange(code: string, verifier: string): Promise<Record<string, unknown>> {
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
    const { id_token } = (await res.json()) as { id_token: string };
    const claims = await verifyIdToken(mem.db, tenant.id, id_token, { expectedIssuer: TEST_ISSUER_URL, expectedAud: CLIENT_ID });
    return claims as Record<string, unknown>;
}

describe("첫 id_token 의 amr", () => {
    it("MFA 세션이면 amr 에 실제 수단(pwd, totp)을 싣는다", async () => {
        const { session } = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id, amr: ["pwd", "totp"], acr: ACR_MFA });
        const { code, verifier } = await authorize(session);
        const claims = await exchange(code, verifier);
        expect(claims.amr).toEqual(["pwd", "totp"]);
        expect(claims.acr).toBe(ACR_MFA);
    });

    it("비밀번호만 쓴 세션이면 amr 은 pwd 하나다", async () => {
        const { session } = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id, amr: ["pwd"], acr: ACR_PASSWORD_TRANSPORT });
        const { code, verifier } = await authorize(session);
        const claims = await exchange(code, verifier);
        expect(claims.amr).toEqual(["pwd"]);
        expect(claims.acr).toBe(ACR_PASSWORD_TRANSPORT);
    });

    it("authorize 이후 세션이 승격돼 acr 이 달라졌으면 amr 을 싣지 않는다 (acr 보다 강한 수단을 말하지 않는다)", async () => {
        const { session } = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id, amr: ["pwd"], acr: ACR_PASSWORD_TRANSPORT });
        const { code, verifier } = await authorize(session);
        await mem.db.update(sessions).set({ amr: "pwd totp", acr: ACR_MFA }).where(eq(sessions.id, session.id));

        const claims = await exchange(code, verifier);
        expect(claims.amr).toBeUndefined();
        expect(claims.acr).toBe(ACR_PASSWORD_TRANSPORT);
    });
});

describe("신뢰 기기 로그인의 amr", () => {
    it("TOTP 를 건너뛴 로그인은 amr 이 pwd + trusted_device 이고 ACR 은 MFA 다", async () => {
        await mem.db.insert(credentials).values({
            id: crypto.randomUUID(),
            userId: user.id,
            type: "totp",
            secret: await encryptTotpSecret(generateTotpSecret(), TEST_SIGNING_SECRET, user.id),
            totpOwnerId: user.id,
        });
        const trusted = await createTrustedDevice(mem.db, { tenantId: tenant.id, userId: user.id });
        const jar = makeCookieJar({ [TRUSTED_DEVICE_COOKIE]: trusted.token });

        await catchRedirect(() =>
            loginActions.default(
                makeEvent({
                    method: "POST",
                    url: `${TEST_ISSUER_URL}/login`,
                    form: { username: "amruser", password: PASSWORD },
                    locals: { db: mem.db, tenant, env: mem.env },
                    cookies: jar.cookies,
                }),
            ),
        );

        const [row] = await mem.db.select().from(sessions).where(eq(sessions.userId, user.id));
        expect(row.amr).toBe(`pwd ${AMR_TRUSTED_DEVICE}`);
        expect(row.amr).not.toContain("totp");
        expect(row.acr).toBe(ACR_MFA);
    });

    it("신뢰 기기 로그인 세션으로 받은 첫 id_token 의 amr 은 pwd + trusted_device 다", async () => {
        await mem.db.insert(credentials).values({
            id: crypto.randomUUID(),
            userId: user.id,
            type: "totp",
            secret: await encryptTotpSecret(generateTotpSecret(), TEST_SIGNING_SECRET, user.id),
            totpOwnerId: user.id,
        });
        const trusted = await createTrustedDevice(mem.db, { tenantId: tenant.id, userId: user.id });
        const jar = makeCookieJar({ [TRUSTED_DEVICE_COOKIE]: trusted.token });
        await catchRedirect(() =>
            loginActions.default(
                makeEvent({
                    method: "POST",
                    url: `${TEST_ISSUER_URL}/login`,
                    form: { username: "amruser", password: PASSWORD },
                    locals: { db: mem.db, tenant, env: mem.env },
                    cookies: jar.cookies,
                }),
            ),
        );
        const [session] = await mem.db.select().from(sessions).where(eq(sessions.userId, user.id));

        const { code, verifier } = await authorize(session);
        const claims = await exchange(code, verifier);
        expect(claims.amr).toEqual(["pwd", AMR_TRUSTED_DEVICE]);
        expect(claims.acr).toBe(ACR_MFA);
    });

    it("amrToAcr: trusted_device 는 1차 수단과 함께일 때만 MFA 다", () => {
        expect(amrToAcr(["pwd", AMR_TRUSTED_DEVICE])).toBe(ACR_MFA);
        expect(amrToAcr(["fed", AMR_TRUSTED_DEVICE])).toBe(ACR_MFA);
        expect(amrToAcr([AMR_TRUSTED_DEVICE])).toBe(ACR_PASSWORD_TRANSPORT);
    });
});

describe("discovery", () => {
    it("claims_supported 에 amr 이 있다", async () => {
        const res = (await discoveryGET(makeEvent({ method: "GET", url: `${TEST_ISSUER_URL}/.well-known/openid-configuration`, locals: { db: mem.db, tenant, env: mem.env } }) as never)) as Response;
        const body = (await res.json()) as { claims_supported: string[] };
        expect(body.claims_supported).toContain("amr");
    });
});
