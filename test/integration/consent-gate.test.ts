import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { GET as authorizeGET } from "../../src/routes/oidc/authorize/+server";
import { oidcClients, oidcGrants } from "../../src/lib/server/db/schema";
import { getActiveConsent } from "../../src/lib/server/consent";
import {
    openMemoryDb,
    seedTenantAndSigningKey,
    seedUser,
    seedSession,
    seedOidcClient,
    seedServiceAssignment,
    seedConsent,
    makeEvent,
    catchRedirect,
    pkceChallengeS256,
    TEST_ISSUER_URL,
    type MemoryDb,
} from "./harness";
import type { Session, Tenant, User } from "../../src/lib/server/db/schema";

// 동의 게이트를 실 라우트로 검증한다.
//
// 게이트 체인의 마지막이고, 앞의 게이트들과 같은 방식으로 동작해야 한다 — 못 미치면 `/consent` 로
// 보내고, 승인 기록이 있으면 통과. 그리고 **발급되는 scope 는 요청 ∩ 동의** 여야 한다.

const CLIENT_ID = "consent-gate-client";
const REDIRECT_URI = "https://app.test.example/callback";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;
let session: Session;
let clientDbId: string;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, { tenantId: tenant.id, email: "consent@test.example", username: "consentuser", password: "pw" });
    session = (await seedSession(mem.db, { tenantId: tenant.id, userId: user.id })).session;
    const client = await seedOidcClient(mem.db, {
        tenantId: tenant.id,
        clientId: CLIENT_ID,
        secret: "s3cr3t-client-secret-value-0123456789",
        redirectUris: [REDIRECT_URI],
        scopes: "openid profile email phone",
    });
    clientDbId = client.id;
    await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "oidc", serviceRefId: clientDbId });
});

afterEach(() => mem.close());

async function authorize(extra: Record<string, string> = {}, opts: { loggedIn?: boolean } = {}) {
    const challenge = await pkceChallengeS256("verifier-consent-gate-0011223344556677aabb");
    const params = new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        scope: "openid profile",
        state: "st-1",
        code_challenge: challenge,
        code_challenge_method: "S256",
        ...extra,
    });
    const event = makeEvent({
        method: "GET",
        url: `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`,
        locals: { db: mem.db, tenant, user: opts.loggedIn === false ? null : user, session: opts.loggedIn === false ? null : session, env: mem.env },
    });
    return catchRedirect(() => authorizeGET(event));
}

async function grantCount(): Promise<number> {
    return (await mem.db.select().from(oidcGrants)).length;
}

describe("동의 게이트: 첫 사용", () => {
    it("동의 기록이 없으면 /consent 로 보내고 코드를 발급하지 않는다", async () => {
        const { status, location } = await authorize();

        expect(status).toBe(302);
        const dest = new URL(location);
        expect(dest.pathname).toBe("/consent");
        expect(dest.searchParams.get("clientType")).toBe("oidc");
        expect(dest.searchParams.get("clientRefId")).toBe(clientDbId);
        // 승인 후 되돌아올 원래 요청이 실려야 한다.
        expect(dest.searchParams.get("redirectTo")).toContain("/oidc/authorize");
        expect(dest.searchParams.get("redirectTo")).toContain("client_id=consent-gate-client");
        expect(dest.searchParams.get("skinHint")).toBe(`oidc:${clientDbId}`);

        expect(await grantCount()).toBe(0);
    });

    it("동의 기록이 있으면 통과해 코드를 발급한다", async () => {
        await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientRefId: clientDbId, scopes: ["openid", "profile"] });

        const { status, location } = await authorize();

        expect(status).toBe(302);
        expect(location.startsWith(REDIRECT_URI)).toBe(true);
        expect(new URL(location).searchParams.get("code")).toBeTruthy();
        expect(await grantCount()).toBe(1);
    });
});

describe("동의 게이트: 발급 범위 = 요청 ∩ 동의", () => {
    it("거부된 선택 스코프는 코드의 scope 에 실리지 않는다", async () => {
        await mem.db.update(oidcClients).set({ optionalScopes: "phone" }).where(eq(oidcClients.id, clientDbId));
        // phone 을 거부한 상태(동의에 없음).
        await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientRefId: clientDbId, scopes: ["openid", "profile"] });

        const { status } = await authorize({ scope: "openid profile phone" });
        expect(status).toBe(302);

        const [grant] = await mem.db.select().from(oidcGrants);
        expect(grant.scope).toBe("openid profile");
        expect(grant.scope).not.toContain("phone");
    });

    it("승인된 선택 스코프는 실린다", async () => {
        await mem.db.update(oidcClients).set({ optionalScopes: "phone" }).where(eq(oidcClients.id, clientDbId));
        await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientRefId: clientDbId, scopes: ["openid", "profile", "phone"] });

        await authorize({ scope: "openid profile phone" });

        const [grant] = await mem.db.select().from(oidcGrants);
        expect(grant.scope).toBe("openid profile phone");
    });

    it("선택 스코프가 거부돼 있어도 다시 묻지 않는다 (반복 노출 방지)", async () => {
        await mem.db.update(oidcClients).set({ optionalScopes: "phone" }).where(eq(oidcClients.id, clientDbId));
        await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientRefId: clientDbId, scopes: ["openid", "profile"] });

        const { location } = await authorize({ scope: "openid profile phone" });
        expect(location.startsWith(REDIRECT_URI)).toBe(true); // /consent 로 가지 않는다
    });

    it("필수 스코프가 늘어나면 다시 묻는다", async () => {
        await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientRefId: clientDbId, scopes: ["openid", "profile"] });

        const { location } = await authorize({ scope: "openid profile email" });
        expect(new URL(location).pathname).toBe("/consent");
        expect(await grantCount()).toBe(0);
    });
});

describe("동의 게이트: prompt 처리", () => {
    it("prompt=consent 는 저장된 동의를 무시하고 다시 묻는다", async () => {
        await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientRefId: clientDbId, scopes: ["openid", "profile"] });

        const { location } = await authorize({ prompt: "consent" });
        expect(new URL(location).pathname).toBe("/consent");
    });

    it("prompt=none 인데 동의가 필요하면 interaction_required 를 RP 로 돌려준다", async () => {
        const { status, location } = await authorize({ prompt: "none" });

        expect(status).toBe(302);
        const dest = new URL(location);
        expect(dest.origin + dest.pathname).toBe(REDIRECT_URI);
        expect(dest.searchParams.get("error")).toBe("interaction_required");
        expect(dest.searchParams.get("state")).toBe("st-1");
        expect(await grantCount()).toBe(0);
    });

    it("prompt=none + 동의 있음 → 정상 발급", async () => {
        await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientRefId: clientDbId, scopes: ["openid", "profile"] });

        const { location } = await authorize({ prompt: "none" });
        expect(new URL(location).searchParams.get("code")).toBeTruthy();
    });
});

describe("동의 게이트: 거부", () => {
    it("consent=denied 로 되돌아오면 access_denied 를 RP 로 돌려준다", async () => {
        const { status, location } = await authorize({ consent: "denied" });

        expect(status).toBe(302);
        const dest = new URL(location);
        expect(dest.origin + dest.pathname).toBe(REDIRECT_URI);
        expect(dest.searchParams.get("error")).toBe("access_denied");
        expect(dest.searchParams.get("state")).toBe("st-1");
        expect(await grantCount()).toBe(0);
    });

    it("거부는 동의 기록을 만들지 않는다", async () => {
        await authorize({ consent: "denied" });

        expect(await getActiveConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientType: "oidc", clientRefId: clientDbId })).toBeNull();
    });
});

describe("동의 게이트: 다른 게이트와의 순서", () => {
    it("미로그인은 동의보다 먼저 걸린다 (/login 으로)", async () => {
        const { location } = await authorize({}, { loggedIn: false });
        expect(new URL(location).pathname).toBe("/login");
    });

    it("서비스 매핑이 없으면 동의 화면 이전에 거부된다", async () => {
        const other = await seedUser(mem.db, { tenantId: tenant.id, email: "nomap@test.example", username: "nomap", password: "pw" });
        const otherSession = (await seedSession(mem.db, { tenantId: tenant.id, userId: other.id })).session;
        const challenge = await pkceChallengeS256("verifier-consent-nomap-0011223344556677aabb");
        const params = new URLSearchParams({
            client_id: CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            response_type: "code",
            scope: "openid",
            code_challenge: challenge,
            code_challenge_method: "S256",
        });
        const { location } = await catchRedirect(() =>
            authorizeGET(
                makeEvent({
                    method: "GET",
                    url: `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`,
                    locals: { db: mem.db, tenant, user: other, session: otherSession, env: mem.env },
                }),
            ),
        );

        // 동의 화면이 아니라 access_denied 로 떨어진다 — 접근 권한이 없으면 물을 이유가 없다.
        expect(new URL(location).searchParams.get("error")).toBe("access_denied");
    });
});
