/**
 * 동의·약관을 **사람이 지나가는 순서 그대로** 태우는 시나리오 테스트.
 *
 * 개별 단위는 이미 덮여 있다(consent-gate / terms-store / terms-admin). 여기서 보는 것은
 * 그 조각들이 **이어졌을 때** 실제로 맞물리는가다. 특히 자동 검증이 비어 있던 세 지점:
 *
 *   1. 화면에서 선택 항목을 해제하면 **토큰과 UserInfo 에도** 그 정보가 없는가
 *      — 게이트 테스트는 인증 코드의 scope 까지만 본다. 코드에서 빠졌다고 UserInfo 에서도
 *        빠졌다는 보장은 없다(claims 계산이 별도 경로다).
 *   2. 철회하면 **갱신이 실제로 막히는가** — 행에 표시만 남고 토큰이 살아 있으면 철회는 이름만이다.
 *   3. 약관을 발행하면 **이미 로그인해 있던 세션**이 다음 이동에서 걸리는가
 *      — 발행 시점에 로그인해 있던 사용자를 놓치면 게이트에 구멍이 남는다.
 *
 * 전부 실제 엔드포인트 핸들러를 호출한다(모킹 없음). 시드로 상태를 만들지 않고
 * `/consent` 액션을 통과해서 동의를 만든다 — 화면과 저장이 어긋나면 여기서 드러난다.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { GET as authorizeGET } from "../../src/routes/oidc/authorize/+server";
import { POST as tokenPOST } from "../../src/routes/oidc/token/+server";
import { GET as userinfoGET } from "../../src/routes/oidc/userinfo/+server";
import { actions as consentActions } from "../../src/routes/consent/+page.server";
import { load as rootLayoutLoad } from "../../src/routes/+layout.server";
import { actions as termsActions } from "../../src/routes/terms/+page.server";
import { actions as connectionsActions } from "../../src/routes/account/connections/+page.server";
import { oidcClients, termsDocuments, userClientConsents } from "../../src/lib/server/db/schema";
import { CONSENT_PARAM } from "../../src/lib/server/consent/gate";
import { TERMS_PARAM } from "../../src/lib/server/terms/gate";
import {
    openMemoryDb,
    seedTenantAndSigningKey,
    seedUser,
    seedMfaSession,
    seedOidcClient,
    seedServiceAssignment,
    makeEvent,
    makeCookieJar,
    catchRedirect,
    TEST_ISSUER_URL,
    type MemoryDb,
} from "./harness";
import type { Session, Tenant, User } from "../../src/lib/server/db/schema";

const REDIRECT_URI = "https://app.test.example/cb";
const CLIENT_SECRET = "scenario-secret";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;
let session: Session;
let clientDbId: string;
let clientId: string;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, { tenantId: tenant.id, email: "alice@test.example", username: "alice", emailVerifiedAt: new Date() });
    session = (await seedMfaSession(mem.db, { tenantId: tenant.id, userId: user.id })).session;

    // profile 은 필수, email 은 거부 가능 — 사용자가 골라 뺄 수 있는 구성.
    const client = await seedOidcClient(mem.db, {
        tenantId: tenant.id,
        clientId: "scenario-client",
        secret: CLIENT_SECRET,
        redirectUris: [REDIRECT_URI],
        scopes: "openid profile email offline_access",
    });
    clientDbId = client.id;
    clientId = client.clientId;
    // refresh token 은 offline_access scope + refresh_token grant 가 둘 다 있어야 발급된다.
    await mem.db.update(oidcClients).set({ optionalScopes: "email", grantTypes: "authorization_code,refresh_token" }).where(eq(oidcClients.id, clientDbId));
    await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "oidc", serviceRefId: clientDbId });
});

afterEach(() => mem.close());

const AUTHORIZE_QS = `client_id=scenario-client&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=${encodeURIComponent("openid profile email offline_access")}&state=st&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256`;

/** /oidc/authorize 를 한 번 통과시킨다. 코드가 나오거나, 게이트가 어디로 보냈는지를 돌려준다. */
async function authorize(): Promise<{ code: string | null; location: string }> {
    const { location } = await catchRedirect(() =>
        authorizeGET(
            makeEvent({
                method: "GET",
                url: `${TEST_ISSUER_URL}/oidc/authorize?${AUTHORIZE_QS}`,
                locals: { db: mem.db, tenant, user, session, env: mem.env },
            }),
        ),
    );
    return { code: new URL(location, TEST_ISSUER_URL).searchParams.get("code"), location };
}

/** /consent 의 승인 액션. checkedOptional 에 넣은 선택 항목만 승인한다. */
/**
 * /consent 의 승인 액션.
 *
 * `withQuery: false` 는 **브라우저가 실제로 하는 일**을 재현한다 — `action="?/approve"` 는
 * 상대 URL 해석 시 쿼리스트링을 통째로 교체하므로, POST 는 대상 파라미터 없이 도착한다.
 * 그 경우에도 본문의 hidden input 으로 대상을 찾아 서비스로 돌아가야 한다.
 */
async function approveConsent(resumeUrl: string, checkedOptional: string[], opts: { withQuery?: boolean } = {}) {
    const withQuery = opts.withQuery ?? true;
    const query = withQuery ? `?${CONSENT_PARAM.clientType}=oidc&${CONSENT_PARAM.clientRefId}=${clientDbId}&${CONSENT_PARAM.redirectTo}=${encodeURIComponent(resumeUrl)}` : "?/approve";

    return catchRedirect(() =>
        consentActions.approve!(
            makeEvent({
                method: "POST",
                url: `${TEST_ISSUER_URL}/consent${query}`,
                headers: { Origin: TEST_ISSUER_URL },
                form: { clientType: "oidc", clientRefId: clientDbId, redirectTo: resumeUrl, optionalScope: checkedOptional },
                locals: { db: mem.db, tenant, user, session, env: mem.env, locale: "ko" },
            }),
        ),
    );
}

async function exchange(form: Record<string, string>): Promise<{ status: number; body: Record<string, string> }> {
    const basic = Buffer.from(`${clientId}:${CLIENT_SECRET}`).toString("base64");
    const res = (await tokenPOST(
        makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/oidc/token`,
            headers: { authorization: `Basic ${basic}` },
            form,
            locals: { db: mem.db, tenant, env: mem.env },
        }),
    )) as Response;
    return { status: res.status, body: (await res.json()) as Record<string, string> };
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

describe("시나리오: 처음 이용 → 동의 → 토큰", () => {
    it("선택 항목을 해제하면 토큰·UserInfo 에서도 빠진다", async () => {
        // 1) 처음 이용 — 코드가 아니라 동의 화면으로 간다.
        const first = await authorize();
        expect(first.code).toBeNull();
        expect(first.location).toContain("/consent");

        const resumeUrl = new URL(first.location, TEST_ISSUER_URL).searchParams.get(CONSENT_PARAM.redirectTo)!;
        expect(resumeUrl).toContain("/oidc/authorize");

        // 2) email 을 해제한 채 승인한다.
        await approveConsent(resumeUrl, []);

        // 3) 되돌아오면 통과하고 코드가 나온다.
        const second = await authorize();
        expect(second.code).toBeTruthy();

        // 4) 발급된 scope 에 email 이 없다.
        const tok = await exchange({
            grant_type: "authorization_code",
            code: second.code!,
            redirect_uri: REDIRECT_URI,
            code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        });
        expect(tok.status).toBe(200);
        expect(tok.body.scope!.split(" ").sort()).toEqual(["offline_access", "openid", "profile"]);

        // 5) UserInfo 에도 email 이 없다 — claims 계산은 코드와 별도 경로이므로 따로 확인해야 한다.
        const claims = await fetchUserinfo(tok.body.access_token!);
        expect(claims.sub).toBe(user.id);
        expect(claims.email).toBeUndefined();
        expect(claims.email_verified).toBeUndefined();
    });

    it("승인하면 원래 요청으로 돌아간다 (IdP 메인이 아니라)", async () => {
        const first = await authorize();
        const resumeUrl = new URL(first.location, TEST_ISSUER_URL).searchParams.get(CONSENT_PARAM.redirectTo)!;

        const back = await approveConsent(resumeUrl, []);

        expect(back.location).toBe(resumeUrl);
        expect(back.location).toContain("/oidc/authorize");
        expect(back.location).not.toBe("/");
    });

    it("POST 에 쿼리스트링이 없어도 서비스로 돌아간다", async () => {
        // 폼 액션이 쿼리를 잃는 것은 실제로 났던 버그다 — 승인은 기록되는데 사용자는 `/` 로 갔다.
        const first = await authorize();
        const resumeUrl = new URL(first.location, TEST_ISSUER_URL).searchParams.get(CONSENT_PARAM.redirectTo)!;

        const back = await approveConsent(resumeUrl, [], { withQuery: false });

        expect(back.location).toBe(resumeUrl);
        expect((await authorize()).code).toBeTruthy(); // 동의도 제대로 기록됐다
    });

    it("거부도 원래 요청으로 돌아간다 (consent=denied 를 실어서)", async () => {
        const first = await authorize();
        const resumeUrl = new URL(first.location, TEST_ISSUER_URL).searchParams.get(CONSENT_PARAM.redirectTo)!;

        const back = await catchRedirect(() =>
            consentActions.deny!(
                makeEvent({
                    method: "POST",
                    url: `${TEST_ISSUER_URL}/consent?/deny`,
                    headers: { Origin: TEST_ISSUER_URL },
                    form: { clientType: "oidc", clientRefId: clientDbId, redirectTo: resumeUrl },
                    locals: { db: mem.db, tenant, user, session, env: mem.env, locale: "ko" },
                }),
            ),
        );

        expect(back.location).toContain("/oidc/authorize");
        expect(back.location).toContain("consent=denied");
    });

    it("선택 항목을 승인하면 UserInfo 에 실린다", async () => {
        const first = await authorize();
        const resumeUrl = new URL(first.location, TEST_ISSUER_URL).searchParams.get(CONSENT_PARAM.redirectTo)!;
        await approveConsent(resumeUrl, ["email"]);

        const { code } = await authorize();
        const tok = await exchange({
            grant_type: "authorization_code",
            code: code!,
            redirect_uri: REDIRECT_URI,
            code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        });
        expect(tok.body.scope!.split(" ").sort()).toEqual(["email", "offline_access", "openid", "profile"]);

        const claims = await fetchUserinfo(tok.body.access_token!);
        expect(claims.email).toBe("alice@test.example");
    });

    it("두 번째 접속은 동의 화면을 다시 거치지 않는다", async () => {
        const first = await authorize();
        await approveConsent(new URL(first.location, TEST_ISSUER_URL).searchParams.get(CONSENT_PARAM.redirectTo)!, []);

        expect((await authorize()).code).toBeTruthy();
        expect((await authorize()).code).toBeTruthy();
    });
});

describe("시나리오: 철회 → 갱신 차단 (C4-A)", () => {
    /** 동의 → 코드 → 토큰까지 한 번에 통과시켜 refresh token 을 얻는다. */
    async function signInAndGetRefreshToken(): Promise<string> {
        const first = await authorize();
        await approveConsent(new URL(first.location, TEST_ISSUER_URL).searchParams.get(CONSENT_PARAM.redirectTo)!, ["email"]);
        const { code } = await authorize();
        const tok = await exchange({
            grant_type: "authorization_code",
            code: code!,
            redirect_uri: REDIRECT_URI,
            code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        });
        expect(tok.body.refresh_token).toBeTruthy();
        return tok.body.refresh_token!;
    }

    async function revoke() {
        return connectionsActions.revokeConsent!(
            makeEvent({
                method: "POST",
                url: `${TEST_ISSUER_URL}/account/connections`,
                headers: { Origin: TEST_ISSUER_URL },
                form: { clientType: "oidc", clientRefId: clientDbId },
                locals: { db: mem.db, tenant, user, session, env: mem.env, locale: "ko" },
            }),
        );
    }

    it("철회 전에는 갱신이 된다", async () => {
        const rt = await signInAndGetRefreshToken();
        const refreshed = await exchange({ grant_type: "refresh_token", refresh_token: rt });
        expect(refreshed.status).toBe(200);
        expect(refreshed.body.access_token).toBeTruthy();
    });

    it("철회하면 그 refresh token 으로 갱신할 수 없다", async () => {
        const rt = await signInAndGetRefreshToken();
        await revoke();

        const refreshed = await exchange({ grant_type: "refresh_token", refresh_token: rt });
        expect(refreshed.status).toBe(400);
        expect(refreshed.body.error).toBe("invalid_grant");
    });

    it("철회하면 다음 접속에서 동의를 다시 묻는다", async () => {
        await signInAndGetRefreshToken();
        expect((await authorize()).code).toBeTruthy(); // 철회 전엔 통과

        await revoke();

        const after = await authorize();
        expect(after.code).toBeNull();
        expect(after.location).toContain("/consent");
    });

    it("철회 기록은 남아서 무엇에 동의했었는지 답할 수 있다", async () => {
        await signInAndGetRefreshToken();
        await revoke();

        const rows = await mem.db.select().from(userClientConsents).where(eq(userClientConsents.userId, user.id));
        expect(rows).toHaveLength(1);
        expect(rows[0].revokedAt).not.toBeNull();
        expect(rows[0].grantedScopes.split(" ").sort()).toEqual(["email", "offline_access", "openid", "profile"]);
    });
});

describe("시나리오: 약관 발행 → 이미 로그인한 세션", () => {
    async function publishTerms(over: Partial<{ key: string; required: boolean }> = {}) {
        const key = over.key ?? "service";
        await mem.db.insert(termsDocuments).values({
            id: crypto.randomUUID(),
            tenantId: tenant.id,
            key,
            version: 1,
            locale: "ko",
            title: "서비스 이용약관",
            body: "## 제1조\n\n**중요**한 내용\n\n- 항목 하나\n- 항목 둘",
            required: over.required ?? true,
            publishedAt: new Date(),
        });
        return key;
    }

    /**
     * 루트 레이아웃 load — 모든 페이지 이동이 지나가는 자리.
     * 게이트에 걸리면 목적지를, 통과하면 null 을 돌려준다.
     */
    async function navigate(pathname: string): Promise<string | null> {
        try {
            await rootLayoutLoad({
                url: new URL(`${TEST_ISSUER_URL}${pathname}`),
                locals: { db: mem.db, tenant, user, session, env: mem.env, locale: "ko" },
                cookies: makeCookieJar().cookies,
                request: new Request(`${TEST_ISSUER_URL}${pathname}`),
            } as never);
            return null;
        } catch (e) {
            const r = e as { status?: number; location?: string };
            if (typeof r.location === "string") return r.location;
            throw e;
        }
    }

    it("발행하면 이미 로그인해 있던 세션도 다음 이동에서 걸린다", async () => {
        // 발행 전에는 그냥 지나간다.
        expect(await navigate("/account")).toBeNull();

        await publishTerms();

        const gated = await navigate("/account");
        expect(gated).toContain("/terms");
    });

    it("약관 화면 자체는 걸리지 않는다 (무한 루프 방지)", async () => {
        await publishTerms();
        expect(await navigate("/terms")).toBeNull();
    });

    it("동의하면 통과한다", async () => {
        const key = await publishTerms();
        await catchRedirect(() =>
            termsActions.default!(
                makeEvent({
                    method: "POST",
                    url: `${TEST_ISSUER_URL}/terms?${TERMS_PARAM.redirectTo}=${encodeURIComponent("/account")}`,
                    headers: { Origin: TEST_ISSUER_URL },
                    form: { redirectTo: "/account", termsKey: [key] },
                    locals: { db: mem.db, tenant, user, session, env: mem.env, locale: "ko" },
                }),
            ),
        );

        expect(await navigate("/account")).toBeNull();
    });

    it("선택 약관은 거부해도 통과한다", async () => {
        await publishTerms({ key: "marketing", required: false });
        // termsKey 를 하나도 보내지 않는다 = 전부 거부
        await catchRedirect(() =>
            termsActions.default!(
                makeEvent({
                    method: "POST",
                    url: `${TEST_ISSUER_URL}/terms?${TERMS_PARAM.redirectTo}=${encodeURIComponent("/account")}`,
                    headers: { Origin: TEST_ISSUER_URL },
                    form: { redirectTo: "/account", termsKey: [] },
                    locals: { db: mem.db, tenant, user, session, env: mem.env, locale: "ko" },
                }),
            ),
        );

        // 거부도 기록되므로 다시 묻지 않는다.
        expect(await navigate("/account")).toBeNull();
    });

    it("약관이 동의보다 먼저 걸린다", async () => {
        await publishTerms();
        const r = await authorize();
        expect(r.code).toBeNull();
        expect(r.location).toContain("/terms");
    });
});
