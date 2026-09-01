import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { GET as authorizeGET } from "../../src/routes/oidc/authorize/+server";
import { POST as tokenPOST } from "../../src/routes/oidc/token/+server";
import { GET as userinfoGET } from "../../src/routes/oidc/userinfo/+server";
import { GET as healthGET } from "../../src/routes/api/health/+server";
import { actions as acceptInviteActions } from "../../src/routes/(auth)/accept-invite/+page.server";
import { actions as confirmEmailChangeActions } from "../../src/routes/account/confirm-email-change/+page.server";
import { assertNotLastAdmin } from "../../src/lib/server/auth/guards";
import { verifyIdToken } from "../../src/lib/server/crypto/keys";
import { generateToken } from "../../src/lib/server/email";
import { credentials, departments, emailChangeTokens, inviteTokens, userDepartments, users } from "../../src/lib/server/db/schema";
import {
    openMemoryDb,
    seedTenantAndSigningKey,
    seedUser,
    seedOidcClient,
    seedConsent,
    seedServiceAssignment,
    seedSession,
    makeEvent,
    pkceChallengeS256,
    catchRedirect,
    TEST_ISSUER_URL,
    type MemoryDb,
} from "./harness";
import type { Tenant } from "../../src/lib/server/db/schema";

let mem: MemoryDb;
let tenant: Tenant;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
});

afterEach(() => mem.close());

// ── B2: organization scope 만 요청 시 id_token 과 userinfo 가 동일한 조직 클레임을 반환 ──
describe("B2 — organization scope 조직 클레임 (id_token ↔ userinfo 동일)", () => {
    const CLIENT_ID = "org-client";
    const CLIENT_SECRET = "org-client-secret-0123456789abcdef";
    const REDIRECT_URI = "https://org-app.test.example/cb";

    it("organization scope 만으로 발급한 id_token 의 조직 클레임이 userinfo 응답과 일치한다", async () => {
        const user = await seedUser(mem.db, { tenantId: tenant.id, email: "org@test.example", username: "org", password: "pw-strong-123", displayName: "Org User" });
        const client = await seedOidcClient(mem.db, {
            tenantId: tenant.id,
            clientId: CLIENT_ID,
            secret: CLIENT_SECRET,
            redirectUris: [REDIRECT_URI],
            scopes: "openid organization",
            grantTypes: "authorization_code",
        });
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "oidc", serviceRefId: client.id });
        await seedConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientRefId: client.id });
        const session = (await seedSession(mem.db, { tenantId: tenant.id, userId: user.id })).session;

        // 주소속 부서 시드.
        const deptId = crypto.randomUUID();
        await mem.db.insert(departments).values({ id: deptId, tenantId: tenant.id, name: "플랫폼실", code: "PLT" });
        await mem.db.insert(userDepartments).values({ id: crypto.randomUUID(), tenantId: tenant.id, userId: user.id, departmentId: deptId, isPrimary: true, jobTitle: "실장" });

        // authorize (PKCE) → code
        const verifier = "org-verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
        const challenge = await pkceChallengeS256(verifier);
        const params = new URLSearchParams({
            client_id: CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            response_type: "code",
            scope: "openid organization",
            code_challenge: challenge,
            code_challenge_method: "S256",
        });
        const authEvent = makeEvent({ method: "GET", url: `${TEST_ISSUER_URL}/oidc/authorize?${params.toString()}`, locals: { db: mem.db, tenant, user, session, env: mem.env } });
        const { location } = await catchRedirect(() => authorizeGET(authEvent));
        const code = new URL(location).searchParams.get("code")!;
        expect(code).toBeTruthy();

        // token → id_token / access_token
        const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
        const tokenRes = (await tokenPOST(
            makeEvent({
                method: "POST",
                url: `${TEST_ISSUER_URL}/oidc/token`,
                headers: { authorization: `Basic ${basic}` },
                form: { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier },
                locals: { db: mem.db, tenant, env: mem.env },
            }),
        )) as Response;
        expect(tokenRes.status).toBe(200);
        const body = (await tokenRes.json()) as Record<string, string>;

        const claims = await verifyIdToken(mem.db, tenant.id, body.id_token, { expectedIssuer: TEST_ISSUER_URL, expectedAud: CLIENT_ID });
        expect(claims).not.toBeNull();

        // userinfo (access token)
        const uinfoRes = (await userinfoGET(
            makeEvent({ method: "GET", url: `${TEST_ISSUER_URL}/oidc/userinfo`, headers: { authorization: `Bearer ${body.access_token}` }, locals: { db: mem.db, tenant, env: mem.env } }),
        )) as Response;
        expect(uinfoRes.status).toBe(200);
        const ui = (await uinfoRes.json()) as Record<string, unknown>;

        // 조직 클레임(department)이 양쪽에 존재하고 동일해야 한다.
        expect(Array.isArray(claims!.department)).toBe(true);
        expect((claims!.department as unknown[]).length).toBe(1);
        expect(claims!.department).toEqual(ui.department);
        expect((claims!.department as Array<Record<string, unknown>>)[0].name).toBe("플랫폼실");
        expect((claims!.department as Array<Record<string, unknown>>)[0].is_primary).toBe(true);
        // job_title 도 동일.
        expect(claims!.job_title).toBe(ui.job_title);
        expect(claims!.job_title).toBe("실장");
    });
});

// ── B3-a: accept-invite 는 disabled/deletion_pending 계정 수락을 거부한다 ──
describe("B3-a — accept-invite 는 비활성 계정 수락을 거부", () => {
    async function makeInvite(userId: string): Promise<string> {
        const { token, tokenHash } = await generateToken();
        await mem.db.insert(inviteTokens).values({ userId, tokenHash, expiresAt: new Date(Date.now() + 60 * 60 * 1000) });
        return token;
    }

    for (const status of ["disabled", "deletion_pending"] as const) {
        it(`status=${status} 계정의 유효 초대 토큰이라도 수락을 400 으로 거부하고 credential 을 만들지 않는다`, async () => {
            const invitee = await seedUser(mem.db, { tenantId: tenant.id, email: `inv-${status}@test.example`, username: `inv-${status}`, emailVerifiedAt: null, status });
            const token = await makeInvite(invitee.id);
            const res = (await acceptInviteActions.default(
                makeEvent({
                    method: "POST",
                    url: `${TEST_ISSUER_URL}/accept-invite`,
                    form: { token, password: "new-strong-password", confirmPassword: "new-strong-password" },
                    locals: { db: mem.db, tenant, env: mem.env },
                }),
            )) as { status?: number };
            expect(res.status).toBe(400);
            const cred = await mem.db.select().from(credentials).where(eq(credentials.userId, invitee.id));
            expect(cred.length).toBe(0);
        });
    }
});

// ── B3-b: assertNotLastAdmin 은 미수락 초대 admin 을 "로그인 가능 admin" 으로 세지 않는다 ──
describe("B3-b — assertNotLastAdmin 은 미수락 초대 admin 을 다른 관리자로 오인하지 않는다", () => {
    it("사용 가능한 admin 이 하나뿐이고 나머지가 credential 없는 초대 admin 이면, 그 admin 변경을 차단한다", async () => {
        // 로그인 가능한(비밀번호 있는) admin.
        const usableAdmin = await seedUser(mem.db, { tenantId: tenant.id, email: "a1@test.example", username: "a1", password: "pw-strong-1", role: "admin", status: "active" });
        // 미수락 초대 admin — active 이지만 credential/identity 없음(로그인 불가).
        await seedUser(mem.db, { tenantId: tenant.id, email: "a2@test.example", username: "a2", role: "admin", status: "active" });

        const blocked = await assertNotLastAdmin(mem.db, tenant.id, usableAdmin.id);
        // 다른 "사용 가능" admin 이 없으므로 last-admin 보호가 차단(fail)을 반환해야 한다.
        expect(blocked).not.toBeNull();
        expect((blocked as { status?: number }).status).toBe(400);
    });

    it("사용 가능한 admin 이 둘 이상이면 변경을 허용(null)한다", async () => {
        const a1 = await seedUser(mem.db, { tenantId: tenant.id, email: "b1@test.example", username: "b1", password: "pw-strong-1", role: "admin", status: "active" });
        await seedUser(mem.db, { tenantId: tenant.id, email: "b2@test.example", username: "b2", password: "pw-strong-2", role: "admin", status: "active" });
        const ok = await assertNotLastAdmin(mem.db, tenant.id, a1.id);
        expect(ok).toBeNull();
    });
});

// ── B4: health 는 DB 쿼리 실패 시 503 을 반환한다 ──
describe("B4 — health readiness", () => {
    it("정상 DB 에서는 200 { db: ready } 를 반환한다", async () => {
        const res = (await healthGET({ locals: { db: mem.db } } as unknown as Parameters<typeof healthGET>[0])) as Response;
        expect(res.status).toBe(200);
        expect(((await res.json()) as { db: string }).db).toBe("ready");
    });

    it("DB 바인딩이 없으면 503 unavailable 을 반환한다", async () => {
        const res = (await healthGET({ locals: { db: null } } as unknown as Parameters<typeof healthGET>[0])) as Response;
        expect(res.status).toBe(503);
    });

    it("DB 쿼리가 실패(연결 끊김)하면 503 을 반환한다", async () => {
        mem.close(); // libSQL 클라이언트를 닫아 이후 쿼리가 실패하도록 만든다.
        const res = (await healthGET({ locals: { db: mem.db } } as unknown as Parameters<typeof healthGET>[0])) as Response;
        expect(res.status).toBe(503);
        expect(((await res.json()) as { db: string }).db).toBe("unavailable");
    });
});

// ── F3: 이메일 변경 confirm → users.email 교체 ──
describe("F3 — 이메일 변경 확인", () => {
    async function makeChangeToken(userId: string, targetEmail: string): Promise<string> {
        const { token, tokenHash } = await generateToken();
        await mem.db.insert(emailChangeTokens).values({ userId, tokenHash, targetEmail, expiresAt: new Date(Date.now() + 60 * 60 * 1000) });
        return token;
    }

    it("유효한 변경 토큰 확인이 users.email 을 targetEmail 로 교체하고 토큰을 소진한다", async () => {
        const user = await seedUser(mem.db, { tenantId: tenant.id, email: "old@test.example", username: "changer", emailVerifiedAt: null });
        const token = await makeChangeToken(user.id, "new@test.example");

        const res = await confirmEmailChangeActions.default(
            makeEvent({ method: "POST", url: `${TEST_ISSUER_URL}/account/confirm-email-change`, form: { token }, locals: { db: mem.db, tenant, user, env: mem.env } }),
        );
        expect(res).toEqual({ changed: true });

        const [u] = await mem.db.select().from(users).where(eq(users.id, user.id)).limit(1);
        expect(u.email).toBe("new@test.example");
        expect(u.emailVerifiedAt).not.toBeNull();
        const [tok] = await mem.db.select().from(emailChangeTokens).where(eq(emailChangeTokens.userId, user.id)).limit(1);
        expect(tok.usedAt).not.toBeNull();
    });

    it("targetEmail 이 이미 다른 계정에 점유된 경우 409 로 거부하고 이메일을 바꾸지 않는다", async () => {
        await seedUser(mem.db, { tenantId: tenant.id, email: "taken@test.example", username: "owner" });
        const user = await seedUser(mem.db, { tenantId: tenant.id, email: "mine@test.example", username: "mine" });
        const token = await makeChangeToken(user.id, "taken@test.example");

        const res = (await confirmEmailChangeActions.default(
            makeEvent({ method: "POST", url: `${TEST_ISSUER_URL}/account/confirm-email-change`, form: { token }, locals: { db: mem.db, tenant, user, env: mem.env } }),
        )) as { status?: number };
        expect(res.status).toBe(409);
        const [u] = await mem.db.select().from(users).where(eq(users.id, user.id)).limit(1);
        expect(u.email).toBe("mine@test.example");
    });
});
