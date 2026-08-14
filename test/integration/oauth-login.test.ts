/**
 * 소셜 로그인 풀플로우 통합 테스트 (계획서 §6).
 *
 * 실제 라우트 핸들러(`/auth/oauth/[slug]/{start,callback}`)와 실제 DB 를 쓰고,
 * 외부 프로바이더로 나가는 HTTP 만 스텁한다.
 *
 * 중점: state 위조/재생 방어와 **이메일 기반 자동 연결 금지**. 후자가 뚫리면
 * 임의의 소셜 계정으로 기존 관리자 계정을 탈취할 수 있다.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { and, eq } from "drizzle-orm";

// node:dns 를 스텁해 테스트가 네트워크에 의존하지 않게 한다.
// (validation.ts 의 SSRF 완화가 fetch 직전에 실호스트를 해석한다.)
vi.mock("node:dns/promises", () => ({
    resolve4: async () => ["140.82.114.4"],
    resolve6: async () => [],
}));

import { GET as startHandler } from "../../src/routes/auth/oauth/[slug]/start/+server";
import { GET as callbackHandler } from "../../src/routes/auth/oauth/[slug]/callback/+server";
import { identities, users } from "$lib/server/db/schema";
import { OAUTH_STATE_COOKIE } from "$lib/server/oauth/state";
import { PENDING_LINK_COOKIE, readPendingLink } from "$lib/server/auth/pending-link";
import { SESSION_COOKIE_NAME } from "$lib/server/auth/constants";
import { catchRedirect, makeCookieJar, makeEvent, openMemoryDb, seedIdentityProvider, seedTenantAndSigningKey, seedUser, TEST_SIGNING_SECRET, type MemoryDb } from "./harness";
import type { Tenant, User } from "$lib/server/db/schema";

const SLUG = "github";

let mem: MemoryDb;
let tenant: Tenant;

/** GitHub 토큰 교환 + 프로필 조회를 스텁한다. */
function stubGithub(profile: { id: number; login: string; name?: string | null; emails?: Array<{ email: string; primary: boolean; verified: boolean }> }) {
    return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
        const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });

        if (url.startsWith("https://github.com/login/oauth/access_token")) return json({ access_token: "stub-access-token", token_type: "bearer" });
        if (url.startsWith("https://api.github.com/user/emails")) return json(profile.emails ?? []);
        if (url.startsWith("https://api.github.com/user")) return json({ id: profile.id, login: profile.login, name: profile.name ?? null, email: null, avatar_url: null });
        throw new Error(`스텁되지 않은 URL: ${url}`);
    });
}

async function seedGithubProvider(config: Record<string, unknown> = {}) {
    return seedIdentityProvider(mem.db, {
        tenantId: tenant.id,
        kind: "oauth2",
        name: "GitHub",
        slug: SLUG,
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
        enabled: true,
        config: { providerType: "github", ...config },
    });
}

/** start → 프로바이더 리다이렉트를 수행하고, 브라우저에 남은 state 쿠키와 state 값을 돌려준다. */
async function runStart(jar: ReturnType<typeof makeCookieJar>, urlSuffix = "") {
    const event = makeEvent({
        url: `https://idp.test.example/auth/oauth/${SLUG}/start${urlSuffix}`,
        params: { slug: SLUG },
        cookies: jar.cookies,
        locals: { db: mem.db, tenant, env: mem.env },
    });

    const { location } = await catchRedirect(() => startHandler(event));
    const state = new URL(location).searchParams.get("state")!;
    return { location, state };
}

/** 콜백을 호출한다. `user` 를 주면 "로그인 상태에서의 계정 연결" 경로를 탄다. */
function callbackEvent(jar: ReturnType<typeof makeCookieJar>, query: Record<string, string>, user: User | null = null) {
    const params = new URLSearchParams(query);
    return makeEvent({
        url: `https://idp.test.example/auth/oauth/${SLUG}/callback?${params.toString()}`,
        params: { slug: SLUG },
        cookies: jar.cookies,
        locals: { db: mem.db, tenant, user, env: mem.env },
    });
}

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
});

afterEach(() => {
    vi.restoreAllMocks();
    mem.close();
});

describe("소셜 로그인 시작(start)", () => {
    it("authorize URL 로 리다이렉트하고 state 쿠키를 심는다", async () => {
        await seedGithubProvider();
        const jar = makeCookieJar();

        const { location, state } = await runStart(jar);
        const url = new URL(location);

        expect(url.origin + url.pathname).toBe("https://github.com/login/oauth/authorize");
        expect(url.searchParams.get("client_id")).toBe("test-client-id");
        expect(url.searchParams.get("redirect_uri")).toBe(`https://idp.test.example/auth/oauth/${SLUG}/callback`);
        expect(url.searchParams.get("response_type")).toBe("code");
        expect(state).toBeTruthy();
        expect(jar.has(OAUTH_STATE_COOKIE)).toBe(true);
    });

    it("PKCE 미지원 프로바이더에는 code_challenge 를 보내지 않는다", async () => {
        await seedGithubProvider();
        const jar = makeCookieJar();
        const { location } = await runStart(jar);
        expect(new URL(location).searchParams.has("code_challenge")).toBe(false);
    });

    it("등록되지 않은 slug 는 404", async () => {
        await seedGithubProvider();
        const jar = makeCookieJar();
        const event = makeEvent({
            url: "https://idp.test.example/auth/oauth/unknown/start",
            params: { slug: "unknown" },
            cookies: jar.cookies,
            locals: { db: mem.db, tenant, env: mem.env },
        });
        await expect(startHandler(event)).rejects.toMatchObject({ status: 404 });
    });
});

describe("state 검증", () => {
    it("state 쿠키가 없으면 거부한다", async () => {
        await seedGithubProvider();
        const jar = makeCookieJar();
        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state: "forged" })));
        expect(location).toContain("socialError=state_expired");
    });

    it("쿼리 state 가 쿠키와 다르면 거부한다", async () => {
        await seedGithubProvider();
        const jar = makeCookieJar();
        await runStart(jar);

        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state: "attacker-supplied" })));
        expect(location).toContain("socialError=state_mismatch");
    });

    it("state 쿠키는 1회용이라 같은 code 로 두 번 진입할 수 없다", async () => {
        await seedGithubProvider();
        stubGithub({ id: 1, login: "octocat", emails: [{ email: "octo@example.com", primary: true, verified: true }] });
        const jar = makeCookieJar();
        const { state } = await runStart(jar);

        // 1회차 — 가입 폼으로 진행(계정 없음).
        await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state })));
        expect(jar.has(OAUTH_STATE_COOKIE)).toBe(false);

        // 2회차 — 쿠키가 소비돼 더는 통과하지 못한다.
        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state })));
        expect(location).toContain("socialError=state_expired");
    });

    it("프로바이더가 error 를 돌려주면 거부한다", async () => {
        await seedGithubProvider();
        const jar = makeCookieJar();
        const { state } = await runStart(jar);

        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { error: "access_denied", state })));
        expect(location).toContain("socialError=provider_denied");
    });
});

describe("계정 해석", () => {
    it("매칭 계정이 없으면 계정을 만들지 않고 가입 폼으로 보낸다", async () => {
        await seedGithubProvider();
        stubGithub({ id: 42, login: "newuser", name: "New User", emails: [{ email: "new@example.com", primary: true, verified: true }] });
        const jar = makeCookieJar();
        const { state } = await runStart(jar);

        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state })));

        expect(location).toContain("/signup?federated=1");
        // 아직 아무 계정도 만들어지지 않아야 한다.
        expect(await mem.db.select().from(users)).toHaveLength(0);
        expect(await mem.db.select().from(identities)).toHaveLength(0);

        // 신원은 서명 쿠키로 전달된다.
        const claims = await readPendingLink(jar.cookies, TEST_SIGNING_SECRET);
        expect(claims).toMatchObject({ provider: `oauth:${SLUG}`, subject: "42", email: "new@example.com", emailVerified: true });
    });

    it("이미 연결된 신원이면 바로 로그인된다", async () => {
        await seedGithubProvider();
        const user = await seedUser(mem.db, { tenantId: tenant.id, email: "linked@example.com", username: "linked" });
        await mem.db.insert(identities).values({ tenantId: tenant.id, userId: user.id, provider: `oauth:${SLUG}`, subject: "77", email: "linked@example.com" });

        stubGithub({ id: 77, login: "linked", emails: [{ email: "linked@example.com", primary: true, verified: true }] });
        const jar = makeCookieJar();
        const { state } = await runStart(jar);

        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state })));

        expect(location).toBe("/");
        expect(jar.has(SESSION_COOKIE_NAME)).toBe(true);
    });

    it("이메일이 같아도 기존 계정에 자동 연결하지 않는다 (계정 탈취 방지)", async () => {
        await seedGithubProvider();
        const admin = await seedUser(mem.db, { tenantId: tenant.id, email: "admin@example.com", username: "admin", role: "admin" });

        // 공격자가 admin@example.com 을 검증된 이메일로 주장하는 소셜 계정으로 진입.
        stubGithub({ id: 999, login: "attacker", emails: [{ email: "admin@example.com", primary: true, verified: true }] });
        const jar = makeCookieJar();
        const { state } = await runStart(jar);

        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state })));

        expect(location).toContain("socialError=link_required");
        expect(jar.has(SESSION_COOKIE_NAME)).toBe(false);
        // admin 계정에 identity 가 붙지 않아야 한다.
        const linked = await mem.db.select().from(identities).where(eq(identities.userId, admin.id));
        expect(linked).toHaveLength(0);
    });

    it("autoLinkVerifiedEmail 을 켜면 검증된 이메일에 한해 자동 연결한다", async () => {
        await seedGithubProvider({ autoLinkVerifiedEmail: true });
        const user = await seedUser(mem.db, { tenantId: tenant.id, email: "known@example.com", username: "known" });

        stubGithub({ id: 555, login: "known", emails: [{ email: "known@example.com", primary: true, verified: true }] });
        const jar = makeCookieJar();
        const { state } = await runStart(jar);

        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state })));

        expect(location).toBe("/");
        const linked = await mem.db
            .select()
            .from(identities)
            .where(and(eq(identities.userId, user.id), eq(identities.subject, "555")));
        expect(linked).toHaveLength(1);
    });

    it("autoLinkVerifiedEmail 이 켜져 있어도 미검증 이메일은 자동 연결하지 않는다", async () => {
        await seedGithubProvider({ autoLinkVerifiedEmail: true });
        await seedUser(mem.db, { tenantId: tenant.id, email: "known@example.com", username: "known" });

        // 검증된 이메일이 없어 /user 의 값으로 폴백 → emailVerified=false.
        vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
            const url = typeof input === "string" ? input : (input as Request).url;
            const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200, headers: { "content-type": "application/json" } });
            if (url.startsWith("https://github.com/login/oauth/access_token")) return json({ access_token: "t" });
            if (url.startsWith("https://api.github.com/user/emails")) return json([]);
            return json({ id: 556, login: "known", name: null, email: "known@example.com", avatar_url: null });
        });

        const jar = makeCookieJar();
        const { state } = await runStart(jar);
        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state })));

        expect(location).toContain("socialError=link_required");
    });

    it("provisioningMode=deny 면 신규 가입을 막는다", async () => {
        await seedGithubProvider({ provisioningMode: "deny" });
        stubGithub({ id: 1, login: "x", emails: [{ email: "x@example.com", primary: true, verified: true }] });
        const jar = makeCookieJar();
        const { state } = await runStart(jar);

        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state })));
        expect(location).toContain("socialError=signup_disabled");
        expect(await mem.db.select().from(users)).toHaveLength(0);
    });

    it("provisioningMode=jit 은 폼 없이 계정을 만든다", async () => {
        await seedGithubProvider({ provisioningMode: "jit" });
        stubGithub({ id: 2, login: "jituser", emails: [{ email: "jit@example.com", primary: true, verified: true }] });
        const jar = makeCookieJar();
        const { state } = await runStart(jar);

        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state })));

        expect(location).toBe("/");
        const rows = await mem.db.select().from(users);
        expect(rows).toHaveLength(1);
        expect(rows[0].email).toBe("jit@example.com");
        // 프로바이더가 검증한 이메일이므로 재확인을 요구하지 않는다.
        expect(rows[0].emailVerifiedAt).not.toBeNull();
        expect(jar.has(PENDING_LINK_COOKIE)).toBe(false);
    });

    it("비활성(disabled) 계정은 연결돼 있어도 로그인되지 않는다", async () => {
        await seedGithubProvider();
        const user = await seedUser(mem.db, { tenantId: tenant.id, email: "off@example.com", username: "off", status: "disabled" });
        await mem.db.insert(identities).values({ tenantId: tenant.id, userId: user.id, provider: `oauth:${SLUG}`, subject: "88", email: "off@example.com" });

        stubGithub({ id: 88, login: "off", emails: [{ email: "off@example.com", primary: true, verified: true }] });
        const jar = makeCookieJar();
        const { state } = await runStart(jar);

        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state })));
        expect(location).toContain("socialError=account_disabled");
        expect(jar.has(SESSION_COOKIE_NAME)).toBe(false);
    });

    it("이메일이 달라도 로그인 상태에서는 현재 계정에 연결한다", async () => {
        await seedGithubProvider();
        const user = await seedUser(mem.db, { tenantId: tenant.id, email: "work@company.com", username: "worker" });

        // 개인 GitHub 계정(회사 메일과 다름)을 본인 계정에 붙이는 정당한 시나리오.
        stubGithub({ id: 321, login: "personal", emails: [{ email: "personal@gmail.com", primary: true, verified: true }] });
        const jar = makeCookieJar();
        const { state } = await runStart(jar);

        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state }, user)));

        expect(location).toBe("/account/connections?linked=1");
        const linked = await mem.db.select().from(identities).where(eq(identities.userId, user.id));
        expect(linked).toHaveLength(1);
        expect(linked[0].subject).toBe("321");
    });

    it("다른 계정에 이미 연결된 외부 신원은 재연결하지 않는다", async () => {
        await seedGithubProvider();
        const owner = await seedUser(mem.db, { tenantId: tenant.id, email: "owner@example.com", username: "owner" });
        const other = await seedUser(mem.db, { tenantId: tenant.id, email: "other@example.com", username: "other" });
        await mem.db.insert(identities).values({ tenantId: tenant.id, userId: owner.id, provider: `oauth:${SLUG}`, subject: "654", email: "owner@example.com" });

        stubGithub({ id: 654, login: "owner", emails: [{ email: "owner@example.com", primary: true, verified: true }] });
        const jar = makeCookieJar();
        const { state } = await runStart(jar);

        const { location } = await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state }, other)));

        expect(location).toContain("linkError=already_linked_elsewhere");
        // 소유자의 연결은 그대로, other 에는 아무것도 생기지 않는다.
        expect(await mem.db.select().from(identities).where(eq(identities.userId, other.id))).toHaveLength(0);
        expect(await mem.db.select().from(identities).where(eq(identities.userId, owner.id))).toHaveLength(1);
    });

    it("연결된 신원의 프로바이더 이메일이 바뀌어도 users.email 은 덮어쓰지 않는다", async () => {
        await seedGithubProvider();
        const user = await seedUser(mem.db, { tenantId: tenant.id, email: "original@example.com", username: "orig" });
        await mem.db.insert(identities).values({ tenantId: tenant.id, userId: user.id, provider: `oauth:${SLUG}`, subject: "101", email: "original@example.com" });

        // 프로바이더가 다른 이메일을 주장한다.
        stubGithub({ id: 101, login: "orig", emails: [{ email: "hijack@example.com", primary: true, verified: true }] });
        const jar = makeCookieJar();
        const { state } = await runStart(jar);
        await catchRedirect(() => callbackHandler(callbackEvent(jar, { code: "c", state })));

        const [row] = await mem.db.select().from(users).where(eq(users.id, user.id));
        expect(row.email).toBe("original@example.com");
    });
});
