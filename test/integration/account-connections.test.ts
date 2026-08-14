/**
 * `/account/connections` 셀프서비스 연결 해제 검증 (계획서 P7).
 *
 * 핵심: **마지막 로그인 수단은 해제할 수 없다.** 이걸 막지 않으면 소셜 전용 계정이
 * 스스로를 잠가버리고 관리자 개입 없이는 복구할 수 없다.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { eq } from "drizzle-orm";

import { actions, load } from "../../src/routes/account/connections/+page.server";
import { credentials, identities, type Tenant, type User } from "$lib/server/db/schema";
import { hashPassword } from "$lib/server/auth/password";
import { makeCookieJar, makeEvent, openMemoryDb, seedIdentityProvider, seedTenantAndSigningKey, seedUser, type MemoryDb } from "./harness";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;

const PROVIDER = "oauth:github";

function unlinkEvent(jar: ReturnType<typeof makeCookieJar>, id: string) {
    return makeEvent({
        method: "POST",
        url: "https://idp.test.example/account/connections",
        form: { id },
        cookies: jar.cookies,
        locals: { db: mem.db, tenant, user, env: mem.env },
    });
}

async function seedIdentity(provider: string, subject: string): Promise<string> {
    const id = crypto.randomUUID();
    await mem.db.insert(identities).values({ id, tenantId: tenant.id, userId: user.id, provider, subject, email: user.email });
    return id;
}

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, { tenantId: tenant.id, email: "u@example.com", username: "u" });
});

afterEach(() => {
    vi.restoreAllMocks();
    mem.close();
});

describe("연결 해제", () => {
    it("다른 로그인 수단이 있으면 해제된다", async () => {
        const identityId = await seedIdentity(PROVIDER, "gh-1");
        await mem.db.insert(credentials).values({ userId: user.id, type: "password", secret: await hashPassword("some-password-1") });

        const jar = makeCookieJar();
        const result = (await actions.unlink(unlinkEvent(jar, identityId))) as { unlinked?: boolean };

        expect(result.unlinked).toBe(true);
        expect(await mem.db.select().from(identities).where(eq(identities.id, identityId))).toHaveLength(0);
    });

    it("마지막 로그인 수단이면 해제를 거부한다", async () => {
        // 비밀번호 없이 소셜 연결 하나만 가진 계정.
        const identityId = await seedIdentity(PROVIDER, "gh-2");

        const jar = makeCookieJar();
        const result = (await actions.unlink(unlinkEvent(jar, identityId))) as { status: number };

        expect(result.status).toBe(400);
        // 연결이 살아 있어야 계정에 다시 들어올 수 있다.
        expect(await mem.db.select().from(identities).where(eq(identities.id, identityId))).toHaveLength(1);
    });

    it("소셜 연결이 둘이면 하나는 해제할 수 있다", async () => {
        const first = await seedIdentity(PROVIDER, "gh-3");
        await seedIdentity("oauth:naver", "nv-3");

        const jar = makeCookieJar();
        const result = (await actions.unlink(unlinkEvent(jar, first))) as { unlinked?: boolean };
        expect(result.unlinked).toBe(true);
    });

    it("LDAP 등 소셜이 아닌 연합은 셀프 해제할 수 없다", async () => {
        const identityId = await seedIdentity("ldap:some-provider-id", "cn=u,dc=x");
        await mem.db.insert(credentials).values({ userId: user.id, type: "password", secret: await hashPassword("some-password-1") });

        const jar = makeCookieJar();
        const result = (await actions.unlink(unlinkEvent(jar, identityId))) as { status: number };
        expect(result.status).toBe(400);
    });

    it("남의 연결은 해제할 수 없다", async () => {
        const other = await seedUser(mem.db, { tenantId: tenant.id, email: "other@example.com", username: "other" });
        const foreignId = crypto.randomUUID();
        await mem.db.insert(identities).values({ id: foreignId, tenantId: tenant.id, userId: other.id, provider: PROVIDER, subject: "gh-9" });

        const jar = makeCookieJar();
        const result = (await actions.unlink(unlinkEvent(jar, foreignId))) as { status: number };

        expect(result.status).toBe(404);
        expect(await mem.db.select().from(identities).where(eq(identities.id, foreignId))).toHaveLength(1);
    });

    it("CSRF 토큰이 없으면 거부한다", async () => {
        const identityId = await seedIdentity(PROVIDER, "gh-4");
        const event = makeEvent({
            method: "POST",
            url: "https://idp.test.example/account/connections",
            form: { id: identityId },
            csrf: false,
            locals: { db: mem.db, tenant, user, env: mem.env },
        });

        const result = (await actions.unlink(event)) as { status: number };
        expect(result.status).toBe(403);
    });
});

describe("연결 목록", () => {
    it("연결됨/연결 가능 목록을 나눠서 돌려준다", async () => {
        await seedIdentityProvider(mem.db, {
            tenantId: tenant.id,
            kind: "oauth2",
            name: "GitHub",
            slug: "github",
            clientId: "cid",
            clientSecret: "csecret",
            enabled: true,
            config: { providerType: "github" },
        });
        await seedIdentityProvider(mem.db, {
            tenantId: tenant.id,
            kind: "oauth2",
            name: "네이버",
            slug: "naver",
            clientId: "cid2",
            clientSecret: "csecret2",
            enabled: true,
            config: { providerType: "naver" },
        });
        await seedIdentity(PROVIDER, "gh-5");

        const jar = makeCookieJar();
        const event = makeEvent({
            url: "https://idp.test.example/account/connections",
            cookies: jar.cookies,
            locals: { db: mem.db, tenant, user, env: mem.env },
        });

        const data = (await load(event as never)) as {
            connections: Array<{ slug: string | null; unlinkable: boolean }>;
            availableProviders: Array<{ slug: string }>;
        };

        expect(data.connections.map((c) => c.slug)).toEqual(["github"]);
        expect(data.connections[0].unlinkable).toBe(true);
        // 이미 연결된 github 는 빠지고 naver 만 남는다.
        expect(data.availableProviders.map((p) => p.slug)).toEqual(["naver"]);
    });

    it("local identity 는 연결 목록에 나오지 않는다", async () => {
        await seedIdentity("local", user.email);

        const jar = makeCookieJar();
        const event = makeEvent({
            url: "https://idp.test.example/account/connections",
            cookies: jar.cookies,
            locals: { db: mem.db, tenant, user, env: mem.env },
        });

        const data = (await load(event as never)) as { connections: unknown[] };
        expect(data.connections).toHaveLength(0);
    });
});
