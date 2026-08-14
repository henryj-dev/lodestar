/**
 * 연합 회원가입 폼의 신뢰 경계 검증 (계획서 §2.8 / §6).
 *
 * 이 파일의 핵심 주장 하나: **폼은 신원을 결정하지 못한다.**
 * provider / subject / 검증된 이메일은 서명 쿠키(PENDING_LINK_COOKIE)에서만 오고,
 * 사용자가 hidden 필드를 위조해도 결과가 달라지지 않아야 한다.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { eq } from "drizzle-orm";

import { actions, load } from "../../src/routes/(auth)/signup/+page.server";
import { identities, users, credentials, type Tenant } from "$lib/server/db/schema";
import { PENDING_LINK_COOKIE, setPendingLinkCookie, type PendingLinkClaims } from "$lib/server/auth/pending-link";
import { SESSION_COOKIE_NAME } from "$lib/server/auth/constants";
import { catchRedirect, makeCookieJar, makeEvent, openMemoryDb, seedTenantAndSigningKey, seedUser, TEST_SIGNING_SECRET, type MemoryDb } from "./harness";

let mem: MemoryDb;
let tenant: Tenant;

const PROVIDER = "oauth:github";
const SUBJECT = "gh-42";

function baseClaims(overrides: Partial<PendingLinkClaims> = {}): PendingLinkClaims {
    return {
        tenantId: tenant.id,
        provider: PROVIDER,
        subject: SUBJECT,
        providerLabel: "GitHub",
        email: "octocat@example.com",
        emailVerified: true,
        displayName: "The Octocat",
        suggestedUsername: "octocat",
        allowPassword: true,
        allowUsernameEdit: true,
        redirectTo: null,
        skinHint: null,
        ...overrides,
    };
}

/** pending link 쿠키를 심은 브라우저를 만든다. */
async function jarWithPendingLink(claims: PendingLinkClaims) {
    const jar = makeCookieJar();
    await setPendingLinkCookie(jar.cookies, new URL("https://idp.test.example/"), claims, TEST_SIGNING_SECRET);
    return jar;
}

/** 연합 가입 폼을 제출한다. */
function submit(jar: ReturnType<typeof makeCookieJar>, form: Record<string, string>) {
    return makeEvent({
        method: "POST",
        url: "https://idp.test.example/signup?federated=1",
        form: { federated: "1", ...form },
        cookies: jar.cookies,
        locals: { db: mem.db, tenant, env: mem.env },
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

describe("연합 가입 — 폼 변조 방어", () => {
    it("폼의 provider/subject 위조값을 무시하고 토큰 값을 쓴다", async () => {
        const jar = await jarWithPendingLink(baseClaims());

        await catchRedirect(() =>
            actions.default(
                submit(jar, {
                    username: "octocat",
                    email: "octocat@example.com",
                    // 공격자가 임의로 끼워 넣은 값들.
                    provider: "oauth:evil",
                    subject: "attacker-controlled",
                    tenantId: "some-other-tenant",
                }),
            ),
        );

        const [identity] = await mem.db.select().from(identities);
        expect(identity.provider).toBe(PROVIDER);
        expect(identity.subject).toBe(SUBJECT);
        expect(identity.tenantId).toBe(tenant.id);
    });

    it("프로바이더가 검증한 이메일은 폼 값으로 바꿀 수 없다", async () => {
        const jar = await jarWithPendingLink(baseClaims({ email: "verified@example.com", emailVerified: true }));

        await catchRedirect(() =>
            actions.default(
                submit(jar, {
                    username: "octocat",
                    // 공격자가 남의 이메일을 주장한다.
                    email: "admin@example.com",
                }),
            ),
        );

        const [row] = await mem.db.select().from(users);
        expect(row.email).toBe("verified@example.com");
        // 프로바이더가 검증했으므로 재확인 없이 인증 완료 상태다.
        expect(row.emailVerifiedAt).not.toBeNull();
    });

    it("미검증 이메일은 사용자 입력을 받되 인증 대기 상태로 만든다", async () => {
        const jar = await jarWithPendingLink(baseClaims({ email: null, emailVerified: false }));

        await catchRedirect(() => actions.default(submit(jar, { username: "octocat", email: "Chosen@Example.com" })));

        const [row] = await mem.db.select().from(users);
        expect(row.email).toBe("chosen@example.com");
        expect(row.emailVerifiedAt).toBeNull();
    });
});

describe("연합 가입 — 토큰 검증", () => {
    it("쿠키가 없으면 로그인으로 되돌린다", async () => {
        const jar = makeCookieJar();
        const { location } = await catchRedirect(() => actions.default(submit(jar, { username: "x", email: "x@example.com" })));
        expect(location).toContain("socialError=link_expired");
        expect(await mem.db.select().from(users)).toHaveLength(0);
    });

    it("서명이 위조된 쿠키는 거부한다", async () => {
        const jar = makeCookieJar();
        jar.cookies.set(PENDING_LINK_COOKIE, "eyJmb3JnZWQiOnRydWV9.bm90LWEtcmVhbC1zaWduYXR1cmU");

        const { location } = await catchRedirect(() => actions.default(submit(jar, { username: "x", email: "x@example.com" })));
        expect(location).toContain("socialError=link_expired");
        expect(await mem.db.select().from(users)).toHaveLength(0);
    });

    it("다른 테넌트에서 발급된 토큰은 거부한다", async () => {
        const jar = await jarWithPendingLink(baseClaims({ tenantId: "different-tenant-id" }));

        const { location } = await catchRedirect(() => actions.default(submit(jar, { username: "x", email: "x@example.com" })));
        expect(location).toContain("socialError=link_expired");
        expect(await mem.db.select().from(users)).toHaveLength(0);
    });

    it("load 는 쿠키가 없으면 로그인으로 보낸다", async () => {
        const jar = makeCookieJar();
        const event = makeEvent({
            url: "https://idp.test.example/signup?federated=1",
            cookies: jar.cookies,
            locals: { db: mem.db, tenant, env: mem.env },
        });

        const { location } = await catchRedirect(() => load(event as never));
        expect(location).toContain("socialError=link_expired");
    });

    it("load 는 검증된 이메일을 잠금 상태로 내려준다", async () => {
        const jar = await jarWithPendingLink(baseClaims({ email: "v@example.com", emailVerified: true }));
        const event = makeEvent({
            url: "https://idp.test.example/signup?federated=1",
            cookies: jar.cookies,
            locals: { db: mem.db, tenant, env: mem.env },
        });

        const data = (await load(event as never)) as { federated: { emailLocked: boolean; email: string | null }; skinHtml: string | null };
        expect(data.federated.emailLocked).toBe(true);
        expect(data.federated.email).toBe("v@example.com");
        // 커스텀 스킨은 연합 필드를 모르므로 기본 스킨으로 폴백한다.
        expect(data.skinHtml).toBeNull();
    });
});

describe("연합 가입 — 계정 정책", () => {
    it("이메일이 기존 계정과 충돌하면 병합하지 않고 거부한다", async () => {
        const existing = await seedUser(mem.db, { tenantId: tenant.id, email: "taken@example.com", username: "taken" });
        const jar = await jarWithPendingLink(baseClaims({ email: "taken@example.com", emailVerified: true }));

        const result = (await actions.default(submit(jar, { username: "newname", email: "taken@example.com" }))) as { status: number };

        expect(result.status).toBe(409);
        // 기존 계정에 identity 가 붙지 않아야 한다.
        expect(await mem.db.select().from(identities).where(eq(identities.userId, existing.id))).toHaveLength(0);
        expect(await mem.db.select().from(users)).toHaveLength(1);
    });

    it("username 이 이미 쓰이면 거부한다", async () => {
        await seedUser(mem.db, { tenantId: tenant.id, email: "other@example.com", username: "octocat" });
        const jar = await jarWithPendingLink(baseClaims());

        const result = (await actions.default(submit(jar, { username: "octocat", email: "octocat@example.com" }))) as { status: number };
        expect(result.status).toBe(409);
    });

    it("비밀번호 없이 가입하면 credential 없이 identity 만 생긴다", async () => {
        const jar = await jarWithPendingLink(baseClaims());

        await catchRedirect(() => actions.default(submit(jar, { username: "octocat", email: "octocat@example.com" })));

        const [user] = await mem.db.select().from(users);
        expect(await mem.db.select().from(credentials).where(eq(credentials.userId, user.id))).toHaveLength(0);
        expect(await mem.db.select().from(identities).where(eq(identities.userId, user.id))).toHaveLength(1);
    });

    it("비밀번호를 설정하면 credential 도 함께 생긴다", async () => {
        const jar = await jarWithPendingLink(baseClaims());

        await catchRedirect(() => actions.default(submit(jar, { username: "octocat", email: "octocat@example.com", password: "correct-horse-battery", confirmPassword: "correct-horse-battery" })));

        const [user] = await mem.db.select().from(users);
        const creds = await mem.db.select().from(credentials).where(eq(credentials.userId, user.id));
        expect(creds).toHaveLength(1);
        expect(creds[0].type).toBe("password");
    });

    it("비밀번호 확인이 일치하지 않으면 거부한다", async () => {
        const jar = await jarWithPendingLink(baseClaims());
        const result = (await actions.default(submit(jar, { username: "octocat", email: "octocat@example.com", password: "correct-horse-battery", confirmPassword: "wrong-value-here" }))) as {
            status: number;
        };
        expect(result.status).toBe(400);
    });

    it("가입 성공 시 세션을 발급하고 pending 쿠키를 지운다", async () => {
        const jar = await jarWithPendingLink(baseClaims());

        const { location } = await catchRedirect(() => actions.default(submit(jar, { username: "octocat", email: "octocat@example.com" })));

        expect(location).toBe("/");
        expect(jar.has(SESSION_COOKIE_NAME)).toBe(true);
        expect(jar.has(PENDING_LINK_COOKIE)).toBe(false);
    });

    it("같은 토큰으로 두 번 제출해도 중복 계정이 생기지 않는다", async () => {
        const jar = await jarWithPendingLink(baseClaims());

        await catchRedirect(() => actions.default(submit(jar, { username: "octocat", email: "octocat@example.com" })));

        // 1회차에서 쿠키가 소비됐으므로 2회차는 처음부터 다시 하도록 되돌려진다.
        const { location } = await catchRedirect(() => actions.default(submit(jar, { username: "octocat2", email: "octocat2@example.com" })));
        expect(location).toContain("socialError=link_expired");
        expect(await mem.db.select().from(users)).toHaveLength(1);
    });

    it("username 편집이 막힌 프로바이더는 폼 값 대신 토큰 값을 쓴다", async () => {
        const jar = await jarWithPendingLink(baseClaims({ allowUsernameEdit: false, suggestedUsername: "fixed_name" }));

        await catchRedirect(() => actions.default(submit(jar, { username: "attacker_choice", email: "octocat@example.com" })));

        const [row] = await mem.db.select().from(users);
        expect(row.username).toBe("fixed_name");
    });

    it("비밀번호가 허용되지 않는 프로바이더는 폼에 값이 와도 credential 을 만들지 않는다", async () => {
        const jar = await jarWithPendingLink(baseClaims({ allowPassword: false }));

        await catchRedirect(() => actions.default(submit(jar, { username: "octocat", email: "octocat@example.com", password: "sneaky-password-1", confirmPassword: "sneaky-password-1" })));

        const [user] = await mem.db.select().from(users);
        expect(await mem.db.select().from(credentials).where(eq(credentials.userId, user.id))).toHaveLength(0);
    });
});
