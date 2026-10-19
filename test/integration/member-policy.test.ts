import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { eq } from "drizzle-orm";
import { actions as loginActions } from "../../src/routes/(auth)/login/+page.server";
import { actions as adminUserActions } from "../../src/routes/admin/users/+page.server";
import { getSessionContext } from "../../src/lib/server/auth/session";
import { retireAndDeleteUser, LODESTAR_SUBJECT_PROVIDER } from "../../src/lib/server/auth/account-deletion";
import { SESSION_IDLE_TIMEOUT_MS } from "../../src/lib/server/auth/constants";
import { auditEvents, credentials, identities, retiredSubjects, sessions, users } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, seedMfaSession, seedSession, makeEvent, makeCookieJar, catchRedirect, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Tenant, User } from "../../src/lib/server/db/schema";

// 회원 공통 정책 2단계(2026-10-18) 중 DB·라우트가 얽힌 항목을 실제 라우트로 고정한다.
//   - 로그인 계정+IP 지수 지연
//   - 세션 유휴 30분
//   - 즉시 삭제 + 식별자 기록(retired_subjects)

vi.mock("../../src/lib/server/security-notify", () => ({ dispatchSecurityAlert: vi.fn() }));

const PASSWORD = "Policy-user-pass1";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, { tenantId: tenant.id, email: "policy@test.example", username: "policyuser", password: PASSWORD });
});

afterEach(() => {
    vi.useRealTimers();
    mem.close();
});

function loginEvent(form: Record<string, string>, ip = "198.51.100.7") {
    const event = makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/login`,
        form,
        locals: { db: mem.db, tenant, env: mem.env },
        cookies: makeCookieJar().cookies,
    });
    (event as unknown as { getClientAddress: () => string }).getClientAddress = () => ip;
    return event;
}

async function attempt(password: string, ip?: string): Promise<number> {
    try {
        const r = (await loginActions.default(loginEvent({ username: "policyuser", password }, ip))) as { status?: number };
        return r.status ?? 200;
    } catch (e) {
        return (e as { status: number }).status;
    }
}

describe("로그인 계정+IP 지수 지연", () => {
    it("5회 실패 뒤 바로 다음 시도는 올바른 비밀번호라도 429 다", async () => {
        for (let i = 0; i < 5; i++) expect(await attempt("wrong-Pass1")).toBe(400);
        expect(await attempt(PASSWORD)).toBe(429);
    });

    it("다른 IP 에서는 막히지 않는다 (원격 DoS 방지)", async () => {
        for (let i = 0; i < 5; i++) expect(await attempt("wrong-Pass1")).toBe(400);
        expect(await attempt(PASSWORD, "203.0.113.9")).toBe(303);
    });

    it("지연이 끝나면 다시 시도할 수 있고, 성공하면 기록이 지워진다", async () => {
        vi.useFakeTimers({ toFake: ["Date"] });
        const t0 = Date.now();
        for (let i = 0; i < 5; i++) expect(await attempt("wrong-Pass1")).toBe(400);
        vi.setSystemTime(t0 + 1001);
        expect(await attempt(PASSWORD)).toBe(303);
        // 기록이 지워졌으므로 곧바로 3번 더 틀려도 막히지 않는다(지워지지 않았다면 두 번째 실패부터 지연에 걸린다).
        // 시도는 모두 10회 — IP 한도(15분 10회)에는 닿지 않게 둔다.
        for (let i = 0; i < 3; i++) expect(await attempt("wrong-Pass1")).toBe(400);
        expect(await attempt(PASSWORD)).toBe(303);
    });
});

describe("세션 유휴 만료 30분", () => {
    it("마지막 활동이 30분을 넘으면 세션으로 인정하지 않는다", async () => {
        const { session, sessionToken } = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id });
        expect(await getSessionContext(mem.db, sessionToken, tenant.id)).not.toBeNull();

        await mem.db
            .update(sessions)
            .set({ lastSeenAt: new Date(Date.now() - SESSION_IDLE_TIMEOUT_MS - 1000) })
            .where(eq(sessions.id, session.id));
        expect(await getSessionContext(mem.db, sessionToken, tenant.id)).toBeNull();
    });

    it("30분 안에 활동했으면 그대로 유효하다", async () => {
        const { session, sessionToken } = await seedSession(mem.db, { tenantId: tenant.id, userId: user.id });
        await mem.db
            .update(sessions)
            .set({ lastSeenAt: new Date(Date.now() - SESSION_IDLE_TIMEOUT_MS + 60_000) })
            .where(eq(sessions.id, session.id));
        expect(await getSessionContext(mem.db, sessionToken, tenant.id)).not.toBeNull();
    });
});

describe("즉시 삭제와 식별자 기록", () => {
    async function retired(): Promise<{ provider: string; subject: string; issuer: string | null }[]> {
        return mem.db.select({ provider: retiredSubjects.provider, subject: retiredSubjects.subject, issuer: retiredSubjects.issuer }).from(retiredSubjects);
    }

    it("관리자 삭제는 사용자 행·자격 증명을 지우고 Lodestar sub 와 외부 신원을 기록한다", async () => {
        const admin = await seedUser(mem.db, { tenantId: tenant.id, email: "admin@test.example", role: "admin" });
        const adminSession = (await seedMfaSession(mem.db, { tenantId: tenant.id, userId: admin.id })).session;
        await mem.db.insert(identities).values({ tenantId: tenant.id, userId: user.id, provider: "oauth:github", subject: "4242", email: "policy@test.example" });
        await mem.db.insert(identities).values({ tenantId: tenant.id, userId: user.id, provider: "local", subject: "policy@test.example", email: "policy@test.example" });
        await mem.db.insert(identities).values({ tenantId: tenant.id, userId: user.id, provider: "ldap:corp", subject: "cn=홍길동,ou=people,dc=corp", email: null });

        await adminUserActions.delete!(
            makeEvent({
                method: "POST",
                url: `${TEST_ISSUER_URL}/admin/users?/delete`,
                form: { id: user.id },
                locals: { db: mem.db, tenant, user: admin, session: adminSession, env: mem.env },
            }) as never,
        );

        expect(await mem.db.select().from(users).where(eq(users.id, user.id))).toHaveLength(0);
        expect(await mem.db.select().from(credentials).where(eq(credentials.userId, user.id))).toHaveLength(0);
        // Lodestar sub 만 남긴다. 외부 신원(subject 가 이메일·DN 일 수 있음)은 기록하지 않는다.
        const rows = await retired();
        expect(rows).toEqual([{ provider: LODESTAR_SUBJECT_PROVIDER, subject: user.id, issuer: TEST_ISSUER_URL }]);
        expect(await mem.db.select().from(identities).where(eq(identities.userId, user.id))).toHaveLength(0);
    });

    it("본인 탈퇴도 즉시 지우고 기록한다", async () => {
        const { actions } = await import("../../src/routes/account/danger-zone/+page.server");
        const current = (await seedSession(mem.db, { tenantId: tenant.id, userId: user.id })).session;
        const { status, location } = await catchRedirect(() =>
            actions.requestDeletion!(
                makeEvent({
                    method: "POST",
                    url: `${TEST_ISSUER_URL}/account/danger-zone?/requestDeletion`,
                    form: { password: PASSWORD },
                    locals: { db: mem.db, tenant, user, session: current, env: mem.env },
                }) as never,
            ),
        );
        expect(status).toBe(303);
        expect(location).toBe("/login?deletionRequested=1");
        expect(await mem.db.select().from(users).where(eq(users.id, user.id))).toHaveLength(0);
        expect(await retired()).toEqual([{ provider: LODESTAR_SUBJECT_PROVIDER, subject: user.id, issuer: TEST_ISSUER_URL }]);
    });

    it("같은 사용자를 두 번 기록하지 않는다", async () => {
        await mem.db.insert(retiredSubjects).values({ tenantId: tenant.id, provider: LODESTAR_SUBJECT_PROVIDER, subject: user.id });
        await retireAndDeleteUser(mem.db, tenant.id, user.id);
        expect(await retired()).toHaveLength(1);
        expect(await mem.db.select().from(users).where(eq(users.id, user.id))).toHaveLength(0);
    });

    it("본인 탈퇴의 감사는 삭제 뒤에 성공으로 남는다(사용자 연결 없이 actorId·detail 로)", async () => {
        const { actions } = await import("../../src/routes/account/danger-zone/+page.server");
        const current = (await seedSession(mem.db, { tenantId: tenant.id, userId: user.id })).session;
        await catchRedirect(() =>
            actions.requestDeletion!(
                makeEvent({
                    method: "POST",
                    url: `${TEST_ISSUER_URL}/account/danger-zone?/requestDeletion`,
                    form: { password: PASSWORD },
                    locals: { db: mem.db, tenant, user, session: current, env: mem.env },
                }) as never,
            ),
        );
        const rows = await mem.db.select().from(auditEvents).where(eq(auditEvents.kind, "user_deleted"));
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({ outcome: "success", userId: null, actorId: user.id });
        expect(JSON.parse(rows[0].detailJson!)).toMatchObject({ userId: user.id, by: "self" });
    });
});
