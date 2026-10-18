import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { eq } from "drizzle-orm";
import { actions as adminUserActions } from "../../src/routes/admin/users/+page.server";
import { updateProfile } from "../../src/lib/server/admin/user-actions/profile";
import { hashToken } from "../../src/lib/server/email";
import { b64uDecode } from "../../src/lib/server/crypto/keys";
import { auditEvents, oidcClients, oidcRefreshTokens, passwordResetTokens, sessions } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, seedMfaSession, seedOidcClient, seedServiceAssignment, seedSession, makeEvent, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Tenant, User, Session } from "../../src/lib/server/db/schema";

// 세션을 철회하는 경로가 모두 RP 에도 back-channel logout 을 보내는지.
//
// 예전에는 관리자 "강제 로그아웃" 만 RP 에 통지했다. 비활성/잠금, 역할 변경, 비밀번호 리셋,
// 본인의 "모든 기기에서 로그아웃" 은 IdP 세션만 끊어서, 자체 세션으로 인가를 들고 가는 RP 는
// 정지된 계정을 RP 세션 수명 동안 살려 두었다.

vi.mock("../../src/lib/server/security-notify", () => ({ dispatchSecurityAlert: vi.fn() }));

const BC_URI = "https://rp.test.example/backchannel-logout";

let mem: MemoryDb;
let tenant: Tenant;
let admin: User;
let adminSession: Session;
let target: User;
let captured: { url: string; body: string }[];
let originalFetch: typeof globalThis.fetch;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    admin = await seedUser(mem.db, { tenantId: tenant.id, email: "admin@test.example", role: "admin" });
    adminSession = (await seedMfaSession(mem.db, { tenantId: tenant.id, userId: admin.id })).session;
    target = await seedUser(mem.db, { tenantId: tenant.id, email: "member@test.example", username: "member", password: "old-password-123" });

    const client = await seedOidcClient(mem.db, {
        tenantId: tenant.id,
        clientId: "bc-client",
        secret: "revoke-paths-secret-0123456789abcdef",
        redirectUris: ["https://rp.test.example/callback"],
    });
    await mem.db.update(oidcClients).set({ backchannelLogoutUri: BC_URI }).where(eq(oidcClients.id, client.id));
    await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: target.id, serviceType: "oidc", serviceRefId: client.id });

    captured = [];
    originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        captured.push({ url: String(input), body: String(init?.body ?? "") });
        return new Response(null, { status: 200 });
    }) as typeof globalThis.fetch;
});

afterEach(() => {
    globalThis.fetch = originalFetch;
    mem.close();
});

function logoutSubjects(): unknown[] {
    return captured
        .filter((c) => c.url === BC_URI)
        .map((c) => {
            const token = new URLSearchParams(c.body).get("logout_token") ?? "";
            return (JSON.parse(new TextDecoder().decode(b64uDecode(token.split(".")[1]))) as { sub: unknown }).sub;
        });
}

async function seedRefreshToken(): Promise<string> {
    const id = crypto.randomUUID();
    await mem.db.insert(oidcRefreshTokens).values({
        id,
        tenantId: tenant.id,
        clientId: "bc-client",
        userId: target.id,
        tokenHash: `rt-${id}`,
        scope: "openid offline_access",
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    });
    return id;
}

async function isRefreshRevoked(id: string): Promise<boolean> {
    const [row] = await mem.db.select({ revokedAt: oidcRefreshTokens.revokedAt }).from(oidcRefreshTokens).where(eq(oidcRefreshTokens.id, id));
    return row.revokedAt !== null;
}

async function liveSessionCount(userId: string): Promise<number> {
    const rows = await mem.db.select({ revokedAt: sessions.revokedAt }).from(sessions).where(eq(sessions.userId, userId));
    return rows.filter((r) => r.revokedAt === null).length;
}

async function bcAuditReasons(): Promise<unknown[]> {
    const rows = await mem.db.select({ detailJson: auditEvents.detailJson }).from(auditEvents).where(eq(auditEvents.kind, "backchannel_logout_sent"));
    return rows.map((r) => (JSON.parse(r.detailJson!) as { reason: unknown }).reason);
}

function adminListEvent(action: string, form: Record<string, string>) {
    return makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/admin/users?/${action}`,
        form,
        locals: { db: mem.db, tenant, user: admin, session: adminSession, env: mem.env },
    });
}

describe("관리자 사용자 목록 액션 → RP 통지", () => {
    for (const status of ["disabled", "locked"] as const) {
        it(`상태를 ${status} 로 바꾸면 세션·refresh 를 끊고 back-channel logout 을 보낸다`, async () => {
            await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });
            const rt = await seedRefreshToken();

            await adminUserActions.updateStatus!(adminListEvent("updateStatus", { id: target.id, status }) as never);

            expect(await liveSessionCount(target.id)).toBe(0);
            expect(await isRefreshRevoked(rt)).toBe(true);
            expect(logoutSubjects()).toEqual([target.id]);
            expect(await bcAuditReasons()).toEqual([`user_${status}`]);
        });
    }

    it("active 로 되돌릴 때는 보내지 않는다", async () => {
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });
        await adminUserActions.updateStatus!(adminListEvent("updateStatus", { id: target.id, status: "active" }) as never);
        expect(captured).toHaveLength(0);
        expect(await liveSessionCount(target.id)).toBe(1);
    });

    it("전역 역할을 바꾸면 back-channel logout 을 보낸다", async () => {
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });
        const rt = await seedRefreshToken();

        await adminUserActions.updateRole!(adminListEvent("updateRole", { id: target.id, role: "admin" }) as never);

        expect(await isRefreshRevoked(rt)).toBe(true);
        expect(logoutSubjects()).toEqual([target.id]);
        expect(await bcAuditReasons()).toEqual(["role_changed"]);
    });

    it("관리자 비밀번호 리셋은 back-channel logout 을 보낸다", async () => {
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });
        const rt = await seedRefreshToken();

        await adminUserActions.resetPassword!(adminListEvent("resetPassword", { id: target.id, newPassword: "new-password-456" }) as never);

        expect(await isRefreshRevoked(rt)).toBe(true);
        expect(logoutSubjects()).toEqual([target.id]);
        expect(await bcAuditReasons()).toEqual(["password_reset_by_admin"]);
    });
});

describe("관리자 사용자 상세 편집 → RP 통지", () => {
    function profileEvent(form: Record<string, string>) {
        const event = makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/admin/users/${target.id}`,
            form,
            locals: { db: mem.db, tenant, user: admin, session: adminSession, env: mem.env },
        });
        (event as unknown as { params: { id: string } }).params = { id: target.id };
        return event as Parameters<typeof updateProfile>[0];
    }

    it("상세 편집에서 비활성으로 바꾸면 세션을 끊고 통지한다 (예전엔 세션도 남았다)", async () => {
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });

        await updateProfile(profileEvent({ role: "user", status: "disabled" }));

        expect(await liveSessionCount(target.id)).toBe(0);
        expect(logoutSubjects()).toEqual([target.id]);
        expect(await bcAuditReasons()).toEqual(["user_disabled"]);
    });

    it("역할도 상태도 그대로면 보내지 않는다", async () => {
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });
        await updateProfile(profileEvent({ role: "user", status: "active", displayName: "Renamed" }));
        expect(captured).toHaveLength(0);
        expect(await liveSessionCount(target.id)).toBe(1);
    });
});

describe("본인 조치 → RP 통지", () => {
    it("모든 기기에서 로그아웃은 back-channel logout 을 보낸다", async () => {
        const { actions } = await import("../../src/routes/account/sessions/+page.server");
        const current = (await seedSession(mem.db, { tenantId: tenant.id, userId: target.id })).session;

        const event = makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/account/sessions?/revokeAll`,
            form: {},
            locals: { db: mem.db, tenant, user: target, session: current, env: mem.env },
        });
        // 현재 세션까지 끊으므로 성공 시 /login 으로 redirect 한다.
        await expect(actions.revokeAll!(event as never)).rejects.toMatchObject({ status: 303, location: "/login" });

        expect(logoutSubjects()).toEqual([target.id]);
        expect(await bcAuditReasons()).toEqual(["self_revoke_all"]);
    });

    it("비밀번호 재설정 링크로 바꾸면 back-channel logout 을 보낸다", async () => {
        const { actions } = await import("../../src/routes/(auth)/reset-password/+page.server");
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });
        const token = `reset-token-${crypto.randomUUID()}`;
        await mem.db.insert(passwordResetTokens).values({
            id: crypto.randomUUID(),
            userId: target.id,
            tokenHash: await hashToken(token),
            expiresAt: new Date(Date.now() + 60 * 60 * 1000),
        });

        const event = makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/reset-password`,
            form: { token, password: "new-password-456", confirmPassword: "new-password-456" },
            locals: { db: mem.db, tenant, env: mem.env },
        });
        try {
            await actions.default!(event as never);
        } catch (e) {
            // 성공 시 /login 으로 redirect 한다.
            if (!(typeof e === "object" && e !== null && "status" in e)) throw e;
        }

        expect(await liveSessionCount(target.id)).toBe(0);
        expect(logoutSubjects()).toEqual([target.id]);
        expect(await bcAuditReasons()).toEqual(["password_reset"]);
    });
});
