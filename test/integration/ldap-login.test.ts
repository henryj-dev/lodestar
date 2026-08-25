import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { eq, and } from "drizzle-orm";
import { provisionLdapUser } from "../../src/lib/server/ldap/provision";
import { auditEvents, identities, users } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, seedIdentityProvider, makeEvent, makeCookieJar, catchRedirect, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Tenant } from "../../src/lib/server/db/schema";

// LDAP 로그인 분기를 실 DB + 실 login 라우트로 검증한다. 실제 LDAP 서버는 띄우지 않고,
// 네트워크 계층(ldap/client)만 최소 모킹한다 — authenticateLdap(필터/DN 조합·검증)과
// provisionLdapUser(JIT), login 액션 분기는 모두 실제 코드가 구동된다.

const LDAP_USER = "ldapuser";
const LDAP_PW = "ldap-correct-pw";
const LDAP_DN = "uid=ldapuser,dc=example,dc=com";

// ldap/client 모킹: 지정한 DN+비밀번호만 bind 성공, 속성은 고정 디렉터리 엔트리 반환.
vi.mock("../../src/lib/server/ldap/client", () => ({
    ldapBind: async (_config: unknown, dn: string, password: string): Promise<void> => {
        if (dn === "uid=ldapuser,dc=example,dc=com" && password === "ldap-correct-pw") return;
        throw new Error("LDAP bind 실패: invalid credentials");
    },
    ldapSearchDn: async (): Promise<string | null> => null,
    ldapFetchEntry: async (): Promise<Record<string, string>> => ({
        mail: "ldapuser@corp.example",
        cn: "LDAP User",
        givenName: "Ldap",
        sn: "User",
    }),
}));

let mem: MemoryDb;
let tenant: Tenant;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    // Pattern 방식 LDAP provider (bindDN 없음 → userDnPattern 으로 DN 조합).
    await seedIdentityProvider(mem.db, {
        tenantId: tenant.id,
        kind: "ldap",
        config: {
            host: "ldap.example.com",
            port: 389,
            baseDN: "dc=example,dc=com",
            userDnPattern: "uid={username},dc=example,dc=com",
            tlsMode: "none",
        },
        enabled: true,
    });
});

afterEach(() => {
    mem.close();
    vi.clearAllMocks();
});

function loginEvent(cookies: ReturnType<typeof makeCookieJar>["cookies"], form: Record<string, string>) {
    return makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/login`,
        form,
        locals: { db: mem.db, tenant, env: mem.env },
        cookies,
    });
}

describe("LDAP 로그인(JIT 프로비저닝)", () => {
    it("올바른 LDAP 자격증명은 신규 유저를 JIT 프로비저닝하고 세션을 발급한다", async () => {
        const { actions: loginActions } = await import("../../src/routes/(auth)/login/+page.server");
        const jar = makeCookieJar();

        const redirect = await catchRedirect(() => loginActions.default(loginEvent(jar.cookies, { username: LDAP_USER, password: LDAP_PW })));
        expect(redirect.status).toBe(303);
        expect(jar.has("idp_session")).toBe(true);

        // JIT 로 생성된 유저 + LDAP identity 연결 확인.
        const [u] = await mem.db
            .select()
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.email, "ldapuser@corp.example")))
            .limit(1);
        expect(u).toBeTruthy();
        expect(u.role).toBe("user");
        expect(u.status).toBe("active");

        const idRows = await mem.db.select().from(identities).where(eq(identities.userId, u.id));
        expect(idRows.length).toBe(1);
        expect(idRows[0].subject).toBe(LDAP_DN);
    });

    it("잘못된 LDAP 비밀번호는 로컬 인증으로도 실패해 400 으로 거부한다(유저 미생성)", async () => {
        const { actions: loginActions } = await import("../../src/routes/(auth)/login/+page.server");
        const jar = makeCookieJar();

        const res = (await loginActions.default(loginEvent(jar.cookies, { username: LDAP_USER, password: "wrong-pw" }))) as { status?: number };
        expect(res.status).toBe(400);
        expect(jar.has("idp_session")).toBe(false);
        // 실패 시 유저가 만들어지면 안 된다.
        const rows = await mem.db.select().from(users).where(eq(users.email, "ldapuser@corp.example"));
        expect(rows.length).toBe(0);
    });

    it("provisionLdapUser: 동일 이메일의 기존 로컬 계정이 있으면 자동 연결을 거부한다(계정 탈취 방지)", async () => {
        // 관리자 로컬 계정이 이미 corp 이메일을 점유.
        await seedUser(mem.db, { tenantId: tenant.id, email: "ldapuser@corp.example", username: "existing", role: "admin", status: "active" });
        await expect(
            provisionLdapUser(mem.db, tenant.id, "provider-1", {
                dn: LDAP_DN,
                username: LDAP_USER,
                email: "ldapuser@corp.example",
                displayName: "LDAP User",
                givenName: "Ldap",
                familyName: "User",
            }),
        ).rejects.toThrow();
    });

    it("교차 테넌트 userId를 가진 잘못된 identity는 프로필을 갱신하지 않고 거부한다", async () => {
        const otherTenantId = crypto.randomUUID();
        await mem.db.insert((await import("../../src/lib/server/db/schema")).tenants).values({ id: otherTenantId, slug: "ldap-other", name: "Other" });
        const foreignUser = await seedUser(mem.db, { tenantId: otherTenantId, email: "foreign@test.example", username: "foreign", displayName: "Original" });
        await mem.db.insert(identities).values({
            tenantId: tenant.id,
            userId: foreignUser.id,
            provider: "ldap:provider-1",
            subject: LDAP_DN,
            email: "ldapuser@corp.example",
        });

        await expect(
            provisionLdapUser(mem.db, tenant.id, "provider-1", {
                dn: LDAP_DN,
                username: LDAP_USER,
                email: "changed@corp.example",
                displayName: "Changed",
                givenName: "Changed",
                familyName: "User",
            }),
        ).rejects.toThrow(/테넌트/);

        const [unchanged] = await mem.db.select().from(users).where(eq(users.id, foreignUser.id));
        expect(unchanged.email).toBe("foreign@test.example");
        expect(unchanged.displayName).toBe("Original");
        const [audit] = await mem.db.select().from(auditEvents).where(eq(auditEvents.kind, "ldap_identity_tenant_mismatch"));
        expect(audit).toMatchObject({ outcome: "failure", tenantId: tenant.id });
    });
});
