import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { and, eq } from "drizzle-orm";
import { actions as skinActions, load as skinLoad } from "../../src/routes/admin/skins/+page.server";
import { adminError } from "../../src/lib/server/admin/errors";
import { auditEvents, clientSkins, oidcClients, samlSps, tenants } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, seedMfaSession, seedSession, seedOidcClient, makeEvent, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Session, Tenant, User } from "../../src/lib/server/db/schema";

// 스킨 등록 화면(`/admin/skins`)의 서버 액션.
//
// 여기서 막아야 하는 것은 두 가지다. (1) 관리자가 실수로든 고의로든 IdP 를 내부망 스캐너로
// 쓰지 못하게 하는 fetch URL 검증 — 등록 시점이 SSRF 의 첫 관문이다. (2) 테넌트 경계 —
// 스킨 행은 tenant_id 로 격리되므로 다른 테넌트의 행을 id 만으로 건드릴 수 없어야 한다.

let mem: MemoryDb;
let tenant: Tenant;
let admin: User;
let adminSession: Session;
let clientId: string;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    admin = await seedUser(mem.db, { tenantId: tenant.id, email: "admin@test.example", username: "admin", role: "admin" });
    adminSession = (await seedMfaSession(mem.db, { tenantId: tenant.id, userId: admin.id })).session;
    const client = await seedOidcClient(mem.db, { tenantId: tenant.id, clientId: "skin-client", redirectUris: ["https://app.test.example/cb"] });
    clientId = client.id;
});

afterEach(() => mem.close());

function adminEvent(form: Record<string, string>, user: User = admin, session: Session = adminSession) {
    return makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/admin/skins`,
        headers: { Origin: TEST_ISSUER_URL },
        form,
        locals: { db: mem.db, tenant, user, session, env: mem.env },
    });
}

const VALID_URL = "https://skin.test.example/login.html";

function createForm(overrides: Record<string, string> = {}) {
    return { clientType: "oidc", clientRefId: clientId, skinType: "login", fetchUrl: VALID_URL, cacheTtlSeconds: "3600", ...overrides };
}

async function rows() {
    return mem.db.select().from(clientSkins).where(eq(clientSkins.tenantId, tenant.id));
}

describe("skins create: fetch URL 검증", () => {
    it("정상 등록되고 기본값이 채워진다", async () => {
        const result = await skinActions.create(adminEvent(createForm()));

        expect(result).toEqual({ created: true });
        const [row] = await rows();
        expect(row.fetchUrl).toBe(VALID_URL);
        expect(row.clientType).toBe("oidc");
        expect(row.skinType).toBe("login");
        expect(row.enabled).toBe(true);
        expect(row.cacheTtlSeconds).toBe(3600);
        expect(row.fetchSecret).toBeNull();
    });

    const rejected = [
        ["https 가 아니면", "http://skin.test.example/login.html", "https_only"],
        ["URL 형식이 아니면", "skin.test.example", "invalid_url"],
        ["localhost 는", "https://localhost/login.html", "loopback_forbidden"],
        ["127.x 는", "https://127.0.0.1/login.html", "loopback_forbidden"],
        ["링크로컬(169.254.x)은", "https://169.254.169.254/x", "internal_addr_forbidden"],
    ] as const;

    for (const [label, fetchUrl, reason] of rejected) {
        it(`${label} 거부한다 (${reason})`, async () => {
            const result = (await skinActions.create(adminEvent(createForm({ fetchUrl })))) as { status: number; data: { error: string } };

            expect(result.status).toBe(400);
            expect(result.data.error).toBe(adminError("ko", reason));
            expect(await rows()).toHaveLength(0);
        });
    }

    it("필수 항목이 빠지면 400", async () => {
        const result = (await skinActions.create(adminEvent(createForm({ fetchUrl: "" })))) as { status: number; data: { error: string } };
        expect(result.status).toBe(400);
        expect(result.data.error).toBe(adminError("ko", "required_fields"));
        expect(await rows()).toHaveLength(0);
    });

    it("clientType 이 oidc/saml 이 아니면 400", async () => {
        const result = (await skinActions.create(adminEvent(createForm({ clientType: "ldap" })))) as { status: number; data: { error: string } };
        expect(result.status).toBe(400);
        expect(result.data.error).toBe(adminError("ko", "invalid_client_type"));
    });
});

describe("skins create: 캐시 TTL", () => {
    it("음수 TTL 은 거부한다", async () => {
        const result = (await skinActions.create(adminEvent(createForm({ cacheTtlSeconds: "-1" })))) as { status: number; data: { error: string } };
        expect(result.status).toBe(400);
        expect(result.data.error).toBe(adminError("ko", "cache_ttl_negative"));
    });

    it("상한(1일) 을 넘으면 거부한다", async () => {
        const result = (await skinActions.create(adminEvent(createForm({ cacheTtlSeconds: "86401" })))) as { status: number; data: { error: string } };
        expect(result.status).toBe(400);
        expect(result.data.error).toBe(adminError("ko", "cache_ttl_max", { max: 86400 }));
    });

    it("상한 정확히 1일은 허용한다 (경계)", async () => {
        expect(await skinActions.create(adminEvent(createForm({ cacheTtlSeconds: "86400" })))).toEqual({ created: true });
        expect((await rows())[0].cacheTtlSeconds).toBe(86400);
    });

    it("TTL 0 은 허용한다 (캐시 없이 매번 가져오기)", async () => {
        expect(await skinActions.create(adminEvent(createForm({ cacheTtlSeconds: "0" })))).toEqual({ created: true });
        expect((await rows())[0].cacheTtlSeconds).toBe(0);
    });

    it("숫자가 아니면 기본값 3600 으로 떨어진다", async () => {
        expect(await skinActions.create(adminEvent(createForm({ cacheTtlSeconds: "abc" })))).toEqual({ created: true });
        expect((await rows())[0].cacheTtlSeconds).toBe(3600);
    });
});

describe("skins create: 중복", () => {
    it("같은 (클라이언트, 스킨 타입) 조합은 409", async () => {
        await skinActions.create(adminEvent(createForm()));
        const result = (await skinActions.create(adminEvent(createForm({ fetchUrl: "https://other.test.example/login.html" })))) as { status: number; data: { error: string } };

        expect(result.status).toBe(409);
        expect(result.data.error).toBe(adminError("ko", "skin_config_exists"));
        expect(await rows()).toHaveLength(1);
    });

    it("스킨 타입이 다르면 같은 클라이언트에도 등록된다", async () => {
        await skinActions.create(adminEvent(createForm({ skinType: "login" })));
        expect(await skinActions.create(adminEvent(createForm({ skinType: "signup" })))).toEqual({ created: true });
        expect(await rows()).toHaveLength(2);
    });
});

describe("skins update", () => {
    async function seedRow() {
        await skinActions.create(adminEvent(createForm()));
        return (await rows())[0];
    }

    it("URL·시크릿·TTL 을 수정하고 감사 로그를 남긴다", async () => {
        const row = await seedRow();
        const result = await skinActions.update(adminEvent({ id: row.id, fetchUrl: "https://new.test.example/login.html", fetchSecret: "tok", cacheTtlSeconds: "60" }));

        expect(result).toEqual({ updated: true });
        const [after] = await rows();
        expect(after.fetchUrl).toBe("https://new.test.example/login.html");
        expect(after.fetchSecret).toBe("tok");
        expect(after.cacheTtlSeconds).toBe(60);

        const events = await mem.db.select().from(auditEvents).where(eq(auditEvents.kind, "client_skin_updated"));
        expect(events).toHaveLength(1);
        const detail = JSON.parse(events[0].detailJson!) as { fetchUrlChanged: boolean; secretRotated: boolean; cacheTtlChanged: boolean };
        expect(detail).toMatchObject({ fetchUrlChanged: true, secretRotated: true, cacheTtlChanged: true });
    });

    it("감사 로그 detail 에 시크릿 평문을 담지 않는다", async () => {
        const row = await seedRow();
        await skinActions.update(adminEvent({ id: row.id, fetchUrl: VALID_URL, fetchSecret: "super-secret-value", cacheTtlSeconds: "3600" }));

        const [event] = await mem.db.select().from(auditEvents).where(eq(auditEvents.kind, "client_skin_updated"));
        expect(event.detailJson).not.toContain("super-secret-value");
    });

    it("URL 이 비면 400 이고 기존 값이 유지된다", async () => {
        const row = await seedRow();
        const result = (await skinActions.update(adminEvent({ id: row.id, fetchUrl: "", cacheTtlSeconds: "3600" }))) as { status: number; data: { error: string } };

        expect(result.status).toBe(400);
        expect(result.data.error).toBe(adminError("ko", "url_required"));
        expect((await rows())[0].fetchUrl).toBe(VALID_URL);
    });

    it("내부 주소로 바꾸려 하면 거부한다", async () => {
        const row = await seedRow();
        const result = (await skinActions.update(adminEvent({ id: row.id, fetchUrl: "https://127.0.0.1/x", cacheTtlSeconds: "3600" }))) as { status: number };

        expect(result.status).toBe(400);
        expect((await rows())[0].fetchUrl).toBe(VALID_URL);
    });

    it("빈 시크릿을 보내면 null 로 지운다", async () => {
        const row = await seedRow();
        await skinActions.update(adminEvent({ id: row.id, fetchUrl: VALID_URL, fetchSecret: "tok", cacheTtlSeconds: "3600" }));
        await skinActions.update(adminEvent({ id: row.id, fetchUrl: VALID_URL, fetchSecret: "", cacheTtlSeconds: "3600" }));

        expect((await rows())[0].fetchSecret).toBeNull();
    });

    it("존재하지 않는 id 는 404", async () => {
        const result = (await skinActions.update(adminEvent({ id: crypto.randomUUID(), fetchUrl: VALID_URL, cacheTtlSeconds: "3600" }))) as { status: number; data: { error: string } };
        expect(result.status).toBe(404);
        expect(result.data.error).toBe(adminError("ko", "skin_not_found"));
    });
});

describe("skins toggleEnabled / delete", () => {
    async function seedRow() {
        await skinActions.create(adminEvent(createForm()));
        return (await rows())[0];
    }

    it("활성 상태를 뒤집는다", async () => {
        const row = await seedRow();
        expect(await skinActions.toggleEnabled(adminEvent({ id: row.id }))).toEqual({ toggled: true });
        expect((await rows())[0].enabled).toBe(false);

        await skinActions.toggleEnabled(adminEvent({ id: row.id }));
        expect((await rows())[0].enabled).toBe(true);
    });

    it("삭제한다", async () => {
        const row = await seedRow();
        expect(await skinActions.delete(adminEvent({ id: row.id }))).toEqual({ deleted: true });
        expect(await rows()).toHaveLength(0);
    });

    it("없는 id 로 토글/삭제/캐시무효화는 404", async () => {
        const id = crypto.randomUUID();
        for (const action of [skinActions.toggleEnabled, skinActions.delete, skinActions.invalidateCache]) {
            const result = (await action(adminEvent({ id }))) as { status: number };
            expect(result.status).toBe(404);
        }
    });

    it("캐시 무효화는 행을 건드리지 않는다", async () => {
        const row = await seedRow();
        expect(await skinActions.invalidateCache(adminEvent({ id: row.id }))).toEqual({ invalidated: true });
        expect((await rows())[0].fetchUrl).toBe(VALID_URL);
    });
});

// ── 테넌트 경계 ────────────────────────────────────────────────────────────────
describe("skins: 테넌트 경계", () => {
    let otherTenant: Tenant;
    let otherSkinId: string;

    beforeEach(async () => {
        const id = crypto.randomUUID();
        await mem.db.insert(tenants).values({ id, name: "Other", slug: `other-${id.slice(0, 8)}` });
        [otherTenant] = await mem.db.select().from(tenants).where(eq(tenants.id, id)).limit(1);

        const skinId = crypto.randomUUID();
        await mem.db.insert(clientSkins).values({
            id: skinId,
            tenantId: otherTenant.id,
            clientType: "oidc",
            clientRefId: crypto.randomUUID(),
            skinType: "login",
            fetchUrl: "https://other-tenant.test.example/login.html",
        });
        otherSkinId = skinId;
    });

    it("다른 테넌트의 스킨은 수정·삭제·토글·무효화 모두 404", async () => {
        for (const action of [skinActions.toggleEnabled, skinActions.delete, skinActions.invalidateCache]) {
            const result = (await action(adminEvent({ id: otherSkinId }))) as { status: number };
            expect(result.status).toBe(404);
        }
        const updated = (await skinActions.update(adminEvent({ id: otherSkinId, fetchUrl: VALID_URL, cacheTtlSeconds: "3600" }))) as { status: number };
        expect(updated.status).toBe(404);

        // 남의 행은 그대로다.
        const [survivor] = await mem.db.select().from(clientSkins).where(eq(clientSkins.id, otherSkinId));
        expect(survivor.fetchUrl).toBe("https://other-tenant.test.example/login.html");
        expect(survivor.enabled).toBe(true);
    });

    it("load 는 자기 테넌트의 스킨과 클라이언트 목록만 반환한다", async () => {
        await skinActions.create(adminEvent(createForm()));

        // load 의 반환 타입은 `void | PageData` 유니온이라 테스트에서 좁혀 쓴다.
        const data = (await skinLoad({ locals: { db: mem.db, tenant, user: admin, session: adminSession } } as never)) as unknown as {
            skins: Array<{ tenantId: string }>;
            oidcList: Array<{ id: string }>;
            samlList: unknown[];
        };

        expect(data.skins).toHaveLength(1);
        expect(data.skins[0].tenantId).toBe(tenant.id);
        expect(data.oidcList.map((c) => c.id)).toEqual([clientId]);
        expect(data.samlList).toEqual([]);
    });
});

// ── 관리자 게이트 ──────────────────────────────────────────────────────────────
describe("skins: 관리자 게이트", () => {
    it("MFA 를 거치지 않은 관리자 세션은 거부한다", async () => {
        const weak = (await seedSession(mem.db, { tenantId: tenant.id, userId: admin.id })).session;
        await expect(skinActions.create(adminEvent(createForm(), admin, weak))).rejects.toThrow();
        expect(await rows()).toHaveLength(0);
    });

    it("일반 사용자는 거부한다", async () => {
        const user = await seedUser(mem.db, { tenantId: tenant.id, email: "u@test.example", username: "u" });
        const session = (await seedMfaSession(mem.db, { tenantId: tenant.id, userId: user.id })).session;
        await expect(skinActions.create(adminEvent(createForm(), user, session))).rejects.toThrow();
        expect(await rows()).toHaveLength(0);
    });
});

// SAML SP 도 스킨 대상이다 — clientType 이 지켜지는지만 확인한다.
describe("skins: SAML SP", () => {
    it("saml 타입으로도 등록된다", async () => {
        const spId = crypto.randomUUID();
        await mem.db.insert(samlSps).values({ id: spId, tenantId: tenant.id, name: "SP", entityId: "https://sp.test.example", acsUrl: "https://sp.test.example/acs" });

        expect(await skinActions.create(adminEvent(createForm({ clientType: "saml", clientRefId: spId })))).toEqual({ created: true });

        const [row] = await mem.db
            .select()
            .from(clientSkins)
            .where(and(eq(clientSkins.tenantId, tenant.id), eq(clientSkins.clientType, "saml")));
        expect(row.clientRefId).toBe(spId);
        expect(await mem.db.select().from(oidcClients).where(eq(oidcClients.tenantId, tenant.id))).toHaveLength(1);
    });
});

// 3-A: 테넌트 기본 스킨은 clientType="tenant" + clientRefId="*" 로 등록된다.
describe("skins: 테넌트 기본 스킨 등록", () => {
    it("tenant 타입으로 등록된다", async () => {
        expect(await skinActions.create(adminEvent(createForm({ clientType: "tenant", clientRefId: "*" })))).toEqual({ created: true });

        const [row] = await rows();
        expect(row.clientType).toBe("tenant");
        expect(row.clientRefId).toBe("*");
    });

    it("tenant 타입인데 clientRefId 가 예약값이 아니면 400", async () => {
        const result = (await skinActions.create(adminEvent(createForm({ clientType: "tenant", clientRefId: clientId })))) as { status: number };
        expect(result.status).toBe(400);
        expect(await rows()).toHaveLength(0);
    });

    it("스킨 타입당 하나만 등록된다 (유니크 인덱스)", async () => {
        await skinActions.create(adminEvent(createForm({ clientType: "tenant", clientRefId: "*" })));
        const dup = (await skinActions.create(adminEvent(createForm({ clientType: "tenant", clientRefId: "*" })))) as { status: number };

        expect(dup.status).toBe(409);
        expect(await rows()).toHaveLength(1);
    });

    it("클라이언트 전용 스킨과 공존한다", async () => {
        await skinActions.create(adminEvent(createForm({ clientType: "tenant", clientRefId: "*" })));
        expect(await skinActions.create(adminEvent(createForm()))).toEqual({ created: true });
        expect(await rows()).toHaveLength(2);
    });

    it("새 스킨 타입 3종도 등록된다", async () => {
        for (const skinType of ["accept_invite", "confirm_email_change", "logout"]) {
            expect(await skinActions.create(adminEvent(createForm({ clientType: "tenant", clientRefId: "*", skinType })))).toEqual({ created: true });
        }
        expect(await rows()).toHaveLength(3);
    });
});
