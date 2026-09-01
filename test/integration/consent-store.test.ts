import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { getActiveConsent, listActiveConsents, recordConsent, revokeConsentRows } from "../../src/lib/server/consent";
import { userClientConsents } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, type MemoryDb } from "./harness";
import type { Tenant, User } from "../../src/lib/server/db/schema";

// 동의 기록의 저장·조회·철회. 핵심은 **철회가 행을 지우지 않는다**는 것이다 —
// "그때 무엇에 동의했는가" 는 나중에 답해야 할 질문이라 이력이 남아야 한다.

let mem: MemoryDb;
let tenant: Tenant;
let user: User;

const OIDC_CLIENT = "11111111-1111-4111-8111-111111111111";
const SAML_SP = "22222222-2222-4222-8222-222222222222";

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, { tenantId: tenant.id, email: "consent@test.example", username: "consentuser" });
});

afterEach(() => mem.close());

function target(clientType: "oidc" | "saml" = "oidc", clientRefId = OIDC_CLIENT) {
    return { tenantId: tenant.id, userId: user.id, clientType, clientRefId } as const;
}

describe("동의 저장과 조회", () => {
    it("동의를 기록하고 되읽는다", async () => {
        await recordConsent(mem.db, target(), ["openid", "profile"]);

        const row = await getActiveConsent(mem.db, target());
        expect(row).not.toBeNull();
        expect(row!.grantedScopes).toBe("openid profile");
        expect(row!.revokedAt).toBeNull();
        expect(row!.clientType).toBe("oidc");
    });

    it("동의가 없으면 null", async () => {
        expect(await getActiveConsent(mem.db, target())).toBeNull();
    });

    it("중복 스코프는 정규화해 저장한다", async () => {
        await recordConsent(mem.db, target(), ["openid", "openid", "profile"]);
        expect((await getActiveConsent(mem.db, target()))!.grantedScopes).toBe("openid profile");
    });

    it("다른 클라이언트의 동의는 섞이지 않는다", async () => {
        await recordConsent(mem.db, target("oidc", OIDC_CLIENT), ["openid"]);
        await recordConsent(mem.db, target("saml", SAML_SP), ["email", "displayName"]);

        expect((await getActiveConsent(mem.db, target("oidc", OIDC_CLIENT)))!.grantedScopes).toBe("openid");
        expect((await getActiveConsent(mem.db, target("saml", SAML_SP)))!.grantedScopes).toBe("email displayName");
    });

    it("같은 id 라도 clientType 이 다르면 별개다 (OIDC/SAML 공용 테이블)", async () => {
        await recordConsent(mem.db, target("oidc", OIDC_CLIENT), ["openid"]);
        expect(await getActiveConsent(mem.db, target("saml", OIDC_CLIENT))).toBeNull();
    });

    it("다른 사용자의 동의는 보이지 않는다", async () => {
        const other = await seedUser(mem.db, { tenantId: tenant.id, email: "other@test.example", username: "other" });
        await recordConsent(mem.db, target(), ["openid"]);

        expect(await getActiveConsent(mem.db, { ...target(), userId: other.id })).toBeNull();
    });
});

describe("재동의", () => {
    it("다시 기록하면 이전 행은 철회 표시되고 새 행이 활성이 된다", async () => {
        await recordConsent(mem.db, target(), ["openid"], new Date(1000));
        await recordConsent(mem.db, target(), ["openid", "email"], new Date(2000));

        const all = await mem.db.select().from(userClientConsents).where(eq(userClientConsents.userId, user.id));
        expect(all).toHaveLength(2); // 이력 보존 — 덮어쓰지 않는다

        const active = all.filter((r) => r.revokedAt === null);
        expect(active).toHaveLength(1);
        expect(active[0].grantedScopes).toBe("openid email");

        const revoked = all.filter((r) => r.revokedAt !== null);
        expect(revoked[0].grantedScopes).toBe("openid");
    });

    it("가장 최근 활성 동의를 돌려준다", async () => {
        await recordConsent(mem.db, target(), ["openid"], new Date(1000));
        await recordConsent(mem.db, target(), ["openid", "profile", "email"], new Date(5000));

        expect((await getActiveConsent(mem.db, target()))!.grantedScopes).toBe("openid profile email");
    });
});

describe("철회", () => {
    it("철회하면 활성 동의가 사라지지만 행은 남는다", async () => {
        await recordConsent(mem.db, target(), ["openid", "profile"]);
        await revokeConsentRows(mem.db, target());

        expect(await getActiveConsent(mem.db, target())).toBeNull();

        const all = await mem.db.select().from(userClientConsents).where(eq(userClientConsents.userId, user.id));
        expect(all).toHaveLength(1);
        expect(all[0].revokedAt).not.toBeNull();
        expect(all[0].grantedScopes).toBe("openid profile"); // 무엇에 동의했었는지 보존
    });

    it("철회 후 다시 동의할 수 있다", async () => {
        await recordConsent(mem.db, target(), ["openid"]);
        await revokeConsentRows(mem.db, target());
        await recordConsent(mem.db, target(), ["openid", "email"]);

        expect((await getActiveConsent(mem.db, target()))!.grantedScopes).toBe("openid email");
    });

    it("철회는 해당 클라이언트만 건드린다", async () => {
        await recordConsent(mem.db, target("oidc", OIDC_CLIENT), ["openid"]);
        await recordConsent(mem.db, target("saml", SAML_SP), ["email"]);

        await revokeConsentRows(mem.db, target("oidc", OIDC_CLIENT));

        expect(await getActiveConsent(mem.db, target("oidc", OIDC_CLIENT))).toBeNull();
        expect(await getActiveConsent(mem.db, target("saml", SAML_SP))).not.toBeNull();
    });
});

describe("목록", () => {
    it("활성 동의만 최신순으로 돌려준다", async () => {
        await recordConsent(mem.db, target("oidc", OIDC_CLIENT), ["openid"], new Date(1000));
        await recordConsent(mem.db, target("saml", SAML_SP), ["email"], new Date(3000));
        const revokedRef = "33333333-3333-4333-8333-333333333333";
        await recordConsent(mem.db, target("oidc", revokedRef), ["openid"], new Date(2000));
        await revokeConsentRows(mem.db, target("oidc", revokedRef));

        const list = await listActiveConsents(mem.db, tenant.id, user.id);
        expect(list.map((r) => r.clientRefId)).toEqual([SAML_SP, OIDC_CLIENT]); // 최신순
    });

    it("다른 테넌트의 동의는 섞이지 않는다", async () => {
        await recordConsent(mem.db, target(), ["openid"]);
        expect(await listActiveConsents(mem.db, "00000000-0000-4000-8000-000000000000", user.id)).toEqual([]);
    });
});
