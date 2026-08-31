import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { evaluateTerms, listApplicableTerms, recordTermDecisions, type TermsItem } from "../../src/lib/server/terms";
import { clientTerms, termsDocuments, userTermAgreements } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, type MemoryDb } from "./harness";
import type { Tenant, User } from "../../src/lib/server/db/schema";

// 약관의 세 축을 검증한다.
//   노출 범위 : 매핑 없는 문서 = 전역, 매핑 있는 문서 = 그 앱에서만
//   버전      : key 의 최신 발행본이 유효본. version 이 오르면 자동으로 재동의 대상
//   필수/선택 : 필수는 진행을 막고, 선택은 거부도 기록해 다시 묻지 않는다

let mem: MemoryDb;
let tenant: Tenant;
let user: User;

const APP_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const APP_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, { tenantId: tenant.id, email: "terms@test.example", username: "termsuser" });
});

afterEach(() => mem.close());

async function addDoc(args: { key: string; version?: number; locale?: "ko" | "en"; title?: string; body?: string; required?: boolean; published?: boolean; order?: number }) {
    await mem.db.insert(termsDocuments).values({
        tenantId: tenant.id,
        key: args.key,
        version: args.version ?? 1,
        locale: args.locale ?? "ko",
        title: args.title ?? `${args.key} 약관`,
        body: args.body ?? "본문",
        required: args.required ?? true,
        publishedAt: args.published === false ? null : new Date(),
        displayOrder: args.order ?? 0,
    });
}

async function mapToApp(key: string, clientRefId: string, clientType: "oidc" | "saml" = "oidc") {
    await mem.db.insert(clientTerms).values({ tenantId: tenant.id, clientType, clientRefId, termsKey: key });
}

const keys = (items: TermsItem[]) => items.map((i) => i.key);

describe("노출 범위", () => {
    it("매핑이 없는 문서는 전역 — 앱 컨텍스트 없이도 나온다", async () => {
        await addDoc({ key: "service" });
        await addDoc({ key: "privacy" });

        expect(keys(await listApplicableTerms(mem.db, tenant.id, { locale: "ko" })).sort()).toEqual(["privacy", "service"]);
    });

    it("특정 앱에 매핑된 문서는 전역 목록에 나오지 않는다", async () => {
        await addDoc({ key: "service" });
        await addDoc({ key: "app-a-extra" });
        await mapToApp("app-a-extra", APP_A);

        expect(keys(await listApplicableTerms(mem.db, tenant.id, { locale: "ko" }))).toEqual(["service"]);
    });

    it("그 앱으로 SSO 할 때는 전역 + 그 앱 약관이 함께 나온다", async () => {
        await addDoc({ key: "service", order: 0 });
        await addDoc({ key: "app-a-extra", order: 10 });
        await mapToApp("app-a-extra", APP_A);

        const items = await listApplicableTerms(mem.db, tenant.id, { locale: "ko", client: { clientType: "oidc", clientRefId: APP_A } });
        expect(keys(items)).toEqual(["service", "app-a-extra"]);
    });

    it("다른 앱의 약관은 섞이지 않는다", async () => {
        await addDoc({ key: "app-a-extra" });
        await addDoc({ key: "app-b-extra" });
        await mapToApp("app-a-extra", APP_A);
        await mapToApp("app-b-extra", APP_B);

        const items = await listApplicableTerms(mem.db, tenant.id, { locale: "ko", client: { clientType: "oidc", clientRefId: APP_A } });
        expect(keys(items)).toEqual(["app-a-extra"]);
    });

    it("clientType 이 다르면 별개 앱이다", async () => {
        await addDoc({ key: "saml-only" });
        await mapToApp("saml-only", APP_A, "saml");

        expect(keys(await listApplicableTerms(mem.db, tenant.id, { locale: "ko", client: { clientType: "oidc", clientRefId: APP_A } }))).toEqual([]);
        expect(keys(await listApplicableTerms(mem.db, tenant.id, { locale: "ko", client: { clientType: "saml", clientRefId: APP_A } }))).toEqual(["saml-only"]);
    });

    it("미발행(초안) 문서는 나오지 않는다", async () => {
        await addDoc({ key: "draft", published: false });
        expect(keys(await listApplicableTerms(mem.db, tenant.id, { locale: "ko" }))).toEqual([]);
    });

    it("displayOrder 순으로 정렬한다", async () => {
        await addDoc({ key: "third", order: 30 });
        await addDoc({ key: "first", order: 10 });
        await addDoc({ key: "second", order: 20 });

        expect(keys(await listApplicableTerms(mem.db, tenant.id, { locale: "ko" }))).toEqual(["first", "second", "third"]);
    });

    it("다른 테넌트의 약관은 보이지 않는다", async () => {
        await addDoc({ key: "service" });
        expect(await listApplicableTerms(mem.db, "00000000-0000-4000-8000-000000000000", { locale: "ko" })).toEqual([]);
    });
});

describe("버전과 로케일", () => {
    it("같은 key 의 최신 발행본만 유효하다", async () => {
        await addDoc({ key: "service", version: 1, title: "v1" });
        await addDoc({ key: "service", version: 2, title: "v2" });

        const [item] = await listApplicableTerms(mem.db, tenant.id, { locale: "ko" });
        expect(item.version).toBe(2);
        expect(item.title).toBe("v2");
    });

    it("요청 로케일이 있으면 그것을 쓴다", async () => {
        await addDoc({ key: "service", locale: "ko", title: "한국어" });
        await addDoc({ key: "service", locale: "en", title: "English" });

        expect((await listApplicableTerms(mem.db, tenant.id, { locale: "en" }))[0].title).toBe("English");
        expect((await listApplicableTerms(mem.db, tenant.id, { locale: "ko" }))[0].title).toBe("한국어");
    });

    it("요청 로케일이 없으면 기본 로케일(ko)로 폴백한다", async () => {
        await addDoc({ key: "service", locale: "ko", title: "한국어만" });

        const [item] = await listApplicableTerms(mem.db, tenant.id, { locale: "en" });
        expect(item.title).toBe("한국어만");
        expect(item.locale).toBe("ko");
    });

    it("로케일별로 version 이 달라도 해당 로케일의 최신을 쓴다", async () => {
        await addDoc({ key: "service", locale: "ko", version: 3, title: "ko-v3" });
        await addDoc({ key: "service", locale: "en", version: 2, title: "en-v2" });

        expect((await listApplicableTerms(mem.db, tenant.id, { locale: "en" }))[0].title).toBe("en-v2");
    });
});

describe("동의 판정", () => {
    async function items(locale: "ko" | "en" = "ko") {
        return listApplicableTerms(mem.db, tenant.id, { locale });
    }

    it("동의 기록이 없으면 pending 이고, 필수면 blocking 이다", async () => {
        await addDoc({ key: "service", required: true });
        await addDoc({ key: "marketing", required: false });

        const state = await evaluateTerms(mem.db, tenant.id, user.id, await items());
        expect(keys(state.pending).sort()).toEqual(["marketing", "service"]);
        expect(keys(state.blocking)).toEqual(["service"]);
    });

    it("동의하면 pending 에서 빠진다", async () => {
        await addDoc({ key: "service" });
        const list = await items();
        await recordTermDecisions(mem.db, tenant.id, user.id, [{ key: "service", version: 1, locale: "ko", agreed: true }]);

        const state = await evaluateTerms(mem.db, tenant.id, user.id, list);
        expect(state.pending).toEqual([]);
        expect(state.blocking).toEqual([]);
    });

    it("선택 항목을 거부해도 다시 묻지 않는다 (거부도 기록되므로)", async () => {
        await addDoc({ key: "marketing", required: false });
        const list = await items();
        await recordTermDecisions(mem.db, tenant.id, user.id, [{ key: "marketing", version: 1, locale: "ko", agreed: false }]);

        const state = await evaluateTerms(mem.db, tenant.id, user.id, list);
        expect(state.pending).toEqual([]);
        expect(state.blocking).toEqual([]);
    });

    it("필수 항목을 거부한 기록이 있으면 계속 막는다", async () => {
        await addDoc({ key: "service", required: true });
        const list = await items();
        await recordTermDecisions(mem.db, tenant.id, user.id, [{ key: "service", version: 1, locale: "ko", agreed: false }]);

        const state = await evaluateTerms(mem.db, tenant.id, user.id, list);
        expect(keys(state.blocking)).toEqual(["service"]);
        expect(keys(state.pending)).toEqual(["service"]);
    });

    it("version 이 오르면 기존 동의자도 다시 대상이 된다", async () => {
        await addDoc({ key: "service", version: 1 });
        await recordTermDecisions(mem.db, tenant.id, user.id, [{ key: "service", version: 1, locale: "ko", agreed: true }]);
        expect((await evaluateTerms(mem.db, tenant.id, user.id, await items())).pending).toEqual([]);

        await addDoc({ key: "service", version: 2 });

        const state = await evaluateTerms(mem.db, tenant.id, user.id, await items());
        expect(keys(state.pending)).toEqual(["service"]);
        expect(state.pending[0].version).toBe(2);
    });

    it("다른 사용자의 동의는 영향을 주지 않는다", async () => {
        await addDoc({ key: "service" });
        const other = await seedUser(mem.db, { tenantId: tenant.id, email: "o@test.example", username: "o" });
        await recordTermDecisions(mem.db, tenant.id, other.id, [{ key: "service", version: 1, locale: "ko", agreed: true }]);

        expect(keys((await evaluateTerms(mem.db, tenant.id, user.id, await items())).pending)).toEqual(["service"]);
    });

    it("빈 목록은 그대로 통과", async () => {
        expect(await evaluateTerms(mem.db, tenant.id, user.id, [])).toEqual({ pending: [], blocking: [] });
    });
});

describe("동의 기록", () => {
    it("어떤 로케일의 본문을 보고 동의했는지 남긴다", async () => {
        await recordTermDecisions(mem.db, tenant.id, user.id, [{ key: "service", version: 2, locale: "en", agreed: true }]);

        const [row] = await mem.db.select().from(userTermAgreements);
        expect(row.termsKey).toBe("service");
        expect(row.version).toBe(2);
        expect(row.locale).toBe("en");
        expect(row.agreed).toBe(true);
    });

    it("같은 (key, version) 재제출은 값을 덮어쓴다 (선택 항목을 나중에 승인)", async () => {
        await recordTermDecisions(mem.db, tenant.id, user.id, [{ key: "marketing", version: 1, locale: "ko", agreed: false }]);
        await recordTermDecisions(mem.db, tenant.id, user.id, [{ key: "marketing", version: 1, locale: "ko", agreed: true }]);

        const rows = await mem.db.select().from(userTermAgreements);
        expect(rows).toHaveLength(1);
        expect(rows[0].agreed).toBe(true);
    });

    it("이전 version 기록은 지우지 않는다 (증빙 보존)", async () => {
        await recordTermDecisions(mem.db, tenant.id, user.id, [{ key: "service", version: 1, locale: "ko", agreed: true }]);
        await recordTermDecisions(mem.db, tenant.id, user.id, [{ key: "service", version: 2, locale: "ko", agreed: true }]);

        const rows = await mem.db.select().from(userTermAgreements);
        expect(rows.map((r) => r.version).sort()).toEqual([1, 2]);
    });

    it("여러 항목을 한 번에 기록한다", async () => {
        await recordTermDecisions(mem.db, tenant.id, user.id, [
            { key: "service", version: 1, locale: "ko", agreed: true },
            { key: "privacy", version: 1, locale: "ko", agreed: true },
            { key: "marketing", version: 1, locale: "ko", agreed: false },
        ]);

        const rows = await mem.db.select().from(userTermAgreements);
        expect(rows).toHaveLength(3);
        expect(rows.filter((r) => r.agreed)).toHaveLength(2);
    });
});
