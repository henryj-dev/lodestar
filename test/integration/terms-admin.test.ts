import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { and, eq, isNull } from "drizzle-orm";
import { actions as termsActions, load as termsLoad } from "../../src/routes/admin/terms/+page.server";
import { actions as connectionsActions } from "../../src/routes/account/connections/+page.server";
import { adminError } from "../../src/lib/server/admin/errors";
import { clientTerms, oidcClients, oidcRefreshTokens, tenants, termsDocuments, userClientConsents } from "../../src/lib/server/db/schema";
import { getActiveConsent, recordConsent } from "../../src/lib/server/consent";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, seedMfaSession, seedOidcClient, makeEvent, makeCookieJar, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Session, Tenant, User } from "../../src/lib/server/db/schema";

// 관리 화면과 사용자 화면의 동작. 여기서 고정하는 성질:
//   - 발행 전(초안) 문서는 사용자에게 노출되지 않는다
//   - key·version 은 만든 뒤 바꿀 수 없다(동의 기록이 그것을 가리킨다)
//   - 매핑은 존재하는 key 만 걸 수 있다(오타로 아무 앱에도 안 뜨는 매핑 방지)
//   - 동의 철회는 행을 남기고 refresh token 을 폐기한다(C4-A)

let mem: MemoryDb;
let tenant: Tenant;
let admin: User;
let adminSession: Session;
let clientDbId: string;
let clientPublicId: string;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    admin = await seedUser(mem.db, { tenantId: tenant.id, email: "admin@test.example", username: "admin", role: "admin" });
    adminSession = (await seedMfaSession(mem.db, { tenantId: tenant.id, userId: admin.id })).session;
    const client = await seedOidcClient(mem.db, { tenantId: tenant.id, clientId: "terms-client", redirectUris: ["https://app.test.example/cb"] });
    clientDbId = client.id;
    clientPublicId = client.clientId;
});

afterEach(() => mem.close());

function adminEvent(form: Record<string, string>) {
    return makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/admin/terms`,
        headers: { Origin: TEST_ISSUER_URL },
        form,
        locals: { db: mem.db, tenant, user: admin, session: adminSession, env: mem.env },
    });
}

const docForm = (over: Record<string, string> = {}) => ({
    key: "service",
    version: "1",
    locale: "ko",
    title: "서비스 이용약관",
    body: "## 제1조\n\n본문",
    required: "true",
    displayOrder: "0",
    ...over,
});

async function docs() {
    return mem.db.select().from(termsDocuments).where(eq(termsDocuments.tenantId, tenant.id));
}

describe("약관 문서 관리", () => {
    it("문서를 만들면 초안 상태다 (발행해야 노출된다)", async () => {
        await termsActions.create!(adminEvent(docForm()));

        const [doc] = await docs();
        expect(doc.key).toBe("service");
        expect(doc.version).toBe(1);
        expect(doc.required).toBe(true);
        expect(doc.publishedAt).toBeNull();
    });

    it("필수 체크를 빼면 선택 약관이 된다", async () => {
        await termsActions.create!(adminEvent(docForm({ key: "marketing", required: "" })));
        expect((await docs())[0].required).toBe(false);
    });

    it("key 형식이 어긋나면 400", async () => {
        const r = (await termsActions.create!(adminEvent(docForm({ key: "안 되는 키!" })))) as { status: number; data: { error: string } };
        expect(r.status).toBe(400);
        expect(r.data.error).toBe(adminError("ko", "terms_key_invalid"));
        expect(await docs()).toHaveLength(0);
    });

    it("제목·본문이 비면 400", async () => {
        expect(((await termsActions.create!(adminEvent(docForm({ title: "" })))) as { status: number }).status).toBe(400);
        expect(((await termsActions.create!(adminEvent(docForm({ body: "" })))) as { status: number }).status).toBe(400);
        expect(await docs()).toHaveLength(0);
    });

    it("같은 key·version·locale 중복은 친절한 오류로 막는다 (예외가 아니라)", async () => {
        await termsActions.create!(adminEvent(docForm()));
        const r = (await termsActions.create!(adminEvent(docForm()))) as { status: number; data: { error: string } };

        // CRUD 팩토리는 beforeCreate 훅 실패를 400 으로 표준화한다(409 가 아니다). 중요한 것은
        // 유니크 위반이 그대로 올라와 500 이 되지 않고 관리자에게 읽을 수 있는 문구가 가는 것이다.
        expect(r.status).toBe(400);
        expect(r.data.error).toBe(adminError("ko", "terms_document_exists"));
        expect(await docs()).toHaveLength(1);
    });

    it("같은 key 라도 version 이 다르면 만들 수 있다 (개정)", async () => {
        await termsActions.create!(adminEvent(docForm({ version: "1" })));
        await termsActions.create!(adminEvent(docForm({ version: "2" })));
        expect((await docs()).map((d) => d.version).sort()).toEqual([1, 2]);
    });

    it("발행하면 publishedAt 이 채워지고, 취소하면 비워진다", async () => {
        await termsActions.create!(adminEvent(docForm()));
        const [doc] = await docs();

        await termsActions.publish!(adminEvent({ id: doc.id }));
        expect((await docs())[0].publishedAt).not.toBeNull();

        await termsActions.unpublish!(adminEvent({ id: doc.id }));
        expect((await docs())[0].publishedAt).toBeNull();
    });

    it("수정은 제목·본문·필수·순서만 바꾼다 (key·version 은 불변)", async () => {
        await termsActions.create!(adminEvent(docForm()));
        const [before] = await docs();

        await termsActions.update!(adminEvent({ id: before.id, title: "바뀐 제목", body: "새 본문", required: "", displayOrder: "5" }));

        const [after] = await docs();
        expect(after.title).toBe("바뀐 제목");
        expect(after.body).toBe("새 본문");
        expect(after.required).toBe(false);
        expect(after.displayOrder).toBe(5);
        // 동의 기록이 (key, version) 을 가리키므로 이 둘은 그대로여야 한다.
        expect(after.key).toBe(before.key);
        expect(after.version).toBe(before.version);
    });

    it("없는 id 로 발행하면 404", async () => {
        const r = (await termsActions.publish!(adminEvent({ id: crypto.randomUUID() }))) as { status: number };
        expect(r.status).toBe(404);
    });

    it("다른 테넌트의 문서는 발행할 수 없다", async () => {
        // FK 가 걸려 있으므로 실제 테넌트를 만들어야 한다.
        const otherTenantId = crypto.randomUUID();
        await mem.db.insert(tenants).values({ id: otherTenantId, name: "Other", slug: `other-${otherTenantId.slice(0, 8)}` });
        const id = crypto.randomUUID();
        await mem.db.insert(termsDocuments).values({ id, tenantId: otherTenantId, key: "other", version: 1, locale: "ko", title: "t", body: "b" });
        const r = (await termsActions.publish!(adminEvent({ id }))) as { status: number };
        expect(r.status).toBe(404);
    });
});

describe("앱별 매핑", () => {
    async function seedDoc() {
        await termsActions.create!(adminEvent(docForm()));
        return (await docs())[0];
    }

    it("존재하는 key 를 앱에 매핑한다", async () => {
        await seedDoc();
        expect(await termsActions.mapClient!(adminEvent({ termsKey: "service", clientType: "oidc", clientRefId: clientDbId }))).toEqual({ mapped: true });

        const [row] = await mem.db.select().from(clientTerms);
        expect(row.termsKey).toBe("service");
        expect(row.clientType).toBe("oidc");
    });

    it("없는 key 는 400 — 오타로 아무 앱에도 안 뜨는 매핑을 막는다", async () => {
        const r = (await termsActions.mapClient!(adminEvent({ termsKey: "typo", clientType: "oidc", clientRefId: clientDbId }))) as { status: number; data: { error: string } };
        expect(r.status).toBe(400);
        expect(r.data.error).toBe(adminError("ko", "terms_not_found"));
        expect(await mem.db.select().from(clientTerms)).toHaveLength(0);
    });

    it("같은 조합 중복 매핑은 409", async () => {
        await seedDoc();
        await termsActions.mapClient!(adminEvent({ termsKey: "service", clientType: "oidc", clientRefId: clientDbId }));
        const r = (await termsActions.mapClient!(adminEvent({ termsKey: "service", clientType: "oidc", clientRefId: clientDbId }))) as { status: number };
        expect(r.status).toBe(409);
        expect(await mem.db.select().from(clientTerms)).toHaveLength(1);
    });

    it("매핑을 해제한다", async () => {
        await seedDoc();
        await termsActions.mapClient!(adminEvent({ termsKey: "service", clientType: "oidc", clientRefId: clientDbId }));
        const [row] = await mem.db.select().from(clientTerms);

        expect(await termsActions.unmapClient!(adminEvent({ id: row.id }))).toEqual({ unmapped: true });
        expect(await mem.db.select().from(clientTerms)).toHaveLength(0);
    });

    it("load 는 문서·매핑·앱 목록을 함께 돌려준다", async () => {
        await seedDoc();
        await termsActions.mapClient!(adminEvent({ termsKey: "service", clientType: "oidc", clientRefId: clientDbId }));

        const data = (await termsLoad({ locals: { db: mem.db, tenant, user: admin, session: adminSession } } as never)) as unknown as {
            docs: unknown[];
            mappings: unknown[];
            oidcList: unknown[];
        };
        expect(data.docs).toHaveLength(1);
        expect(data.mappings).toHaveLength(1);
        expect(data.oidcList).toHaveLength(1);
    });
});

describe("동의 철회 (C4-A)", () => {
    let user: User;
    let session: Session;

    beforeEach(async () => {
        user = await seedUser(mem.db, { tenantId: tenant.id, email: "u@test.example", username: "u" });
        session = (await seedMfaSession(mem.db, { tenantId: tenant.id, userId: user.id })).session;
    });

    function userEvent(form: Record<string, string>, jar: ReturnType<typeof makeCookieJar>) {
        return makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/account/connections`,
            headers: { Origin: TEST_ISSUER_URL },
            form,
            cookies: jar.cookies,
            locals: { db: mem.db, tenant, user, session, env: mem.env },
        });
    }

    it("철회하면 활성 동의가 사라지지만 행은 남는다", async () => {
        await recordConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientType: "oidc", clientRefId: clientDbId }, ["openid", "profile"]);
        const jar = makeCookieJar();

        const result = await connectionsActions.revokeConsent!(userEvent({ clientType: "oidc", clientRefId: clientDbId }, jar));

        expect(result).toEqual({ consentRevoked: true });
        expect(await getActiveConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientType: "oidc", clientRefId: clientDbId })).toBeNull();
        const all = await mem.db.select().from(userClientConsents).where(eq(userClientConsents.userId, user.id));
        expect(all).toHaveLength(1);
        expect(all[0].revokedAt).not.toBeNull();
        expect(all[0].grantedScopes).toBe("openid profile"); // 무엇에 동의했었는지 보존
    });

    it("그 클라이언트의 refresh token 을 폐기한다", async () => {
        await recordConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientType: "oidc", clientRefId: clientDbId }, ["openid"]);
        await mem.db.insert(oidcRefreshTokens).values({
            tenantId: tenant.id,
            clientId: clientPublicId,
            userId: user.id,
            sessionId: session.id,
            tokenHash: "hash-1",
            scope: "openid",
            expiresAt: new Date(Date.now() + 86400000),
        });

        await connectionsActions.revokeConsent!(userEvent({ clientType: "oidc", clientRefId: clientDbId }, makeCookieJar()));

        const active = await mem.db
            .select()
            .from(oidcRefreshTokens)
            .where(and(eq(oidcRefreshTokens.userId, user.id), isNull(oidcRefreshTokens.revokedAt)));
        expect(active).toHaveLength(0);
    });

    it("다른 클라이언트의 refresh token 은 건드리지 않는다", async () => {
        const other = await seedOidcClient(mem.db, { tenantId: tenant.id, clientId: "other-client", redirectUris: ["https://o.test/cb"] });
        await recordConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientType: "oidc", clientRefId: clientDbId }, ["openid"]);
        for (const [cid, hash] of [
            [clientPublicId, "h-target"],
            [other.clientId, "h-other"],
        ]) {
            await mem.db.insert(oidcRefreshTokens).values({
                tenantId: tenant.id,
                clientId: cid,
                userId: user.id,
                sessionId: session.id,
                tokenHash: hash,
                scope: "openid",
                expiresAt: new Date(Date.now() + 86400000),
            });
        }

        await connectionsActions.revokeConsent!(userEvent({ clientType: "oidc", clientRefId: clientDbId }, makeCookieJar()));

        const active = await mem.db
            .select({ clientId: oidcRefreshTokens.clientId })
            .from(oidcRefreshTokens)
            .where(and(eq(oidcRefreshTokens.userId, user.id), isNull(oidcRefreshTokens.revokedAt)));
        expect(active.map((r) => r.clientId)).toEqual([other.clientId]);
    });

    it("세션은 끊지 않는다 (다른 RP 로 이미 로그인한 세션 보호)", async () => {
        await recordConsent(mem.db, { tenantId: tenant.id, userId: user.id, clientType: "oidc", clientRefId: clientDbId }, ["openid"]);

        await connectionsActions.revokeConsent!(userEvent({ clientType: "oidc", clientRefId: clientDbId }, makeCookieJar()));

        const [row] = await mem.db.select({ id: oidcClients.id }).from(oidcClients).where(eq(oidcClients.id, clientDbId));
        expect(row).toBeDefined(); // 클라이언트도 남아 있다
    });

    it("clientType 이 잘못되면 400", async () => {
        const r = (await connectionsActions.revokeConsent!(userEvent({ clientType: "ldap", clientRefId: clientDbId }, makeCookieJar()))) as { status: number };
        expect(r.status).toBe(400);
    });
});
