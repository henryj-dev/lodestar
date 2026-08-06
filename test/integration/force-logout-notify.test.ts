import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { forceLogout } from "../../src/lib/server/admin/user-actions/security";
import { b64uDecode } from "../../src/lib/server/crypto/keys";
import { oidcClients } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, seedOidcClient, seedServiceAssignment, seedSession, makeEvent, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Tenant, User } from "../../src/lib/server/db/schema";

// 관리자 "강제 로그아웃" 이 RP 에도 도달하는지.
//
// 이전에는 IdP 세션 + refresh token 만 끊고 back-channel logout 을 보내지 않았다. 그래서 자체
// 세션으로 인가를 들고 가는 RP 는 그대로 살아 있었다 — 버튼을 눌러도 아무 일도 일어나지 않고
// 아무도 그걸 모르는 형태의 고장. 게다가 기존 세션 단위 타깃 탐색은 grant/refresh 행에
// 의존하는데 그 행들은 단명하므로, offline_access 를 안 쓰는 RP 는 애초에 탐색되지도 않았다.

const BC_URI = "https://rp.test.example/backchannel-logout";

let mem: MemoryDb;
let tenant: Tenant;
let admin: User;
let target: User;
let captured: { url: string; body: string }[];
let originalFetch: typeof globalThis.fetch;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    admin = await seedUser(mem.db, { tenantId: tenant.id, email: "admin@test.example", role: "admin" });
    target = await seedUser(mem.db, { tenantId: tenant.id, email: "member@test.example" });

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

async function seedBcClient(opts: { clientId: string; sessionRequired?: boolean; allowAllUsers?: boolean }) {
    const client = await seedOidcClient(mem.db, {
        tenantId: tenant.id,
        clientId: opts.clientId,
        secret: "force-logout-secret-0123456789abcdef",
        redirectUris: ["https://rp.test.example/callback"],
    });
    await mem.db
        .update(oidcClients)
        .set({ backchannelLogoutUri: BC_URI, backchannelLogoutSessionRequired: opts.sessionRequired ?? false, allowAllUsers: opts.allowAllUsers ?? false })
        .where(eq(oidcClients.id, client.id));
    return client;
}

function adminEvent() {
    const event = makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/admin/users/${target.id}`,
        form: {},
        locals: { db: mem.db, tenant, user: admin, env: mem.env },
    });
    (event as unknown as { params: { id: string } }).params = { id: target.id };
    return event as Parameters<typeof forceLogout>[0];
}

function decodePayload(body: string): Record<string, unknown> {
    const token = new URLSearchParams(body).get("logout_token") ?? "";
    const [, p] = token.split(".");
    return JSON.parse(new TextDecoder().decode(b64uDecode(p))) as Record<string, unknown>;
}

describe("관리자 강제 로그아웃 → RP 통지", () => {
    it("배정된 클라이언트에 back-channel logout 을 보낸다", async () => {
        const client = await seedBcClient({ clientId: "assigned-client" });
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: target.id, serviceType: "oidc", serviceRefId: client.id });
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });

        const res = await forceLogout(adminEvent());

        expect(res).toMatchObject({ forcedLogout: true });
        expect(captured).toHaveLength(1);
        expect(captured[0].url).toBe(BC_URI);
        const payload = decodePayload(captured[0].body);
        expect(payload.sub).toBe(target.id);
        expect(payload.aud).toBe("assigned-client");
    });

    it("grant/refresh 행이 하나도 없어도 도달한다 (단명 행 의존 제거)", async () => {
        // 세션만 있고 oidcGrants/oidcRefreshTokens 는 비어 있는 상태 = grant 가 GC 된 뒤의 모습.
        // 세션 단위 탐색이었다면 여기서 타깃이 0건이라 아무것도 못 보낸다.
        const client = await seedBcClient({ clientId: "no-grant-client" });
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: target.id, serviceType: "oidc", serviceRefId: client.id });
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });

        await forceLogout(adminEvent());

        expect(captured).toHaveLength(1);
        expect(decodePayload(captured[0].body).aud).toBe("no-grant-client");
    });

    it("allowAllUsers 클라이언트는 배정이 없어도 대상이 된다", async () => {
        await seedBcClient({ clientId: "open-client", allowAllUsers: true });
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });

        await forceLogout(adminEvent());

        expect(captured).toHaveLength(1);
        expect(decodePayload(captured[0].body).aud).toBe("open-client");
    });

    it("배정도 allowAllUsers 도 없으면 보내지 않는다", async () => {
        await seedBcClient({ clientId: "unrelated-client" });
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });

        await forceLogout(adminEvent());

        expect(captured).toHaveLength(0);
    });

    it("sid 를 요구하는 클라이언트에는 세션마다 한 건씩 sid 를 실어 보낸다", async () => {
        const client = await seedBcClient({ clientId: "sid-client", sessionRequired: true });
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: target.id, serviceType: "oidc", serviceRefId: client.id });
        const a = await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });
        const b = await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });

        await forceLogout(adminEvent());

        expect(captured).toHaveLength(2);
        const sids = captured.map((c) => decodePayload(c.body).sid).sort();
        expect(sids).toEqual([a.session.idpSessionId, b.session.idpSessionId].sort());
    });

    it("주체 단위 클라이언트에는 sid 없이 한 건만 보낸다 (세션이 둘이어도)", async () => {
        const client = await seedBcClient({ clientId: "subject-client", sessionRequired: false });
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: target.id, serviceType: "oidc", serviceRefId: client.id });
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });

        await forceLogout(adminEvent());

        expect(captured).toHaveLength(1);
        const payload = decodePayload(captured[0].body);
        expect(payload.sid).toBeUndefined();
        expect(payload.sub).toBe(target.id);
    });

    it("비활성 클라이언트에는 보내지 않는다", async () => {
        const client = await seedBcClient({ clientId: "disabled-client" });
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: target.id, serviceType: "oidc", serviceRefId: client.id });
        await mem.db.update(oidcClients).set({ enabled: false }).where(eq(oidcClients.id, client.id));
        await seedSession(mem.db, { tenantId: tenant.id, userId: target.id });

        await forceLogout(adminEvent());

        expect(captured).toHaveLength(0);
    });
});
