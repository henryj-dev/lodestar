import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { actions as acceptInviteActions } from "../../src/routes/(auth)/accept-invite/+page.server";
import { generateToken } from "../../src/lib/server/email";
import { authenticateLocalUser } from "../../src/lib/server/auth/users";
import { credentials, inviteTokens, users } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, makeEvent, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Tenant, User } from "../../src/lib/server/db/schema";

// Phase 7: 초대 수락 → credential(비밀번호) 생성 + emailVerifiedAt 세팅 + 토큰 소진 → 로그인 가능.
// 실제 accept-invite default 액션과 authenticateLocalUser 를 실 DB 로 검증한다.

let mem: MemoryDb;
let tenant: Tenant;
let invitee: User;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    // 초대 대상: 비밀번호 credential 없음 + 이메일 미인증 상태로 생성
    invitee = await seedUser(mem.db, {
        tenantId: tenant.id,
        email: "invitee@test.example",
        username: "invitee",
        emailVerifiedAt: null,
    });
});

afterEach(() => mem.close());

/** 실제 issueInvite 와 동일한 방식(generateToken → inviteTokens insert)으로 유효 초대 토큰을 만든다. */
async function makeInvite(userId: string): Promise<string> {
    const { token, tokenHash } = await generateToken();
    await mem.db.insert(inviteTokens).values({ userId, tokenHash, expiresAt: new Date(Date.now() + 60 * 60 * 1000) });
    return token;
}

describe("Phase 7 — 초대 수락", () => {
    it("초대 수락이 password credential 생성 + emailVerifiedAt 세팅 + 토큰 소진을 원자적으로 수행하고, 이후 로그인 가능하다", async () => {
        const token = await makeInvite(invitee.id);

        const event = makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/accept-invite`,
            form: { token, password: "New-strong-password1", confirmPassword: "New-strong-password1" },
            locals: { db: mem.db, tenant, env: mem.env },
        });
        const result = await acceptInviteActions.default(event);
        expect(result).toEqual({ accepted: true });

        // password credential 생성 확인
        const cred = await mem.db.select().from(credentials).where(eq(credentials.userId, invitee.id));
        expect(cred.length).toBe(1);
        expect(cred[0].type).toBe("password");
        expect(cred[0].secret).toBeTruthy();

        // emailVerifiedAt 세팅 확인(초대 클릭 = 이메일 소유 증명)
        const [u] = await mem.db.select().from(users).where(eq(users.id, invitee.id)).limit(1);
        expect(u.emailVerifiedAt).not.toBeNull();

        // 토큰 소진 확인
        const [tok] = await mem.db.select().from(inviteTokens).where(eq(inviteTokens.userId, invitee.id)).limit(1);
        expect(tok.usedAt).not.toBeNull();

        // 실제 로컬 인증으로 로그인 가능(설정한 비밀번호로 통과)
        const authed = await authenticateLocalUser(mem.db, tenant.id, "invitee", "New-strong-password1");
        expect(authed?.id).toBe(invitee.id);
    });

    it("비밀번호 확인 불일치는 400 으로 거부하고 credential 을 만들지 않는다", async () => {
        const token = await makeInvite(invitee.id);
        const event = makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/accept-invite`,
            form: { token, password: "abcdefgh", confirmPassword: "different" },
            locals: { db: mem.db, tenant, env: mem.env },
        });
        const result = (await acceptInviteActions.default(event)) as { status?: number };
        expect(result.status).toBe(400);
        const cred = await mem.db.select().from(credentials).where(eq(credentials.userId, invitee.id));
        expect(cred.length).toBe(0);
    });

    it("소진된 토큰은 재사용할 수 없다", async () => {
        const token = await makeInvite(invitee.id);
        const mkEvent = () =>
            makeEvent({
                method: "POST",
                url: `${TEST_ISSUER_URL}/accept-invite`,
                form: { token, password: "first-password-1", confirmPassword: "first-password-1" },
                locals: { db: mem.db, tenant, env: mem.env },
            });
        expect(await acceptInviteActions.default(mkEvent())).toEqual({ accepted: true });
        // 두 번째 제출: 토큰이 이미 소진됨 → invalid_link 400
        const second = (await acceptInviteActions.default(mkEvent())) as { status?: number };
        expect(second.status).toBe(400);
    });
});
