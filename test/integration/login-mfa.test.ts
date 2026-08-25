import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq, and } from "drizzle-orm";
import { actions as loginActions } from "../../src/routes/(auth)/login/+page.server";
import { actions as mfaActions } from "../../src/routes/(auth)/mfa/+page.server";
import { credentials, sessions } from "../../src/lib/server/db/schema";
import { encryptTotpSecret, generateTotpCode, generateTotpSecret, hashBackupCode } from "../../src/lib/server/auth/totp";
import { TOTP_CREDENTIAL_TYPE, BACKUP_CODE_CREDENTIAL_TYPE } from "../../src/lib/server/auth/constants";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, makeEvent, makeCookieJar, catchRedirect, TEST_ISSUER_URL, TEST_SIGNING_SECRET, type MemoryDb } from "./harness";
import type { Tenant, User } from "../../src/lib/server/db/schema";

// 로그인(비밀번호) → idp_mfa_pending 발급 → MFA(TOTP/백업코드) → idp_session 발급을,
// 같은 쿠키(브라우저) 인스턴스로 체이닝해 실 DB + 실 라우트 액션으로 검증한다.

const MFA_PENDING_COOKIE = "idp_mfa_pending";
const SESSION_COOKIE = "idp_session";
const PASSWORD = "mfa-user-strong-password";

let mem: MemoryDb;
let tenant: Tenant;
let user: User;
let totpSecret: string;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    user = await seedUser(mem.db, {
        tenantId: tenant.id,
        email: "mfauser@test.example",
        username: "mfauser",
        password: PASSWORD,
        displayName: "MFA User",
    });
    // TOTP credential 등록(현행 v2 암호문 — signingKeySecret + userId 바인딩).
    totpSecret = generateTotpSecret();
    await mem.db.insert(credentials).values({
        id: crypto.randomUUID(),
        userId: user.id,
        type: TOTP_CREDENTIAL_TYPE,
        secret: await encryptTotpSecret(totpSecret, TEST_SIGNING_SECRET, user.id),
        label: "authenticator",
    });
});

afterEach(() => mem.close());

/** 비밀번호 로그인 액션을 실행한다(옵션 쿠키 재사용). */
function loginEvent(cookies: ReturnType<typeof makeCookieJar>["cookies"], form: Record<string, string>) {
    return makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/login`,
        form,
        locals: { db: mem.db, tenant, env: mem.env },
        cookies,
    });
}

function mfaEvent(cookies: ReturnType<typeof makeCookieJar>["cookies"], form: Record<string, string>) {
    return makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/mfa`,
        form,
        locals: { db: mem.db, tenant, env: mem.env },
        cookies,
    });
}

describe("로그인 → MFA 체이닝", () => {
    it("비밀번호 로그인이 MFA 대기 쿠키를 발급하고, 올바른 TOTP 로 세션이 발급된다(동일 쿠키 체이닝)", async () => {
        const jar = makeCookieJar();

        // 1) 비밀번호 로그인 → /mfa 로 리다이렉트 + idp_mfa_pending 쿠키 발급(세션 미발급)
        const step1 = await catchRedirect(() => loginActions.default(loginEvent(jar.cookies, { username: "mfauser", password: PASSWORD })));
        expect(step1.status).toBe(303);
        expect(step1.location).toBe("/mfa");
        expect(jar.has(MFA_PENDING_COOKIE)).toBe(true);
        expect(jar.has(SESSION_COOKIE)).toBe(false);
        // 아직 세션 row 없음
        expect((await mem.db.select().from(sessions).where(eq(sessions.userId, user.id))).length).toBe(0);

        // 2) 같은 쿠키로 MFA(TOTP) 제출 → idp_session 발급 + MFA 대기 쿠키 소거
        const code = await generateTotpCode(totpSecret);
        const step2 = await catchRedirect(() => mfaActions.default(mfaEvent(jar.cookies, { code })));
        expect(step2.status).toBe(303);
        expect(step2.location).toBe("/"); // 일반 사용자 기본 랜딩
        expect(jar.has(SESSION_COOKIE)).toBe(true);
        expect(jar.has(MFA_PENDING_COOKIE)).toBe(false);

        // 세션 row 가 생성되고 amr 에 pwd+otp 가 기록되어야 한다.
        const rows = await mem.db.select().from(sessions).where(eq(sessions.userId, user.id));
        expect(rows.length).toBe(1);
        expect(rows[0].amr).toContain("totp");
        expect(rows[0].amr).toContain("pwd");
    });

    it("잘못된 TOTP 코드는 400 으로 거부하고 세션을 발급하지 않는다", async () => {
        const jar = makeCookieJar();
        await catchRedirect(() => loginActions.default(loginEvent(jar.cookies, { username: "mfauser", password: PASSWORD })));

        // 유효 코드와 다른(그리고 현재/인접 스텝과 겹치지 않는) 코드 사용.
        const valid = await generateTotpCode(totpSecret);
        const wrong = valid === "000000" ? "999999" : "000000";
        const res = (await mfaActions.default(mfaEvent(jar.cookies, { code: wrong }))) as { status?: number; data?: unknown };
        expect(res.status).toBe(400);
        expect(jar.has(SESSION_COOKIE)).toBe(false);
        expect((await mem.db.select().from(sessions).where(eq(sessions.userId, user.id))).length).toBe(0);
    });

    it("백업 코드로도 MFA 를 통과해 세션이 발급된다", { timeout: 15_000 }, async () => {
        // 미사용 백업코드 credential 하나 등록.
        const backupCode = "ABCD2345";
        await mem.db.insert(credentials).values({
            id: crypto.randomUUID(),
            userId: user.id,
            type: BACKUP_CODE_CREDENTIAL_TYPE,
            secret: await hashBackupCode(backupCode),
            label: "backup",
        });

        const jar = makeCookieJar();
        await catchRedirect(() => loginActions.default(loginEvent(jar.cookies, { username: "mfauser", password: PASSWORD })));

        const step2 = await catchRedirect(() => mfaActions.default(mfaEvent(jar.cookies, { code: backupCode, use_backup: "1" })));
        expect(step2.status).toBe(303);
        expect(jar.has(SESSION_COOKIE)).toBe(true);

        // 사용된 백업코드는 소진(usedAt) 처리되어야 한다.
        const [bc] = await mem.db
            .select()
            .from(credentials)
            .where(and(eq(credentials.userId, user.id), eq(credentials.type, BACKUP_CODE_CREDENTIAL_TYPE)))
            .limit(1);
        expect(bc.usedAt).not.toBeNull();

        // 세션 amr 에 백업코드(swk) 방식이 반영되어야 한다.
        const rows = await mem.db.select().from(sessions).where(eq(sessions.userId, user.id));
        expect(rows.length).toBe(1);
        expect(rows[0].amr).toContain("swk");
    });

    it("같은 TOTP 코드를 동시에 제출해도 한 요청만 성공한다", { timeout: 15_000 }, async () => {
        const firstJar = makeCookieJar();
        await catchRedirect(() => loginActions.default(loginEvent(firstJar.cookies, { username: "mfauser", password: PASSWORD })));
        const pendingCookies = firstJar.snapshot();
        const code = await generateTotpCode(totpSecret);

        const results = await Promise.all([0, 1].map((i) => catchRedirect(() => mfaActions.default(mfaEvent(makeCookieJar(pendingCookies).cookies, { code }))).catch((error) => ({ error, i }))));

        expect(results.filter((result) => "status" in result && result.status === 303)).toHaveLength(1);
        expect(results.filter((result) => !("status" in result && result.status === 303))).toHaveLength(1);
    });

    it("같은 백업 코드를 동시에 제출해도 한 요청만 성공한다", { timeout: 15_000 }, async () => {
        const backupCode = "EFGH2345";
        await mem.db.insert(credentials).values({
            id: crypto.randomUUID(),
            userId: user.id,
            type: BACKUP_CODE_CREDENTIAL_TYPE,
            secret: await hashBackupCode(backupCode),
            label: "backup",
        });

        const firstJar = makeCookieJar();
        await catchRedirect(() => loginActions.default(loginEvent(firstJar.cookies, { username: "mfauser", password: PASSWORD })));
        const pendingCookies = firstJar.snapshot();
        const results = await Promise.all(
            [0, 1].map(() => catchRedirect(() => mfaActions.default(mfaEvent(makeCookieJar(pendingCookies).cookies, { code: backupCode, use_backup: "1" }))).catch((error) => ({ error }))),
        );

        expect(results.filter((result) => "status" in result && result.status === 303)).toHaveLength(1);
        expect(results.filter((result) => !("status" in result && result.status === 303))).toHaveLength(1);
    });

    // 11회 순차 로그인은 시도마다 scrypt 검증 + 실패 타이밍 균등화 지연이 누적되므로 기본 5s 로는 부족하다.
    it("로그인 IP 레이트리밋: 임계(10회/15분) 초과 시 429 로 차단한다", { timeout: 30_000 }, async () => {
        const jar = makeCookieJar();
        // 잘못된 비밀번호로 10회 시도(모두 400), 11회째는 IP 레이트리밋으로 429.
        for (let i = 0; i < 10; i++) {
            const r = (await loginActions.default(loginEvent(jar.cookies, { username: "mfauser", password: "wrong-password" }))) as { status?: number };
            expect(r.status).toBe(400);
        }
        const over = (await loginActions.default(loginEvent(jar.cookies, { username: "mfauser", password: "wrong-password" }))) as { status?: number };
        expect(over.status).toBe(429);
    });
});
