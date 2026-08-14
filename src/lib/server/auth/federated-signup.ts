/**
 * 연합 회원가입 — 외부 IdP 로 인증했지만 매칭 계정이 없던 사용자의 계정 생성 (계획서 §2.8).
 *
 * ── 신뢰 규칙 (이 파일의 존재 이유) ───────────────────────────────────────────
 * `provider` / `subject` / `emailVerified` 는 **오직 `claims`(서명 쿠키)에서만** 읽는다.
 * `input`(폼)에서 오는 값은 사용자가 정당하게 고를 수 있는 것에만 쓴다:
 *   - username        : 항상 사용자 선택 (LDAP 처럼 고정인 경우 claims 가 지시)
 *   - email           : **프로바이더가 미검증인 경우에만** 사용자 입력을 채택
 *   - password        : 선택 사항
 *
 * 프로바이더가 검증했다고 단언한 이메일을 폼 값으로 덮어쓸 수 있게 두면, 공격자가
 * 자기 소셜 계정으로 로그인한 뒤 임의 이메일을 주장할 수 있게 된다.
 */

import { and, eq } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { credentials, identities, users, type User } from "$lib/server/db/schema";
import { runAtomic, type AtomicOp } from "$lib/server/db/atomic";
import { isUniqueViolation } from "$lib/server/db/errors";
import { hashPassword, MAX_PASSWORD_LENGTH } from "./password";
import { isBreachCheckEnabled, isPasswordBreached } from "./breach-check";
import { issueEmailVerification } from "./email-verification";
import type { PendingLinkClaims } from "./pending-link";
import type { Locale } from "$lib/i18n/core";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_REGEX = /^[a-z0-9_]{3,32}$/;

export interface FederatedSignupInput {
    username: string;
    email: string;
    password: string;
    confirmPassword: string;
}

export type FederatedSignupResult =
    | { ok: true; user: User }
    /** `errorKey` 는 i18n 키(전체 경로), `status` 는 HTTP 상태. */
    | { ok: false; status: number; errorKey: string; params?: Record<string, string | number> };

function fail(status: number, errorKey: string, params?: Record<string, string | number>): FederatedSignupResult {
    return { ok: false, status, errorKey, params };
}

/**
 * 폼 입력과 pending 토큰을 합쳐 계정을 만든다.
 *
 * 성공 시 호출부는 pending 쿠키를 삭제하고 세션을 발급해야 한다.
 */
export async function createFederatedAccount(db: DB, claims: PendingLinkClaims, input: FederatedSignupInput, locale: Locale, platform: App.Platform | undefined): Promise<FederatedSignupResult> {
    const tenantId = claims.tenantId;

    // ── username ───────────────────────────────────────────────────────────────
    // 사용자가 고칠 수 없는 프로바이더(LDAP)면 토큰 값을 쓴다. 폼 값은 무시한다.
    const username = (claims.allowUsernameEdit ? input.username : (claims.suggestedUsername ?? "")).trim().toLowerCase();
    if (!username) return fail(400, "signup.err_missing_fields");
    if (!USERNAME_REGEX.test(username)) return fail(400, "signup.err_invalid_username");

    // ── email ──────────────────────────────────────────────────────────────────
    // 프로바이더가 검증을 단언했으면 그 값이 확정이다. 폼 입력은 쳐다보지 않는다.
    const providerVerifiedEmail = claims.emailVerified && claims.email ? claims.email.toLowerCase() : null;
    const email = providerVerifiedEmail ?? input.email.trim().toLowerCase();

    if (!email) return fail(400, "signup.err_missing_fields");
    if (!EMAIL_REGEX.test(email)) return fail(400, "signup.err_invalid_email");

    // ── password (선택) ────────────────────────────────────────────────────────
    // 비밀번호를 설정하지 않으면 credentials 행 없이 identities 행만 남는다.
    // `guards.ts` 의 로그인 가능 판정이 identities 도 인정하므로 정상 동작한다.
    const wantsPassword = claims.allowPassword && input.password.length > 0;
    let hashedPw: string | null = null;

    if (wantsPassword) {
        if (input.password.length < 8) return fail(400, "signup.err_password_short");
        if (input.password.length > MAX_PASSWORD_LENGTH) return fail(400, "errors.password_too_long", { max: MAX_PASSWORD_LENGTH });
        if (input.password !== input.confirmPassword) return fail(400, "signup.err_password_mismatch");
        if (isBreachCheckEnabled() && (await isPasswordBreached(input.password))) return fail(400, "signup.err_password_breached");
        hashedPw = await hashPassword(input.password);
    }

    // ── 중복 검사 ──────────────────────────────────────────────────────────────
    const [usernameTaken] = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.username, username)))
        .limit(1);
    if (usernameTaken) return fail(409, "signup.err_username_taken");

    // 이메일이 이미 있으면 **병합하지 않는다**. 검증된 이메일이라도 마찬가지다 —
    // 여기서 자동 병합을 허용하면 콜백 단계(§2.4)의 자동 연결 금지가 무의미해진다.
    const [emailTaken] = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.email, email)))
        .limit(1);
    if (emailTaken) return fail(409, "signup.err_federated_email_taken");

    // ── 생성 ───────────────────────────────────────────────────────────────────
    const userId = crypto.randomUUID();
    const now = new Date();
    const emailVerified = providerVerifiedEmail !== null;

    const ops: AtomicOp[] = [
        (h) =>
            h.insert(users).values({
                id: userId,
                tenantId,
                username,
                email,
                // 프로바이더가 검증한 이메일은 재확인을 요구하지 않는다.
                emailVerifiedAt: emailVerified ? now : null,
                displayName: claims.displayName?.trim() || username,
                givenName: claims.givenName,
                familyName: claims.familyName,
                role: "user",
                status: "active",
            }),
        (h) =>
            h.insert(identities).values({
                tenantId,
                userId,
                provider: claims.provider,
                subject: claims.subject,
                email,
                linkedAt: now,
                lastLoginAt: now,
            }),
    ];

    if (hashedPw) {
        ops.push((h) => h.insert(credentials).values({ userId, type: "password", secret: hashedPw, label: "비밀번호", createdAt: now }));
    }

    try {
        await runAtomic(db, ops);
    } catch (e) {
        // 같은 pending 토큰으로 두 번 제출됐거나(더블 클릭/두 탭), username·email 을
        // 동시에 선점당한 경우. identities 의 (tenant, provider, subject) unique 가
        // 중복 계정을 막아준다. 사용자에게는 다시 로그인하도록 안내한다.
        if (isUniqueViolation(e)) return fail(409, "signup.err_federated_conflict");
        throw e;
    }

    // 프로바이더가 검증하지 않은 이메일은 KeyStone 이 직접 확인한다.
    if (!emailVerified) {
        await issueEmailVerification(db, userId, email, locale, platform);
    }

    const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (!user) return fail(500, "errors.db_not_ready");

    return { ok: true, user };
}
