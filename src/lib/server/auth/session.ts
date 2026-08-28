import { and, desc, eq, gt, isNull, ne } from "drizzle-orm";
import type { Cookies } from "@sveltejs/kit";
import { dev } from "$app/environment";
import type { DB } from "$lib/server/db";
import { sessions, users } from "$lib/server/db/schema";
import { SESSION_COOKIE_NAME, SESSION_TTL_MS } from "./constants";

function bytesToBase64Url(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

async function hashSessionToken(token: string): Promise<string> {
    const data = new TextEncoder().encode(token);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return bytesToBase64Url(new Uint8Array(hash));
}

function cookieOptions(url: URL, expiresAt: Date) {
    return {
        path: "/",
        httpOnly: true,
        sameSite: "lax" as const,
        // ctrls M-COOKIE-1: 프로덕션 빌드에서는 관측된 protocol 과 무관하게 Secure 를 강제한다.
        // adapter-node 가 TLS 종단 프록시 뒤에서 평문 HTTP 로 요청을 받으면 url.protocol 이
        // "http:" 라 Secure 가 빠지고 세션 쿠키가 평문 전송될 수 있다. Workers 는 항상 https.
        secure: !dev || url.protocol === "https:",
        expires: expiresAt,
    };
}

export function createSessionToken(): string {
    return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function createSessionRecord(
    db: DB,
    params: {
        tenantId: string;
        userId: string;
        ip?: string | null;
        userAgent?: string | null;
        /** Authentication Methods References (RFC 8176), e.g. ['pwd'], ['pwd','totp'] */
        amr?: string[];
        /** Authentication Context Class Reference */
        acr?: string;
    },
) {
    const now = Date.now();
    const expiresAt = new Date(now + SESSION_TTL_MS);
    const sessionToken = createSessionToken();

    const tokenHash = await hashSessionToken(sessionToken);
    const sessionId = crypto.randomUUID();

    await db.insert(sessions).values({
        id: sessionId,
        tenantId: params.tenantId,
        userId: params.userId,
        idpSessionId: tokenHash,
        amr: params.amr ? params.amr.join(" ") : null,
        acr: params.acr ?? null,
        // 신규 세션은 생성 시각이 곧 인증 시각. 명시적으로 채워 두면 이후 step-up 승격이
        // 이 값만 갱신하고 createdAt 은 세션 시작 시각으로 보존된다.
        authTime: new Date(now),
        ip: params.ip ?? null,
        userAgent: params.userAgent ?? null,
        expiresAt,
        lastSeenAt: new Date(now),
    });

    return { sessionToken, expiresAt, sessionId };
}

/**
 * 지정한 세션을 제외한 동일 사용자의 모든 활성 세션을 무효화한다.
 * 셀프서비스 세션 관리 화면의 "다른 세션 모두 로그아웃" 에서 사용한다.
 * (로그인 시에는 호출하지 않는다 — 디바이스별 동시 세션을 허용한다.)
 */
export async function revokeOtherSessions(db: DB, userId: string, keepSessionId: string, revokedAt = new Date()) {
    await db
        .update(sessions)
        .set({ revokedAt })
        .where(and(eq(sessions.userId, userId), ne(sessions.id, keepSessionId), isNull(sessions.revokedAt)));
}

export interface ActiveSessionInfo {
    id: string;
    ip: string | null;
    userAgent: string | null;
    lastSeenAt: Date;
    createdAt: Date;
}

/**
 * 사용자의 활성(revokedAt IS NULL·미만료) 세션 목록을 최근 활동 순으로 반환한다.
 * 셀프서비스 세션 관리 화면에서 사용한다.
 */
export async function listActiveSessions(db: DB, userId: string): Promise<ActiveSessionInfo[]> {
    const now = new Date();
    return db
        .select({
            id: sessions.id,
            ip: sessions.ip,
            userAgent: sessions.userAgent,
            lastSeenAt: sessions.lastSeenAt,
            createdAt: sessions.createdAt,
        })
        .from(sessions)
        .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt), gt(sessions.expiresAt, now)))
        .orderBy(desc(sessions.lastSeenAt));
}

/**
 * `sessionId` + `userId` 가 **동시에 일치**하는 활성 세션만 폐기한다.
 *
 * IDOR 방지: userId 조건이 select·update 양쪽에 걸려 있어 다른 사용자의 sessionId 를
 * 넘겨도 어떤 행도 폐기되지 않는다. 이미 폐기된 세션은 건드리지 않는다(멱등).
 *
 * 반환값: 실제로 한 행을 폐기했으면 `true`, 대상이 없거나(타 사용자/미존재/이미 폐기) `false`.
 */
export async function revokeSessionById(db: DB, sessionId: string, userId: string, revokedAt = new Date()): Promise<boolean> {
    // 방언 독립적으로 "영향 행 존재" 를 판정하기 위해 소유·활성 가드를 건 select 로 먼저 확인한다.
    const [target] = await db
        .select({ id: sessions.id })
        .from(sessions)
        .where(and(eq(sessions.id, sessionId), eq(sessions.userId, userId), isNull(sessions.revokedAt)))
        .limit(1);
    if (!target) return false;

    await db
        .update(sessions)
        .set({ revokedAt })
        .where(and(eq(sessions.id, sessionId), eq(sessions.userId, userId), isNull(sessions.revokedAt)));
    return true;
}

export async function getSessionContext(db: DB, sessionToken: string, tenantId?: string) {
    const now = new Date();
    const tokenHash = await hashSessionToken(sessionToken);
    const [row] = await db
        .select({ session: sessions, user: users })
        .from(sessions)
        .innerJoin(users, eq(sessions.userId, users.id))
        .where(and(eq(sessions.idpSessionId, tokenHash), gt(sessions.expiresAt, now), isNull(sessions.revokedAt), eq(users.status, "active"), tenantId ? eq(sessions.tenantId, tenantId) : undefined))
        .limit(1);

    return row ?? null;
}

export async function touchSession(db: DB, sessionId: string, timestamp = new Date()) {
    await db.update(sessions).set({ lastSeenAt: timestamp }).where(eq(sessions.id, sessionId));
}

export async function revokeSession(db: DB, sessionToken: string, revokedAt = new Date()) {
    await db
        .update(sessions)
        .set({ revokedAt })
        .where(and(eq(sessions.idpSessionId, sessionToken), isNull(sessions.revokedAt)));
}

export async function revokeAllUserSessions(db: DB, userId: string, revokedAt = new Date()) {
    await db
        .update(sessions)
        .set({ revokedAt })
        .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)));
}

/**
 * 세션의 **인증 시각**. `authTime` 이 NULL 인 구행(컬럼 도입 전 세션)은 `createdAt` 으로 폴백한다.
 *
 * OIDC `auth_time` 클레임, `max_age` 판정, `prompt=login` 복귀 확인, SAML `isPostReauth` 판정이
 * 모두 이 값을 기준으로 해야 한다. `createdAt` 을 직접 읽으면 MFA step-up 으로 승격된 세션이
 * "옛날에 인증한 세션"으로 보여 재인증 요구가 영구히 충족되지 않는다(리다이렉트 루프).
 */
export function sessionAuthTime(session: { authTime: Date | null; createdAt: Date }): Date {
    return session.authTime ?? session.createdAt;
}

/**
 * MFA step-up 으로 **기존 세션의 인증 수단을 승격**한다. 세션 행을 새로 만들지 않는다.
 *
 * `sessions.id`(OIDC `sid` — ID 토큰과 로그아웃 통지가 함께 쓰는 값이자 oidc_grants·
 * oidc_refresh_tokens 의 FK)와 `idpSessionId`(세션 쿠키의 조회 키)를 **둘 다 유지**하는 것이 이
 * 함수의 핵심이다. 새 세션을 만들면 이미 로그인돼 있던 다른 RP 들의 세션 매핑이 끊기고, 기존
 * 행은 폐기되지 않아 유령 세션으로 남는다(로그인 재인증 경로의 기존 결함).
 *
 * 세션 쿠키를 회전시키지 않는 이유: 승격 대상 쿠키는 IdP 가 발급한 값이라 공격자가 지정할 수
 * 없어 세션 fixation 이 성립하지 않는다. 반대로 회전시키면 `idpSessionId` 가 바뀌어 이미 발급된
 * 세션 쿠키가 무효가 된다.
 *
 * `expiresAt` 은 늘리지 않는다 — 승격은 인증 수단의 상승이지 세션 수명의 갱신이 아니다.
 *
 * 반환값: 실제로 승격했으면 `true`. 대상이 없거나(타 사용자/미존재) 이미 폐기·만료면 `false`.
 * 소유(userId)·활성 조건을 select 와 update 양쪽에 걸어 IDOR 을 막는다.
 */
export async function elevateSession(
    db: DB,
    params: {
        sessionId: string;
        userId: string;
        /** 승격 후의 전체 AMR 목록 (기존 1차 인증 수단 + 새로 통과한 2차 수단). */
        amr: string[];
        acr: string;
        /** 인증 시각. 기본값은 호출 시점. */
        authTime?: Date;
    },
): Promise<boolean> {
    const now = new Date();
    const guard = and(eq(sessions.id, params.sessionId), eq(sessions.userId, params.userId), isNull(sessions.revokedAt), gt(sessions.expiresAt, now));

    // 방언 독립적으로 "영향 행 존재" 를 판정하기 위해 동일 가드를 건 select 로 먼저 확인한다
    // (revokeSessionById 와 같은 이유 — MySQL 은 UPDATE ... RETURNING 이 없다).
    const [target] = await db.select({ id: sessions.id }).from(sessions).where(guard).limit(1);
    if (!target) return false;

    await db
        .update(sessions)
        .set({
            amr: params.amr.join(" "),
            acr: params.acr,
            authTime: params.authTime ?? now,
            lastSeenAt: now,
        })
        .where(guard);
    return true;
}

export function setSessionCookie(cookies: Cookies, url: URL, sessionToken: string, expiresAt: Date) {
    cookies.set(SESSION_COOKIE_NAME, sessionToken, cookieOptions(url, expiresAt));
}

export function clearSessionCookie(cookies: Cookies, url: URL) {
    cookies.delete(SESSION_COOKIE_NAME, cookieOptions(url, new Date(0)));
}
