/**
 * OIDC Refresh Token 발급·회전.
 *
 * 정책:
 *   - raw 토큰은 저장하지 않고 SHA-256 해시만 DB(`oidc_refresh_tokens`)에 보관 —
 *     DB read 권한만으로는 토큰을 재구성할 수 없다 (authorization code 와 동일 정책).
 *   - 회전(rotation): 사용된 refresh token 은 즉시 revoke 하고 새 토큰을 발급한다.
 *     `revokedAt IS NULL` 가드가 걸린 원자적 UPDATE 로 old 토큰을 claim 하므로
 *     동시 사용은 단 하나만 성공한다.
 *   - 재사용 감지(breach detection): 이미 revoke 된 토큰(또는 동시 사용으로 claim 실패)이
 *     제출되면 해당 (user, client) 의 활성 refresh token 을 전부 폐기한다 (RFC 6819 §5.2.2.3).
 */

import { and, eq, isNull, lt } from "drizzle-orm";
import { type DB, DB_DIALECT } from "$lib/server/db";
import { runAtomic } from "$lib/server/db/atomic";
import { oidcRefreshTokens } from "$lib/server/db/schema";

export type OidcRefreshTokenRecord = typeof oidcRefreshTokens.$inferSelect;

export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30일

async function hashRefreshToken(token: string): Promise<string> {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    const bytes = new Uint8Array(buf);
    let hex = "";
    for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
    return hex;
}

function generateRefreshToken(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    // URL-safe base64 (RP 가 body 파라미터로 그대로 사용)
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface IssueRefreshTokenParams {
    tenantId: string;
    clientId: string;
    userId: string;
    sessionId: string | null;
    scope: string;
}

/** 새 refresh token 을 발급하고 raw 토큰 문자열을 반환한다. */
export async function issueRefreshToken(db: DB, params: IssueRefreshTokenParams): Promise<string> {
    const token = generateRefreshToken();
    const tokenHash = await hashRefreshToken(token);
    await db.insert(oidcRefreshTokens).values({
        id: crypto.randomUUID(),
        tenantId: params.tenantId,
        clientId: params.clientId,
        userId: params.userId,
        sessionId: params.sessionId,
        tokenHash,
        scope: params.scope,
        expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
    });
    return token;
}

/** (user, client) 의 활성 refresh token 을 전부 폐기 (재사용/침해 감지, 세션 만료 시). */
export async function revokeRefreshTokenFamily(db: DB, tenantId: string, userId: string, clientId: string): Promise<void> {
    await db
        .update(oidcRefreshTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(oidcRefreshTokens.tenantId, tenantId), eq(oidcRefreshTokens.userId, userId), eq(oidcRefreshTokens.clientId, clientId), isNull(oidcRefreshTokens.revokedAt)));
}

/** 특정 IdP 세션에 묶인 활성 refresh token 을 전부 폐기 (로그아웃 시). */
export async function revokeRefreshTokensForSession(db: DB, sessionId: string): Promise<void> {
    await db
        .update(oidcRefreshTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(oidcRefreshTokens.sessionId, sessionId), isNull(oidcRefreshTokens.revokedAt)));
}

/**
 * 한 사용자의 **특정 클라이언트** 활성 refresh token 을 폐기 (동의 철회 시).
 *
 * 철회가 실질적 효과를 가지려면 갱신 경로를 끊어야 한다(C4-A). 이미 발급된 access token 은
 * 만료까지 유효하다 — 즉시 무효화하려면 introspection 을 쓰는 RP 여야 하고, 그건 RP 선택이다.
 * 세션까지 끊지는 않는다: 다른 RP 로 이미 로그인한 세션을 함께 날리는 것은 과하다.
 *
 * `clientId` 는 **공개 client_id 문자열**이다(refresh token 이 그 값으로 저장된다) — 동의 기록의
 * `clientRefId`(행 id)와 다르므로 호출부가 변환해서 넘긴다.
 */
export async function revokeRefreshTokensForUserClient(db: DB, tenantId: string, userId: string, clientId: string): Promise<void> {
    await db
        .update(oidcRefreshTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(oidcRefreshTokens.tenantId, tenantId), eq(oidcRefreshTokens.userId, userId), eq(oidcRefreshTokens.clientId, clientId), isNull(oidcRefreshTokens.revokedAt)));
}

/** 사용자의 활성 refresh token 을 전부 폐기 (비밀번호 재설정·권한 변경 등 전역 무효화 시). */
export async function revokeAllUserRefreshTokens(db: DB, userId: string): Promise<void> {
    await db
        .update(oidcRefreshTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(oidcRefreshTokens.userId, userId), isNull(oidcRefreshTokens.revokedAt)));
}

/**
 * raw refresh token 값으로 활성(미폐기·미만료) 레코드를 조회한다. (introspection 용)
 * 존재하지만 폐기/만료면 null 을 반환한다.
 */
export async function findActiveRefreshToken(db: DB, tenantId: string, clientId: string, presentedToken: string): Promise<OidcRefreshTokenRecord | null> {
    const tokenHash = await hashRefreshToken(presentedToken);
    const [record] = await db
        .select()
        .from(oidcRefreshTokens)
        .where(and(eq(oidcRefreshTokens.tokenHash, tokenHash), eq(oidcRefreshTokens.tenantId, tenantId), eq(oidcRefreshTokens.clientId, clientId)))
        .limit(1);
    if (!record) return null;
    if (record.revokedAt) return null;
    if (record.expiresAt.getTime() < Date.now()) return null;
    return record;
}

/**
 * raw refresh token 값으로 해당 토큰을 폐기한다 (RFC 7009 revocation).
 * 토큰이 없거나 이미 폐기됐어도 조용히 성공 처리한다 (revocation 은 멱등).
 */
export async function revokeRefreshTokenByValue(db: DB, tenantId: string, clientId: string, presentedToken: string): Promise<void> {
    const tokenHash = await hashRefreshToken(presentedToken);
    await db
        .update(oidcRefreshTokens)
        .set({ revokedAt: new Date() })
        .where(and(eq(oidcRefreshTokens.tokenHash, tokenHash), eq(oidcRefreshTokens.tenantId, tenantId), eq(oidcRefreshTokens.clientId, clientId), isNull(oidcRefreshTokens.revokedAt)));
}

export type RotateResult = { ok: true; record: OidcRefreshTokenRecord; newToken: string } | { ok: false; reason: "invalid_grant" | "expired" | "reuse" };

/**
 * 제출된 refresh token 을 검증하고 회전한다.
 * 성공 시 old 토큰을 revoke(+replacedById) 하고 새 raw 토큰과 원본 레코드를 반환한다.
 */
export async function rotateRefreshToken(db: DB, tenantId: string, clientId: string, presentedToken: string): Promise<RotateResult> {
    const tokenHash = await hashRefreshToken(presentedToken);
    const [record] = await db
        .select()
        .from(oidcRefreshTokens)
        .where(and(eq(oidcRefreshTokens.tokenHash, tokenHash), eq(oidcRefreshTokens.tenantId, tenantId), eq(oidcRefreshTokens.clientId, clientId)))
        .limit(1);

    if (!record) return { ok: false, reason: "invalid_grant" };

    // 이미 revoke 된 토큰의 재사용 → 침해 가능성. family 전체 폐기 후 거부.
    if (record.revokedAt) {
        await revokeRefreshTokenFamily(db, tenantId, record.userId, clientId);
        return { ok: false, reason: "reuse" };
    }
    if (record.expiresAt.getTime() < Date.now()) return { ok: false, reason: "expired" };

    const now = new Date();
    const newId = crypto.randomUUID();
    const newToken = generateRefreshToken();
    const newHash = await hashRefreshToken(newToken);

    // old 토큰 claim(revokedAt IS NULL 가드) 과 new 토큰 insert 를 하나의 원자 단위로 실행한다.
    //
    // 동시성 시맨틱: claim UPDATE 가 실제로 한 행을 revoke 했는가(비-mysql RETURNING rows,
    // mysql affectedRows)가 동시 회전 경쟁의 승자를 결정한다 — revokedAt IS NULL 가드로
    // 동시 요청 중 단 하나만 claim 에 성공한다. (기존 시맨틱 그대로 보존)
    //
    // 원자성: claim 과 insert 를 같은 batch/transaction 에 묶어 부분 적용을 제거한다.
    // insert 가 실패하면 claim 도 함께 rollback 되므로, 기존에 존재하던 "claim 성공 +
    // insert 실패 → old-revoked·new-부재(세션 유실)" 창이 사라진다. 이 창이 닫히는 것은
    // batch(d1/sqlite)·transaction(pg/mysql) 모두 중간 실패 시 전체 rollback 하기 때문이다.
    //
    // 경쟁 패자 처리: batch 는 앞 문장 결과로 뒤 문장을 조건 분기할 수 없으므로 insert 는
    // 항상 실행된다. 패자(claim 0행)의 요청도 new 토큰을 삽입하지만, 이 raw 값은 호출자에게
    // 반환되지 않고(never handed out) 곧바로 아래 family 폐기로 승자 토큰과 함께 무효화된다
    // — 재사용 감지 시맨틱(RFC 6819 §5.2.2.3)과 결과가 동일하다.
    const claimWhere = and(eq(oidcRefreshTokens.id, record.id), isNull(oidcRefreshTokens.revokedAt));
    const buildClaim = (h: Pick<DB, "update">) => {
        const builder = h.update(oidcRefreshTokens).set({ revokedAt: now, replacedById: newId }).where(claimWhere);
        // mysql 은 UPDATE ... RETURNING 미지원 → affectedRows 로 승자 판정. 그 외 방언은 RETURNING.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return DB_DIALECT === "mysql" ? builder : (builder as any).returning({ id: oidcRefreshTokens.id });
    };
    const buildInsert = (h: Pick<DB, "insert">) =>
        h.insert(oidcRefreshTokens).values({
            id: newId,
            tenantId,
            clientId,
            userId: record.userId,
            sessionId: record.sessionId,
            tokenHash: newHash,
            scope: record.scope,
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
        });

    // claim 이 index 0 → 결과 배열 첫 항목이 claim 결과. insert 실패는 여기서 throw 되어
    // (rollback 후) 호출자로 전파된다 — old 토큰은 원복되어 재시도 가능하다.
    const [claimResult] = await runAtomic(db, [buildClaim, buildInsert]);
    const claimed =
        DB_DIALECT === "mysql" ? Boolean((claimResult as [{ affectedRows: number }] | undefined)?.[0]?.affectedRows) : ((claimResult as Array<{ id: string }> | undefined) ?? []).length > 0;

    if (!claimed) {
        // 이미 다른 요청이 회전 → 동시 재사용으로 간주하고 family 폐기.
        // (위 insert 로 삽입된 new 토큰도 활성 상태이므로 family 폐기에 함께 무효화된다.)
        await revokeRefreshTokenFamily(db, tenantId, record.userId, clientId);
        return { ok: false, reason: "reuse" };
    }

    return { ok: true, record, newToken };
}

/** 만료된 refresh token 레코드를 정리 (주기적 호출용). */
export async function purgeExpiredRefreshTokens(db: DB): Promise<void> {
    await db.delete(oidcRefreshTokens).where(lt(oidcRefreshTokens.expiresAt, new Date()));
}
