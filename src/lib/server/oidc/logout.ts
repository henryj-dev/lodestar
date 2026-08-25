/**
 * OIDC Single Logout helpers (Front-channel 1.0 + Back-channel 1.0).
 *
 * Back-channel (BC):
 *   - IdP POSTs signed logout_token (JWT) to clients' `backchannel_logout_uri`.
 *   - 세션 단위 target set = 이 IdP 세션에 묶인 grant/refresh_token 이 있는 클라이언트.
 *   - **주체 단위** target set(`getOidcBackchannelTargetsForUser`) = 이 사용자가 접근 가능한
 *     클라이언트 전부. 관리자 강제 로그아웃처럼 세션 하나가 아니라 사용자를 대상으로 할 때 쓴다.
 *
 * Front-channel (FC):
 *   - IdP renders <iframe src=<frontchannel_logout_uri>?iss=...&sid=...> for each client.
 *   - Same target-set strategy as BC.
 */

import { and, eq, gt, inArray, isNotNull, isNull, or } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { oidcClientSessions, oidcClients, oidcGrants, oidcRefreshTokens, userServiceAssignments } from "$lib/server/db/schema";
import { signJwt } from "$lib/server/crypto/keys";
import { postOidcWebhook, type OidcWebhookQueue } from "$lib/server/oidc/webhook-fetch";

export interface BackchannelTarget {
    clientId: string;
    backchannelLogoutUri: string;
    backchannelLogoutSessionRequired: boolean;
}

export interface FrontchannelTarget {
    uri: string;
}

/**
 * 이 IdP 세션에 묶여 있는 활성 grant/refresh_token 이 있는 OIDC 클라이언트 중,
 * backchannel_logout_uri 가 설정된 클라이언트를 반환한다.
 */
export async function getOidcBackchannelTargets(db: DB, tenantId: string, sessionId: string): Promise<BackchannelTarget[]> {
    const grantClientIds = await db
        .select({ clientId: oidcGrants.clientId })
        .from(oidcGrants)
        .where(and(eq(oidcGrants.tenantId, tenantId), eq(oidcGrants.sessionId, sessionId)));
    const refreshClientIds = await db
        .select({ clientId: oidcRefreshTokens.clientId })
        .from(oidcRefreshTokens)
        .where(and(eq(oidcRefreshTokens.tenantId, tenantId), eq(oidcRefreshTokens.sessionId, sessionId), isNull(oidcRefreshTokens.revokedAt)));

    // 기록 테이블도 함께 본다. grant/refresh 로만 찾던 것을 **대체하지 않고 합집합**으로 두는 이유는
    // 이 테이블이 생기기 전에 만들어진 세션에는 기록이 없기 때문이다(그쪽은 기존 경로로 계속 찾힌다).
    const trackedClientIds = await db
        .select({ clientId: oidcClientSessions.clientId })
        .from(oidcClientSessions)
        .where(and(eq(oidcClientSessions.tenantId, tenantId), eq(oidcClientSessions.sessionId, sessionId)));

    const clientIds = Array.from(new Set([...grantClientIds.map((r) => r.clientId), ...refreshClientIds.map((r) => r.clientId), ...trackedClientIds.map((r) => r.clientId)]));
    if (clientIds.length === 0) return [];

    const rows = await db
        .select({
            clientId: oidcClients.clientId,
            backchannelLogoutUri: oidcClients.backchannelLogoutUri,
            backchannelLogoutSessionRequired: oidcClients.backchannelLogoutSessionRequired,
        })
        .from(oidcClients)
        .where(and(eq(oidcClients.tenantId, tenantId), inArray(oidcClients.clientId, clientIds), eq(oidcClients.enabled, true), isNotNull(oidcClients.backchannelLogoutUri)));

    const targets: BackchannelTarget[] = [];
    for (const row of rows) {
        if (!row.backchannelLogoutUri) continue;
        targets.push({
            clientId: row.clientId,
            backchannelLogoutUri: row.backchannelLogoutUri,
            backchannelLogoutSessionRequired: row.backchannelLogoutSessionRequired,
        });
    }
    return targets;
}

/**
 * 토큰 발급 시 (IdP 세션 ↔ 클라이언트) 연결을 남긴다. 로그아웃 통지 대상을 나중에 찾기 위한 것.
 *
 * 같은 세션·클라이언트로 여러 번 발급(코드 교환 후 refresh 회전 등)되므로 두 번째부터는 unique
 * 위반이 나는데, 그것은 "이미 기록됨" 이라 삼킨다. 기록 실패가 토큰 발급을 막아서는 안 되므로
 * 그 외 오류도 삼킨다 — 최악의 경우 이 세션이 로그아웃 통지를 못 받을 뿐이고, 그건 이 테이블이
 * 생기기 전의 동작과 같다.
 */
export async function recordClientSession(db: DB, tenantId: string, sessionId: string | null, clientId: string): Promise<void> {
    if (!sessionId) return;
    try {
        await db.insert(oidcClientSessions).values({ id: crypto.randomUUID(), tenantId, sessionId, clientId });
    } catch {
        /* 중복이거나 기록 실패 — 발급을 막지 않는다 */
    }
}

/**
 * **주체 단위** back-channel logout 타깃 — 이 사용자가 접근 가능한 모든 OIDC 클라이언트 중
 * backchannel_logout_uri 가 설정된 것.
 *
 * 세션 단위(`getOidcBackchannelTargets`)와 달리 **단명 행에 의존하지 않는다.** 그쪽은 대상을
 * `oidcGrants`(authorization code, 수 분 TTL — GC 가 삭제한다) 또는 미폐기 `oidcRefreshTokens`
 * (`offline_access` scope 가 있어야 발급)로만 찾기 때문에, **offline_access 를 쓰지 않고 자체
 * 세션을 오래 유지하는 RP 는 grant 가 GC 된 뒤 아예 탐색되지 않는다.** 관리자 강제 로그아웃처럼
 * "이 사용자를 지금 전부 로그아웃시킨다" 는 의도에는 그 탐색이 맞지 않는다.
 *
 * 대신 SSO 게이트와 같은 기준을 쓴다 — 사용자가 클라이언트에 로그인할 수 있는 경로는 둘뿐이다:
 *   1. 활성 서비스 배정(`user_service_assignments`)이 있거나
 *   2. 클라이언트가 `allowAllUsers` 라 배정 없이도 허용되거나
 * 따라서 이 둘의 합집합이 "세션이 있을 수 있는 클라이언트" 전부를 덮는다.
 *
 * 세션을 실제로 가진 적 없는 클라이언트에도 갈 수 있는데, 그 경우 RP 는 없는 세션을 끊으려다
 * no-op 이 된다(OIDC BC logout 규격상 허용). 못 보내는 것보다 낫다.
 */
export async function getOidcBackchannelTargetsForUser(db: DB, tenantId: string, userId: string): Promise<BackchannelTarget[]> {
    const now = new Date();
    const assigned = await db
        .select({ serviceRefId: userServiceAssignments.serviceRefId })
        .from(userServiceAssignments)
        .where(
            and(
                eq(userServiceAssignments.tenantId, tenantId),
                eq(userServiceAssignments.userId, userId),
                eq(userServiceAssignments.serviceType, "oidc"),
                or(isNull(userServiceAssignments.expiresAt), gt(userServiceAssignments.expiresAt, now)),
            ),
        );
    const assignedDbIds = assigned.map((a) => a.serviceRefId);

    // 배정 대상(oidcClients.id) 이거나 allowAllUsers 인 클라이언트.
    const rows = await db
        .select({
            clientId: oidcClients.clientId,
            backchannelLogoutUri: oidcClients.backchannelLogoutUri,
            backchannelLogoutSessionRequired: oidcClients.backchannelLogoutSessionRequired,
        })
        .from(oidcClients)
        .where(
            and(
                eq(oidcClients.tenantId, tenantId),
                eq(oidcClients.enabled, true),
                isNotNull(oidcClients.backchannelLogoutUri),
                assignedDbIds.length > 0 ? or(eq(oidcClients.allowAllUsers, true), inArray(oidcClients.id, assignedDbIds)) : eq(oidcClients.allowAllUsers, true),
            ),
        );

    const targets: BackchannelTarget[] = [];
    for (const row of rows) {
        if (!row.backchannelLogoutUri) continue;
        targets.push({
            clientId: row.clientId,
            backchannelLogoutUri: row.backchannelLogoutUri,
            backchannelLogoutSessionRequired: row.backchannelLogoutSessionRequired,
        });
    }
    return targets;
}

/**
 * 이 IdP 세션에 묶여 있는 활성 grant/refresh_token 이 있는 OIDC 클라이언트 중,
 * frontchannel_logout_uri 가 설정된 클라이언트의 iframe URL 목록을 반환한다.
 * frontchannelLogoutSessionRequired=true 인 클라이언트에만 sid 쿼리 파라미터를 추가한다.
 */
export async function getOidcFrontchannelTargets(db: DB, tenantId: string, sessionId: string, idpSessionId: string, issuerUrl: string): Promise<FrontchannelTarget[]> {
    const grantClientIds = await db
        .select({ clientId: oidcGrants.clientId })
        .from(oidcGrants)
        .where(and(eq(oidcGrants.tenantId, tenantId), eq(oidcGrants.sessionId, sessionId)));
    const refreshClientIds = await db
        .select({ clientId: oidcRefreshTokens.clientId })
        .from(oidcRefreshTokens)
        .where(and(eq(oidcRefreshTokens.tenantId, tenantId), eq(oidcRefreshTokens.sessionId, sessionId), isNull(oidcRefreshTokens.revokedAt)));

    const trackedClientIds = await db
        .select({ clientId: oidcClientSessions.clientId })
        .from(oidcClientSessions)
        .where(and(eq(oidcClientSessions.tenantId, tenantId), eq(oidcClientSessions.sessionId, sessionId)));

    const clientIds = Array.from(new Set([...grantClientIds.map((r) => r.clientId), ...refreshClientIds.map((r) => r.clientId), ...trackedClientIds.map((r) => r.clientId)]));
    if (clientIds.length === 0) return [];

    const rows = await db
        .select({
            frontchannelLogoutUri: oidcClients.frontchannelLogoutUri,
            frontchannelLogoutSessionRequired: oidcClients.frontchannelLogoutSessionRequired,
        })
        .from(oidcClients)
        .where(and(eq(oidcClients.tenantId, tenantId), inArray(oidcClients.clientId, clientIds), eq(oidcClients.enabled, true), isNotNull(oidcClients.frontchannelLogoutUri)));

    const targets: FrontchannelTarget[] = [];
    for (const row of rows) {
        if (!row.frontchannelLogoutUri) continue;
        const base = row.frontchannelLogoutUri;
        const sep = base.includes("?") ? "&" : "?";
        let uri = `${base}${sep}iss=${encodeURIComponent(issuerUrl)}`;
        if (row.frontchannelLogoutSessionRequired) {
            uri += `&sid=${encodeURIComponent(idpSessionId)}`;
        }
        targets.push({ uri });
    }
    return targets;
}

/**
 * 단일 OIDC BC 타깃에 logout_token 을 POST 한다.
 * 네트워크 오류는 호출자에서 swallow 하도록 래핑하고, 여기서는 정상 경로에 대한
 * 검증만 수행한다 (비정상 상태 코드도 RP 측 문제이므로 IdP 는 재시도하지 않는다).
 */
export async function sendOneBackchannelLogout(
    target: BackchannelTarget,
    userId: string,
    idpSessionId: string,
    issuerUrl: string,
    privateKey: CryptoKey,
    kid: string,
    queue?: OidcWebhookQueue,
): Promise<{ status: number; durationMs: number }> {
    const payload: Record<string, unknown> = {
        iss: issuerUrl,
        sub: userId,
        aud: target.clientId,
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(),
        events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    };
    if (target.backchannelLogoutSessionRequired) {
        payload.sid = idpSessionId;
    }

    // BC logout JWT 는 일반 ID Token 과 구별되어야 하므로 typ=logout+jwt (RFC: OpenID BC logout 1.0)
    const jwt = await signJwt(payload, privateKey, kid, { typ: "logout+jwt" });
    const body = new URLSearchParams({ logout_token: jwt });

    return postOidcWebhook(target.backchannelLogoutUri, body.toString(), { queue });
}
