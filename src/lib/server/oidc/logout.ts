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
import { oidcClients, oidcGrants, oidcRefreshTokens, userServiceAssignments } from "$lib/server/db/schema";
import { signJwt } from "$lib/server/crypto/keys";
import { isForbiddenWebhookHost, assertResolvedHostAllowed } from "$lib/server/validation";

/**
 * ctrls M-1(SSRF): IdP 가 서버측에서 직접 fetch 하는 아웃바운드 웹훅(backchannel logout,
 * role-change) URL 이 https 이고 내부/loopback/메타데이터 호스트가 아닌지 fetch 직전에
 * 재검증한다. 등록 시 검증을 우회했거나 이전에 저장된 행을 방어하는 최종 게이트.
 * 위반 시 throw — 호출자는 개별 콜백 오류를 swallow 하므로 해당 타깃만 스킵된다.
 */
export function assertPublicWebhookUrl(raw: string): void {
    let parsed: URL;
    try {
        parsed = new URL(raw);
    } catch {
        throw new Error(`webhook URL invalid: ${raw}`);
    }
    if (parsed.protocol !== "https:") {
        throw new Error(`webhook URL must be https: ${raw}`);
    }
    if (isForbiddenWebhookHost(parsed.hostname)) {
        throw new Error(`webhook URL host is forbidden (SSRF guard): ${parsed.hostname}`);
    }
}

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

    const clientIds = Array.from(new Set([...grantClientIds.map((r) => r.clientId), ...refreshClientIds.map((r) => r.clientId)]));
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

    const clientIds = Array.from(new Set([...grantClientIds.map((r) => r.clientId), ...refreshClientIds.map((r) => r.clientId)]));
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
export async function sendOneBackchannelLogout(target: BackchannelTarget, userId: string, idpSessionId: string, issuerUrl: string, privateKey: CryptoKey, kid: string): Promise<void> {
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

    // ctrls M-1(SSRF): fetch 직전 재검증(fail-closed).
    assertPublicWebhookUrl(target.backchannelLogoutUri);
    // ctrls R7: DNS 리바인딩 완화 — 실호스트 해석 후 내부 IP 면 차단(발행 실패는 상위에서 삼킴).
    await assertResolvedHostAllowed(new URL(target.backchannelLogoutUri).hostname);

    await fetch(target.backchannelLogoutUri, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
    });
}
