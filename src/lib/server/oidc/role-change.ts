/**
 * OIDC Role-Change Security Event Token (SET) 발행.
 *
 * KeyStone(IdP)에서 관리자가 사용자의 서비스 role 을 변경(부여/회수)하면, back-channel
 * logout 과 **동일한 서명키·JWKS·SET 봉투**로 서명된 토큰을 대상 RP 의 `role_change_uri` 로
 * POST 한다. RP 는 세션을 끊지 않고 members.role 만 갱신하므로 재로그인 없이 다음 요청부터 반영된다.
 *
 * 계약(수신 RP 와 바이트 단위 일치):
 *   - 전송: Content-Type: application/x-www-form-urlencoded, body `role_change_token=<JWT>`
 *   - 서명: 테넌트 서명키 RS256 (RP 가 KeyStone JWKS 로 검증), typ=secevent+jwt
 *   - 클레임: iss / aud(=clientId) / iat / exp / txn / sub(=userId) / jti / events
 *   - events = { "https://idp.hyochan.site/event/role-change": { roles: string[], entitlements: string[] } }
 *   - nonce 금지 (RP 가 있으면 거부 — id_token 오용 방지)
 *
 * **`txn` 은 스냅샷 순서 표식이다(ms 단위 발행 시각 문자열).** 이 SET 은 델타가 아니라 변경 후
 * 전체 상태를 싣는데, 발행은 fire-and-forget 이고 재시도가 없어 두 변경이 짧은 간격으로 일어나면
 * 도착 순서가 뒤집힐 수 있다. 그러면 나중 상태(회수)를 먼저 적용하고 이전 상태(부여)를 나중에
 * 적용해 **회수가 조용히 되돌아간다.** `iat` 는 초 단위라 같은 초에 난 두 변경을 구분하지 못한다.
 * RP 는 마지막으로 적용한 `txn` 을 기억하고 그보다 작거나 같으면 버려야 한다.
 *
 * **`exp` 는 재생(replay) 상한이다.** 지연 도착한 오래된 스냅샷이 현재 상태를 덮지 않도록,
 * RP 는 만료된 SET 을 거부한다.
 *
 * `entitlements` 는 나중에 추가됐다. **같은 event 객체에 키를 하나 더한 것이라 하위 호환**이다 —
 * `roles` 만 읽던 기존 RP 는 영향이 없고, 새 RP 는 처음부터 두 키를 가정하고 만들면 된다
 * (권한 모델을 아직 안 쓰는 서비스에서는 항상 `[]`).
 *
 * **주체 단위(subject-scoped) 통지다.** payload 에 `sid` 가 없고 `sub` 만 있다 — 이 사용자의
 * 세션 전부에 적용하라는 뜻이다. 세션 단위 통지가 필요하면 back-channel logout(`logout.ts`)을 쓴다.
 *
 * back-channel logout 발행(`logout.ts`)을 그대로 본떠 만든다 — 새 서명 스킴/시크릿 불필요.
 */

import { and, eq, isNotNull } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { oidcClients } from "$lib/server/db/schema";
import { assertPublicWebhookUrl } from "$lib/server/oidc/logout";
import { assertResolvedHostAllowed } from "$lib/server/validation";
import { signJwt } from "$lib/server/crypto/keys";

/**
 * role-change SET 의 event 식별자. RP 상수(`ROLE_CHANGE_EVENT`)와 **바이트 단위로 일치**해야 한다.
 * 변경 시 RP 검증이 즉시 깨진다.
 */
export const ROLE_CHANGE_EVENT = "https://idp.hyochan.site/event/role-change";

/** SET 유효 기간(초). 지연 도착한 오래된 스냅샷의 재생을 막는다. */
const SET_TTL_S = 300;

export interface RoleChangeTarget {
    clientId: string;
    roleChangeUri: string;
}

/**
 * 배정 대상 OIDC 클라이언트(=assignment.serviceRefId = oidcClients.id) 1곳을 조회해,
 * enabled 이고 role_change_uri 가 설정돼 있으면 SET 발행 타깃을 반환한다. 아니면 null.
 *
 * logout 은 세션에 묶인 전 클라이언트가 대상이지만, role 변경은 **그 배정의 대상 클라이언트 1곳**만 통지한다.
 */
export async function getRoleChangeTarget(db: DB, tenantId: string, oidcClientDbId: string): Promise<RoleChangeTarget | null> {
    const [row] = await db
        .select({
            clientId: oidcClients.clientId,
            roleChangeUri: oidcClients.roleChangeUri,
        })
        .from(oidcClients)
        .where(and(eq(oidcClients.id, oidcClientDbId), eq(oidcClients.tenantId, tenantId), eq(oidcClients.enabled, true), isNotNull(oidcClients.roleChangeUri)))
        .limit(1);

    if (!row?.roleChangeUri) return null;
    return { clientId: row.clientId, roleChangeUri: row.roleChangeUri };
}

/**
 * 단일 role-change 타깃에 서명된 SET 을 POST 한다.
 * 네트워크/비정상 상태 코드는 호출자에서 swallow 하도록 래핑한다(logout 과 동일 — 재시도 없음).
 *
 * @param roles 변경 후의 **권위 있는 최종 roles** (부여→[role.key], 회수→[]).
 *              로그인 시 내려주는 roles 클레임과 완전히 동일한 값이어야 한다.
 * @param entitlements 변경 후의 **권위 있는 최종 entitlements** (없으면 []).
 *              roles 와 같은 규칙 — 로그인 시 내려주는 entitlements 클레임과 동일한 값이어야 한다.
 *              단, 클레임은 0개일 때 키를 생략하는 반면 여기서는 **항상 배열을 싣는다**:
 *              통지의 목적이 "변경 후 최종 상태"를 알리는 것이라, 빈 배열이 곧 "전부 회수됨"이라는
 *              정보다. 키를 빼면 RP 가 "변경 없음"과 구분할 수 없다.
 */
export async function sendRoleChangeSet(target: RoleChangeTarget, userId: string, roles: string[], entitlements: string[], issuerUrl: string, privateKey: CryptoKey, kid: string): Promise<void> {
    const nowMs = Date.now();
    const payload: Record<string, unknown> = {
        iss: issuerUrl,
        sub: userId,
        aud: target.clientId,
        iat: Math.floor(nowMs / 1000),
        exp: Math.floor(nowMs / 1000) + SET_TTL_S,
        // ms 단위 문자열. 초 단위 iat 로는 같은 초에 난 두 변경의 선후를 가릴 수 없다.
        txn: String(nowMs),
        jti: crypto.randomUUID(),
        events: { [ROLE_CHANGE_EVENT]: { roles, entitlements } },
    };

    // SET 관례상 typ=secevent+jwt. id_token 오용을 막기 위해 nonce 는 절대 넣지 않는다.
    const jwt = await signJwt(payload, privateKey, kid, { typ: "secevent+jwt" });
    const body = new URLSearchParams({ role_change_token: jwt });

    // ctrls M-1(SSRF): 등록 시 검증을 하더라도, 이전에 저장된 행이나 검증 우회 경로가
    // 내부 호스트로 서명된 SET 을 흘리지 않도록 fetch 직전 재검증(fail-closed).
    assertPublicWebhookUrl(target.roleChangeUri);
    // ctrls R7: DNS 리바인딩 완화 — 실호스트 해석 후 내부 IP 면 차단.
    await assertResolvedHostAllowed(new URL(target.roleChangeUri).hostname);

    await fetch(target.roleChangeUri, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
    });
}
