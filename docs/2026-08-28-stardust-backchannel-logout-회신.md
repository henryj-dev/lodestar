# stardust back-channel logout E2E 확인 요청 — 회신

작성일: 2026-08-28
발신: henryj-dev/lodestar (구 KeyStone)
수신: tiny-universe/stardust
원문: [2026-08-25-stardust-backchannel-logout-e2e-확인-요청.md](./2026-08-25-stardust-backchannel-logout-e2e-확인-요청.md)

## 요약

코드 검토로 확인한 결과, **`sid` 값 불일치라는 잠재 결함이 있었고 이번에 고쳤습니다.** 다만 이것이
2026-08-25 관측한 실패의 원인은 **아닙니다** — stardust 클라이언트가 `backchannel_logout_session_required=false`
로 등록돼 있어 Lodestar 가 `sid` 를 애초에 보내지 않기 때문입니다.

운영 DB 를 볼 수 없어 확인 항목 1~7 중 일부는 답하지 못했습니다. 아래에 확인한 것과 확인하지 못한 것을
구분해 적었습니다.

## 고친 것 — `sid` 값 불일치

Lodestar 는 ID 토큰의 `sid` 클레임과 로그아웃 통지의 `sid` 에 **서로 다른 값**을 넣고 있었습니다.

| 위치                           | 이전 값                                    | 현재 값       |
| ------------------------------ | ------------------------------------------ | ------------- |
| ID 토큰 `sid`                  | `sessions.id` (UUID 36자)                  | `sessions.id` |
| 프론트채널 로그아웃 `sid` 쿼리 | `sessions.idp_session_id` (base64url 43자) | `sessions.id` |
| 백채널 `logout_token` 의 `sid` | `sessions.idp_session_id`                  | `sessions.id` |

`idp_session_id` 는 세션 토큰의 SHA-256 해시로, Lodestar 내부의 세션 조회 키입니다. RP 에 내보낼 값이
아니었고, ID 토큰의 `sid` 와도 달랐습니다.

**stardust 입장에서 의미:** `session_required=true` 로 올리는 순간 터졌을 결함입니다. 원문 「권고 순서」
5단계가 바로 그 변경이므로, 그 경로에 놓여 있던 지뢰가 제거된 것으로 보시면 됩니다.

- `dashboard/src/routes/auth/callback/+server.ts:83` 이 ID 토큰의 `sid`(UUID)를 읽어 세션 쿠키와
  `session_bindings` 에 저장합니다.
- 이전 Lodestar 는 logout_token 에 해시를 실었으므로 `revokeSessionInTx(tx, su.id, body.sid)` 가
  `(user_id, 해시)` 로 기록되고, `findSessionRevocation` 의 `sid IN ('', UUID)` 는 그 행을 찾지 못합니다.
- 지금은 세 값이 모두 `sessions.id` 로 같으므로 `session_bindings` 조회와 `session_revocations` 매칭이
  전부 맞습니다.

이 계약은 회귀 테스트로 고정했습니다 — ID 토큰의 `sid` 와 logout_token 의 `sid` 가 같고
`idp_session_id` 가 **아님**을 확인합니다(`test/integration/sid-admin-authninstant.test.ts`).

## 관측된 실패의 원인은 아닙니다 — 정정

원문의 등록값 확인에 `backchannel_logout_session_required: false` 로 적혀 있습니다. 이 모드에서
Lodestar 는 `sid` 를 **아예 넣지 않습니다.**

```ts
// src/lib/server/oidc/logout.ts
if (target.backchannelLogoutSessionRequired) {
    payload.sid = sid;
}
```

그러면 stardust 경로는 이렇게 흐릅니다.

1. logout_token 에 `sub` 만 있고 `sid` 없음 → `backchannel-logout/+server.ts:114` 의
   `!claims.sub && !claims.sid` 통과.
2. dispatcher 로 `idp_sub` 만 전달 → `parseLogoutReplayInput` 이 `sid: null` 로 정규화.
3. `revokeSessionInTx(tx, su.id, body.sid ?? "")` → `(user_id, '')` 로 기록.
4. `findSessionRevocation` 이 `WHERE user_id = ? AND sid IN ('', ?)` + `MAX(revoked_at)` 이므로
   **`''` 행을 찾습니다.**

즉 이 경로 자체는 정상 동작합니다. 저희가 처음에 "sid 불일치가 지금의 실패 원인"이라고 판단했는데,
`findSessionRevocation` 의 `sid IN ('', ?)` 를 확인하고 그 판단을 철회했습니다.

## 확인 항목에 대한 답

원문의 7개 항목 중 코드로 답할 수 있는 것만 답합니다. 운영 DB·로그 접근이 필요한 항목은 확인하지
못했습니다.

| #   | 항목                               | 답변                                                                                     |
| --- | ---------------------------------- | ---------------------------------------------------------------------------------------- |
| 1   | client `enabled=true` 여부         | **확인 불가** (운영 DB)                                                                  |
| 2   | `backchannel_logout_uri` 일치      | **확인 불가** (운영 DB)                                                                  |
| 3   | 세션에 grant/refresh 연결 여부     | 아래 「대상 조회 구조」 참고 — 원문이 지적한 구조적 누락은 **이미 보강돼 있습니다**      |
| 4   | end-session 처리 중 대상 선정 여부 | 코드상 선정 로직은 확인. 실제 선정 결과는 **확인 불가**                                  |
| 5   | Logout Token POST 시도 여부        | **확인 불가** (감사 로그 `backchannel_logout_sent` 조회 필요)                            |
| 6   | 응답 코드 / 네트워크 거절          | **확인 불가**. 시도는 `backchannel_logout_sent` 감사 이벤트에 상태코드와 함께 기록됩니다 |
| 7   | signing key 존재 여부              | **확인 불가**. 없으면 발송 자체를 건너뜁니다(아래)                                       |

### 대상 조회 구조 (항목 3)

원문의 지적은 정확했습니다.

> 현재 KeyStone 구현의 세션 단위 target 조회는 해당 IdP 세션에 연결된 grant 또는 refresh token이 있는
> client만 대상으로 삼는 구조이므로, client 등록값만 존재하고 세션 연결이 없으면 발송 대상에서 빠질 수
> 있다.

이후 `oidc_client_sessions` 추적이 추가되어 보강됐습니다. 토큰 발급 시
`recordClientSession()`(`src/routes/oidc/token/+server.ts:206`)이 세션↔클라이언트 관계를 따로 남기고,
대상 조회는 **grant · refresh token · 이 기록의 합집합**을 봅니다. grant 가 GC 된 뒤에도 대상으로
잡히는지는 `test/integration/session-logout-durability.test.ts` 가 고정합니다.

관측일(2026-08-25) 시점에 이 기록이 있었는지는 배포 시점에 따라 다릅니다. **재현 테스트를 다시 한 번
해 주시면** 이 후보를 배제할 수 있습니다.

### 발송을 건너뛰는 조건 (항목 5·7)

`executeLogout` 은 다음 중 하나라도 참이면 백채널 발송을 조용히 건너뜁니다. 감사 로그에
`backchannel_logout_sent` 이벤트가 **아예 없다면** 이 중 하나입니다.

- 대상 클라이언트가 0개 (위 「대상 조회 구조」)
- `signingKeySecrets` 가 비어 있음 (`IDP_SIGNING_KEY_SECRET` 미설정)
- 활성 서명 키가 없음 (`getActiveSigningKey` 가 null)

발송을 시도했다면 성공·실패 모두 `backchannel_logout_sent` 감사 이벤트에 상태코드와 함께 남습니다.
`/admin/audit` 에서 kind 로 필터하면 보입니다.

### 남은 후보 — `users/lookup` 서비스 토큰

`session_required=false` 경로에서 dispatcher 는 `sid` 바인딩 없이 `lookupUser({ id: idp_sub })` 로
Lodestar 의 `/api/users/lookup` 을 호출합니다(`admin.routes.ts:361`). 이 API 는 `users.lookup` 스코프를
가진 서비스 토큰을 요구하므로, 토큰이 없거나 스코프가 빠지면 502 로 끊기고 `oidc_logout_failures` 에
`idp lookup failed` 로 기록됩니다. 원문에서 "실패 요청이 `oidc_logout_failures` 에 영속 기록됨" 은
확인했다고 하셨으니, **그 표의 최근 행에 `error` 값이 무엇인지** 보시면 바로 갈립니다.

## 권고

1. **`oidc_logout_failures` 의 최근 행 `error` 를 먼저 보십시오.** `idp lookup failed` 면 서비스 토큰
   문제이고, 비어 있으면 발송 자체가 없었던 것입니다.
2. Lodestar `/admin/audit` 에서 `backchannel_logout_sent` 를 조회해 발송 시도 유무와 상태코드를
   확인하십시오. 이벤트가 없으면 대상 선정 또는 서명 키 문제입니다.
3. 위가 해소된 뒤 **`backchannel_logout_session_required=true` 로 올리는 것을 검토하십시오.** 이제
   `sid` 가 ID 토큰과 일치하므로 안전합니다. 다만 `false` 는 "이 사용자의 세션 전부"를 끊는 주체 단위
   폐기이고 `true` 는 세션 하나만 끊는 것이므로, **원하는 의미를 먼저 정하셔야 합니다.** 관리자 강제
   로그아웃의 의도가 "이 사람의 모든 세션 종료"라면 `false` 가 오히려 맞습니다.

## 함께 바뀐 것

같은 작업에서 다음도 함께 반영했습니다. stardust 에 영향은 없다고 판단했지만 알려 둡니다.

- **`/admin` 콘솔이 MFA 세션을 요구**합니다. stardust 는 Lodestar 콘솔을 쓰지 않으므로 무관합니다.
- **SAML `AuthnInstant`** 가 응답 발급 시각에서 실제 세션 인증 시각으로 바뀌었습니다. stardust 는 SAML
  SP 가 아니므로 무관합니다.
- **OIDC `auth_time`** 이 `sessions.created_at` 대신 마지막 인증 시각(`sessions.auth_time`)을 반영합니다.
  stardust dashboard 는 `auth_time` 을 읽지 않으므로(코드 검색 결과 사용처 없음) 무관합니다.
- **클라이언트별 재인증 정책**(`require_mfa` / `reauth_policy`)이 추가됐습니다. 기본값이 각각 꺼짐 ·
  `full` 이라 등록된 클라이언트의 동작은 변하지 않습니다.
