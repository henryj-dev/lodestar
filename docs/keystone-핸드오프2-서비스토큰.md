# KeyStone 핸드오프 ② — 서비스 API 토큰을 스코프 있는 것으로

작성 2026-08-06 · 근거: KeyStone `feat/workers-vpc-db` @ e45b80d 실측
비교 대상: stardust `dispatcher/src/cert-token.ts` (별도 저장소, 같은 운영자)

---

## 이 문서를 받는 사람에게

heliopause 콘솔에 OTP 승인을 붙이면서 `POST /api/totp/verify` 를 부르게 됐고, 그러려면
`DISPATCHER_SERVICE_TOKEN` 이 필요합니다. **그 토큰을 받는 것이 생각보다 큰 권한을 받는 일**이라는
것을 확인했고, 그 관찰을 정리합니다.

**진행을 막는 이야기가 아닙니다.** 저희는 이 토큰으로 지금 진행하려 합니다 — 아래 3절에서 왜
감수할 만한지 적었습니다. 다만 감수한다는 것과 괜찮다는 것은 다르므로 남깁니다.

이 문서는 첫 핸드오프(`keystone-핸드오프.md`)와 독립입니다. entitlement 작업과 겹치지 않습니다.

---

## 1. 지금 상태

```
env DISPATCHER_SERVICE_TOKEN  →  runtimeConfig.dispatcherServiceToken   (runtime.ts:24,52)
requireServiceToken()         →  constant-time 문자열 비교              (auth/service-token.ts)
```

**단일 공유 시크릿**이고, 발급 UI 가 없으며, 이 하나로 다섯 개가 열립니다.

| 엔드포인트                 | heliopause 에 필요한가 |
| -------------------------- | ---------------------- |
| `/api/totp/verify`         | **예 — 이것만**        |
| `/api/totp/status`         | 아니오                 |
| `/api/totp/enroll/init`    | 아니오                 |
| `/api/totp/enroll/confirm` | 아니오                 |
| `/api/users/lookup`        | 아니오                 |

잘 만들어진 부분이 있다는 것도 적어 둡니다 — 실패 시도는 IP 단위 rate-limit(5분 20회)에
감사 이벤트(`service_token_rejected`)까지 남고, 토큰 미설정이면 503 으로 **인증 우회를 자동
거부**합니다. 문제는 토큰의 *모양*이지 검증의 품질이 아닙니다.

---

## 2. 셋이 걸립니다

### 2-1. 감사가 호출자를 구분하지 못합니다

토큰이 하나이므로 `/api/totp/verify` 호출이 dispatcher 에서 왔는지 heliopause 에서 왔는지
**구별할 방법이 없습니다.** 그리고 성공 호출은 애초에 감사에 남지 않습니다 — `service-token.ts`
의 감사 호출 두 곳은 모두 실패 경로입니다.

heliopause 에서 이 호출은 **방화벽 변경 승인의 2단계 검증**입니다. "누가 언제 이 사람의 OTP 를
검증했는가" 는 사고 조사에서 물어볼 질문인데, 지금은 답이 "서비스 토큰을 가진 누군가" 입니다.

### 2-2. 회전이 전부 아니면 전무입니다

토큰이 유출되면 바꿔야 하는데, 바꾸는 순간 **그것을 쓰는 모든 서비스가 동시에 끊깁니다.**
지금은 dispatcher 하나라 티가 안 나지만 heliopause 가 둘째가 됩니다. 셋째가 생기면 회전은
조율이 필요한 작업이 되고, 조율이 필요한 보안 조치는 미뤄집니다.

### 2-3. 최소권한이 아닙니다

heliopause 는 `/api/totp/verify` 하나만 필요한데 다섯 개를 받습니다. 특히 `enroll/*` 은
**2단계를 검증하는 주체가 2단계를 새로 만들 수도 있게** 합니다.

---

## 3. 그럼에도 지금 진행하는 이유 — 확인해 봤습니다

처음엔 2-3 이 치명적이라고 봤습니다. heliopause 에서 OTP 는 **최고관리자 단독 승인의 보상 통제**
입니다(두 사람 규칙을 그 역할에 한해 끕니다). 매니저가 침해됐을 때 OTP 를 스스로 만들어낼 수
있다면 그 통제가 무너집니다.

**확인해 보니 아니었습니다.**

```
enroll/init    이미 등록돼 있으면 409     (init/+server.ts:45)
enroll/confirm 이미 등록돼 있으면 409     (confirm/+server.ts:53)
```

**둘 다 덮어쓰지 않습니다.** 이미 TOTP 를 등록한 사용자의 2단계를 갈아치울 수 없으므로, 매니저가
침해돼도 보상 통제가 유지됩니다. 이 설계 판단에 감사드립니다 — 저희 위협 모델이 여기 걸려
있었는데 이미 막혀 있었습니다.

남는 노출은 둘이고, 둘 다 감수 가능하다고 봤습니다.

- **미등록 사용자에게 TOTP 를 등록시킬 수 있다.** 그 사람 명의로 승인하려면 역할 배정이 따로
  필요하므로 단독으로는 권한 상승이 되지 않습니다.
- **`/api/users/lookup` 으로 사용자를 조회할 수 있다.** 방화벽 제어 평면이 이미 전 VPC 의 호스트와
  열린 포트를 열거할 수 있다는 점을 생각하면 상대적으로 작습니다.

---

## 4. 제안 — 이미 있는 설계를 옮기는 일입니다

새로 발명할 것이 없습니다. **stardust dispatcher 가 같은 문제를 이미 풀었습니다**
(`dispatcher/src/cert-token.ts`). 별도 저장소지만 같은 운영자가 돌리는 시스템이고, 모양이 그대로
맞습니다.

```
cert_api_tokens          id · token_hash(sha256) · label · created_by · expires_at · revoked_at · last_used_at
cert_api_token_scopes    token_id → cert_name (다대다)

발급   평문은 반환값에 1회만. DB 엔 해시 + 스코프
검증   해시 조회 → 폐기·만료 확인 → 스코프 대조 → last_used 갱신
접두사 stcert_
```

KeyStone 판으로 옮기면 스코프의 단위가 **엔드포인트 그룹**이 됩니다.

```
service_api_tokens         (위와 동형)
service_api_token_scopes   token_id → scope   예: totp.verify · totp.enroll · users.lookup
```

`requireServiceToken(event)` 이 `requireServiceToken(event, "totp.verify")` 가 되고, 각 라우트가
자기가 요구하는 스코프를 이름으로 적습니다. 지금의 `DISPATCHER_SERVICE_TOKEN` 은 **모든 스코프를
가진 토큰 하나**로 남겨 두면 기존 dispatcher 가 안 깨집니다.

### 규모

| 항목                                 | 비용   | 비고                             |
| ------------------------------------ | ------ | -------------------------------- |
| 테이블 2개 × 3방언                   | 중     | `serviceRoles` 처럼 동형으로     |
| `requireServiceToken` 에 스코프 인자 | 소     | 호출 지점 5곳                    |
| 라우트별 스코프 이름 부여            | 소     | 5줄                              |
| 발급·폐기 UI                         | **대** | 이번에도 여기가 절반 이상입니다  |
| 기존 토큰 호환                       | 소     | 전 스코프 토큰으로 남기면 무중단 |

**UI 없이 만들면 `DISPATCHER_SERVICE_TOKEN` 과 실질적으로 같습니다** — 첫 핸드오프의 entitlement
와 같은 구조의 이야기입니다. 착수하신다면 발급 화면을 범위에 넣는 편이 낫다고 봅니다.

---

## 5. 우선순위에 대한 저희 의견

**entitlement 보다 낮다고 봅니다.**

entitlement 는 *지금 잘못 쓰기 쉬운 것*을 고치는 일입니다 — `groups` 로 인가하는 RP 는 오늘도
생길 수 있습니다. 이 건은 *지금 과하게 주는 것*을 좁히는 일이고, 그 과함이 실제 피해가 되려면
서비스 토큰을 가진 쪽이 먼저 침해되어야 합니다.

그리고 저희 쪽은 3절 때문에 **급하지 않습니다.**

다만 **호출자가 셋째가 되기 전에** 하시는 편이 낫다고 봅니다. 둘일 때는 회전이 조율 가능한
작업이고, 셋부터는 아무도 회전을 시작하지 않게 됩니다.

---

## 6. 그동안 저희가 하는 것

토큰을 파일로 마운트하고(env 는 `/proc/<pid>/environ` 과 크래시 덤프에 남습니다) `/api/totp/verify`
외에는 부르지 않습니다. 스코프가 없으므로 **그것을 강제하는 것은 저희 코드뿐**이고, 그게 정확히 이
문서가 지적하는 상태입니다.

스코프 있는 토큰이 생기면 `totp.verify` 하나만 받겠습니다.
