# service API 토큰 — 설계안

작성 2026-08-06 · 근거: `feat/service-entitlements` 이후 실측
발단: `docs/keystone-핸드오프2-서비스토큰.md` (heliopause) · 회신 `회신-heliopause.md`

---

## 0. 무엇을 고치나

지금 `/api/totp/*` 와 `/api/users/lookup` 은 **단일 공유 시크릿** 하나(`DISPATCHER_SERVICE_TOKEN`,
env)로 열린다. 발급 화면이 없고, 그 토큰 하나를 받으면 다섯 엔드포인트가 전부 열린다.

heliopause 는 `/api/totp/verify` 하나만 필요한데 다섯을 받게 된다. 그리고 호출자가 둘이 되는
순간 회전이 조율 작업이 되고, 조율이 필요한 보안 조치는 미뤄진다.

**호출자별 토큰 + 스코프**로 바꾼다. 관리 화면에서 발급·폐기한다.

---

## 1. 새로 발명할 것이 없다

이 저장소에 "시크릿 생성 → 1회 노출 → 해시 저장 → 상수시간 검증" 이 이미 완성돼 있다.
OIDC client_secret 이 그 방식이고, 그대로 본뜬다.

| 조각 | 기존 | 위치 |
|---|---|---|
| 생성 | 32바이트 난수 → base64url | `admin/oidc-clients/+page.server.ts:17` |
| 해시 | `sha256$<b64u>` | `oidc/client.ts:74` |
| 검증 | 상수시간 비교 | `oidc/client.ts:90` |
| 1회 노출 | 생성 직후 화면에 한 번, DB 엔 해시만 | `admin/oidc-clients/+page.svelte:43` |

Workers 제약도 없다 — `crypto.getRandomValues` / `crypto.subtle.digest` 를 이미 쓰고 있다.

### 다만 검증 방향이 뒤집힌다

client_secret 은 `clientId` 로 **누구인지 먼저 알고** 그 행의 해시와 비교한다.
서비스 토큰은 `Authorization: Bearer <토큰>` 하나로 오고 식별자가 없다. 그래서:

```
받은 토큰 → SHA-256 → token_hash 로 행 조회 → 스코프 대조
```

`token_hash` 에 unique 인덱스가 필요하다. 조회는 O(1).

**해시는 SHA-256 으로 충분하다.** 토큰이 256비트 난수라 사전 공격 대상이 아니다 — 느린 해시
(argon2)가 필요 없다. 이 저장소가 client_secret 에 이미 같은 판단을 했다(비밀번호만 argon2).

---

## 2. 확정한 설계 판단 셋

### 2-1. 테넌트가 어긋나면 거부한다

env 토큰은 전역이라 테넌트와 무관했다. DB 토큰은 테넌트 행에 매달린다.
요청의 테넌트(`requireDbContext` 가 해석)와 토큰 행의 `tenantId` 가 다르면 **거부**한다.
단일 테넌트 배포에서는 차이가 없고, 멀티테넌트에서 남의 테넌트 API 를 여는 것을 막는다.

### 2-2. env 토큰은 전 스코프로 남긴다 (무중단)

`DISPATCHER_SERVICE_TOKEN` 을 지우지 않는다. **env 우선 → 없으면 DB 조회** 순으로 가고,
env 토큰은 모든 스코프를 가진 것으로 취급한다. 기존 dispatcher 가 그대로 동작한다.

### 2-3. `last_used_at` 은 **throttle 해서** 쓴다 ⚠️

참조 설계(stardust `cert-token.ts`)에 `last_used_at` 이 있는데, 그대로 옮기면 **OTP 검증
호출마다 DB 쓰기가 한 번씩 는다.** Workers + D1/Hyperdrive 에서 승인 경로에 쓰기를 얹으면
지연·경합이 생긴다.

마지막 기록이 **5분보다 오래됐을 때만** 갱신한다. 행은 이미 손에 있으므로 추가 조회가 없고,
"이 토큰이 최근에 쓰이고 있나" 라는 운영 질문에는 5분 해상도로 충분하다.

---

## 3. 스키마 — 테이블 하나

참조 설계는 토큰/스코프 2테이블이지만, **이 저장소는 scope 를 공백 구분 텍스트로 저장한다**
(`oidcClients.scopes`). 그 선례를 따라 한 테이블로 둔다 — 검증 시 조인이 없어진다.

| 컬럼 | 비고 |
|---|---|
| `id` PK | |
| `tenant_id` → tenants cascade | 2-1 |
| `name` | 사람이 읽는 호출자 이름 (`heliopause`) |
| `token_hash` **unique** | `sha256$<b64u>`. 조회 키 |
| `token_prefix` | 평문 앞 8자. **식별 표시용** — 목록에서 어느 토큰인지 구분 |
| `scopes` | 공백 구분 (`totp.verify`) |
| `created_by` / `created_at` | |
| `expires_at` (nullable) | 발급 화면에서 설정. 검증이 필터 |
| `last_used_at` (nullable) | 2-3 |

**`revoked_at` 을 두지 않는다.** 폐기는 행 삭제 + 감사 이벤트다. 이 저장소의 실제 회수 방식이
그렇고(`revokeAssignment`), 직전 작업에서 **쓰는 코드가 없는 `revokedAt` 이 "안전 검사처럼
보이는 죽은 코드"** 가 돼 있던 것을 걷어냈다. 같은 것을 다시 만들지 않는다.

`expires_at` 과 `last_used_at` 은 **쓰는 경로를 반드시 함께 넣는다**(발급 폼 / 검증 시 갱신).
쓰지 않을 컬럼은 애초에 만들지 않는다.

---

## 4. 스코프 이름

라우트가 자기가 요구하는 스코프를 이름으로 적는다.

| 엔드포인트 | 스코프 |
|---|---|
| `/api/totp/verify` | `totp.verify` |
| `/api/totp/status` | `totp.status` |
| `/api/totp/enroll/init` · `/confirm` | `totp.enroll` |
| `/api/users/lookup` | `users.lookup` |

heliopause 는 `totp.verify` 하나만 받는다.

---

## 5. 단계

| 단계 | 내용 | 규모 |
|---|---|---|
| 1 | 스키마 1테이블 × 3방언 + `db:generate:all` | 소 |
| 2 | `requireServiceToken(event, scope)` + 호출부 5곳 | 소~중 |
| 3 | 발급·폐기 UI (`/admin/service-tokens`) | **대** |
| 4 | i18n · 감사 · 문서(README env 표, ADMIN_GUIDE) | 중 |

3단계가 절반 이상이다. `crud-factory` 는 쓸 수 없다 — 그 계약이 **1회 시크릿 노출을 다루지
않는다**(create 가 성공/실패만 반환). `oidc-clients` 목록 화면처럼 손으로 만든다.

---

## 6. 이 설계 밖

- **스코프 계층/와일드카드**(`totp.*`) — 지금 스코프가 넷뿐이라 이득이 없다. 정확 일치만.
- **토큰 자동 만료 알림** — 운영 기능. 필요해지면.
- **env 토큰 제거** — 호출자가 전부 DB 토큰으로 옮긴 뒤 별건으로.
