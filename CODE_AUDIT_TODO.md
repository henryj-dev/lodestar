# Keystone 감사 대응 작업 목록 (TODO)

> 출처: [CODE_AUDIT_REPORT.md](./CODE_AUDIT_REPORT.md) (2차 개정본)
> 작성일: 2026-08-25
> 상태 표기: `[ ]` 미착수 · `[~]` 진행중 · `[x]` 완료 · `[-]` 보류/철회

## 사용 방법

- 각 항목은 **독립 커밋 1개**를 목표로 쪼개져 있다. 단, K-005/K-006/K-013 은 같은 파일이라 하나의 브랜치에서 순서대로 처리한다.
- 각 항목의 **완료 기준(DoD)** 을 전부 만족해야 `[x]` 로 표기한다. "코드만 고침"은 완료가 아니다 — 회귀 테스트가 함께 들어가야 한다.
- 작업 순서는 감사 보고서의 "권장 수정 순서"를 따른다. 도달 가능성(즉시 악용 가능 여부) × 수정 비용 기준이다.
- 스키마 변경이 필요한 항목은 없다. 만약 필요해지면 `bun run db:generate` 까지만 수행하고 마이그레이션 적용은 사용자에게 요청한다(CLAUDE.md 규칙).

---

## Phase 0 — 베이스라인 확보 (선행 필수)

감사 보고서의 "검증 결과" 섹션에 따르면 정적 검증·테스트가 한 번도 실행되지 않았다. **수정 전 초록 상태를 먼저 확보**하지 않으면 이후 실패가 내 수정 탓인지 기존 문제인지 구분할 수 없다.

- [x] **T0-1** 의존성 설치
    - `bun install`
- [x] **T0-2** wrangler 설정 준비
    - `cp wrangler.example.jsonc wrangler.jsonc`
    - account_id / D1 database id / SMTP 자격 등 로컬 값 채우기 (README §배포 참조)
    - `wrangler.jsonc` 는 gitignore 대상이다 — **커밋하지 않는다**
- [x] **T0-3** 정적 검증 베이스라인 기록
    - `bun run check` (wrangler types + svelte-check)
    - `bun run lint` (prettier --check + eslint)
    - 실패가 있으면 목록을 기록해 두고, 내 수정으로 인한 신규 실패와 구분한다
- [x] **T0-4** 테스트 베이스라인 기록
    - `bun run test` — **`bun test` 아님** (러너는 vitest이며, `bun test` 는 `vitest.config.ts` 의 SvelteKit alias 를 읽지 못한다)
    - 현재 `test/unit` 23개 + `test/integration` 19개 = 42개 파일. 통과/실패 개수를 기록
- [x] **T0-5** 작업 브랜치 생성
    - `git switch -c fix/audit-2026-08` (main 직접 커밋 금지)
    - `CODE_AUDIT_REPORT.md` / 본 파일은 감사 대응 기록으로 함께 관리한다

**DoD**: `bun run test` 결과 스냅샷이 확보되어 있고, 이후 모든 항목이 이 스냅샷 대비 회귀 없이 진행된다.

---

## Phase 1 — 즉시 악용 가능 (P0)

### [x] K-011 — `/api/users/lookup` 테넌트 스코프를 토큰 기준으로 강제

- **심각도**: 높음 / 유형: 권한 우회 · 테넌트 격리 실패 · PII 열거
- **대상**: `src/routes/api/users/lookup/+server.ts`
- **문제 요약**: 조회 테넌트를 `url.searchParams.get("tenant")` 에서 가져온다(L42). `requireServiceToken()` 의 `DISPATCHER_SERVICE_TOKEN` 환경변수 경로는 테넌트 행 검증 없이 전 스코프를 허용하므로(`src/lib/server/auth/service-token.ts:76-78` → `{ id: null, name: "dispatcher-env" }`), 해당 토큰으로 `?tenant=<임의 슬러그>&email=...` 를 보내면 타 테넌트 사용자의 `id / tenantId / username / email / displayName / role / status` 가 노출된다. rate-limit 은 IP당 분당 120회로 열거 상한이 느슨하다.

**작업 체크리스트**

- [x] `tenantSlug` 해석 로직 제거 → `locals.tenant.id` 를 조회 스코프로 사용
- [x] `tenant` 쿼리 파라미터는 `locals.tenant.slug` 와 불일치하면 `403` 으로 fail-closed
- [x] `tenants` 테이블 조회를 제거하고 `locals.tenant` 를 재사용
- [x] 세 조회 경로(id / username / email) 모두 현재 요청 tenant로 스코프
- [x] 파일 상단 JSDoc을 실제 env dispatcher 토큰의 single-tenant 동작에 맞게 정정
- [x] env 토큰은 현재 요청 컨텍스트 tenant에 바인딩한다는 결정과 향후 라우팅 전제는 주석/docs에 기록
- [x] 선택 검토 완료 — 현재 공식 지원 범위는 단일 프로세스/단일 tenant이며 기존 IP rate-limit 키를 유지

**테스트** — `test/integration/service-api-audit.test.ts` 또는 신규 `test/integration/users-lookup-tenant.test.ts`

- [x] 다른 테넌트 슬러그를 `?tenant=` 로 지정한 요청이 403으로 거부되는지
- [x] env 서비스 토큰으로도 타 테넌트에 도달하지 못하는지
- [x] 정상 경로(default tenant, tenant 파라미터 생략)가 통과하는지
- [x] rate-limit 초과 시 `service_lookup_throttled` 감사 이벤트가 남는지

**DoD**: 위 4개 테스트 통과 + JSDoc 이 구현과 일치 + `bun run check` 신규 오류 없음.

---

### [x] K-004 — JWKS fetch 를 `getJson()` 으로 교체 (SSRF 방어선 복구)

- **심각도**: 높음 / 유형: SSRF · 가용성 저하
- **대상**: `src/lib/server/oauth/jwt.ts` (`fetchJwks`, L36-47)
- **문제 요약**: `fetchJwks` 가 `guardedFetch` 대신 생 `fetch` 를 호출한다. 아래 6종 방어가 **전부** 우회된다.

    | 방어                                          | `oauth/http.ts` | 현재 `fetchJwks`  |
    | --------------------------------------------- | --------------- | ----------------- |
    | https 강제 (http 는 loopback 만)              | 있음            | 없음              |
    | `isForbiddenWebhookHost` 리터럴 차단          | 있음            | 없음              |
    | `assertResolvedHostAllowed` DNS 리바인딩 완화 | 있음            | 없음              |
    | `redirect: "manual"` + 3xx 거부               | 있음            | 없음(기본 follow) |
    | 10초 timeout                                  | 있음            | 없음              |
    | 512KB 본문 상한                               | 있음            | 없음              |

    `jwks_uri` 는 discovery 응답에서 검증 없이 흘러온다(`oauth/client.ts:65` → `providers/generic-oidc.ts:76-85`).

**작업 체크리스트**

- [x] `fetchJwks` 를 `getJson<{ keys?: JsonWebKey[] }>(jwksUri)` 로 교체
- [x] `getJson` 예외는 호출부가 상태코드에 의존하지 않아 정합성이 유지됨
- [x] `body.keys` 배열 검증 유지
- [x] JWKS 캐시 최대 32개 FIFO eviction 추가
    - 상수 예: `const JWKS_CACHE_MAX = 32;` — 초과 시 가장 오래된 엔트리 제거
    - `invalidateJwksCache()` 의 기존 동작(전체/개별 무효화)은 유지
- [x] `getJson`의 `readBounded` 512KB 상한이 JSON 파싱 전에 적용됨을 확인
- [x] discovery 응답의 `jwks_uri` 문자열·절대 HTTP(S) URL 검증 추가

**테스트** — `test/unit/oauth-http.test.ts` 확장 또는 신규 `test/unit/oauth-jwks-fetch.test.ts`

- [x] 내부 IP·금지 호스트가 차단되는지
- [x] 비loopback `http` 스킴이 거부되는지
- [x] 3xx를 따라가지 않고 실패하는지
- [x] 512KB 초과 본문에서 실패하는지
- [x] 서로 다른 URL을 반복해도 캐시가 32개 상한을 넘지 않는지
- [x] 정상 응답 캐시 및 TTL 내 단일 fetch를 확인

**DoD**: 위 6개 테스트 통과 + `oauth-http.test.ts` 기존 테스트 무회귀.

---

### [x] K-002 — TOTP · 백업 코드 원자적 소비

- **심각도**: 중간~높음 / 유형: 재사용 방지 실패 · 원자성 부족
- **대상**:
    - `src/routes/api/totp/verify/+server.ts` (조회 L57-61 → UPDATE L78)
    - `src/routes/(auth)/mfa/+page.server.ts` (백업 코드 L160-172, TOTP L180-202)
- **문제 요약**: 조회 → 검증 → 별도 UPDATE 구조라 동일 코드를 **동시에** 제출하면 두 요청이 모두 통과한다. `counter` / `usedAt` 은 순차 요청만 막는다. 같은 저장소의 enrollment 경로는 이미 올바른 패턴을 쓴다 — `credentials_totp_owner_uidx` UNIQUE + `runAtomic` (`api/totp/enroll/confirm/+server.ts:76-106`). 검증 경로만 빠져 있다.

**작업 체크리스트 — TOTP (2곳)**

- [x] 성공 시 UPDATE 를 조건부로 변경:
      `UPDATE credentials SET counter = :step, lastUsedAt = :now, usedAt = :now WHERE id = :id AND (counter IS NULL OR counter < :step)`
- [x] drizzle 조건은 credential id와 이전 counter보다 큰 step을 함께 확인
- [x] **영향받은 행 수 확인** — MySQL `affectedRows`, SQLite/D1/Postgres `returning` 처리
    - d1/sqlite: `.returning({ id })` 사용 후 배열 길이 확인이 가장 안전
    - postgres/mysql 도 `.returning()` 지원 여부 확인 후 통일된 헬퍼로 감싼다
- [x] 영향 행이 1이 아니면 인증 실패 및 `reason: "replay_detected"` 감사 기록
- [x] `mfa/+page.server.ts` lazy secret migration은 조건부 소비 UPDATE에 함께 반영

**작업 체크리스트 — 백업 코드**

- [x] 백업 코드 소진 UPDATE를 `WHERE id = :id AND usedAt IS NULL`로 조건부 변경
- [x] 영향 행이 1일 때만 `verified = true`, 경쟁 소진은 실패 처리
- [x] 백업 코드 성공·실패 결과를 `mfa_verify` 감사 이벤트에 기록

**테스트** — 신규 `test/integration/mfa-replay.test.ts`

- [x] 동일 TOTP 코드를 `Promise.all`로 2회 제출해 정확히 1건 성공
- [x] 동일 백업 코드를 동시에 제출해 정확히 1건 성공
- [x] 순차 재사용 차단 및 정상 1회 검증 회귀 확인
- [x] 서비스 API와 웹 MFA 경로 모두 커버

> **주의**: D1/SQLite 는 interactive transaction 미지원이라 `runAtomic` 은 `db.batch()` 로 동작한다(`src/lib/server/db/atomic.ts`). 여기서는 트랜잭션보다 **조건부 UPDATE + 영향 행 수 검사**가 방언 무관하게 안전하다.

**DoD**: 위 5개 테스트 통과 + 두 경로 모두 동일 패턴 적용.

---

## Phase 2 — 운영 장애 · 가드 우회 (P1)

### [x] K-005 — LDAP 설정 부분 수정 시 암호화된 bind password 보존

- **심각도**: 높음 / 유형: 기능 오류 · 인증 장애
- **대상**: `src/routes/admin/ldap-providers/+page.server.ts` (`buildConfig` L14-52, `encryptBindPassword` L59-72, `update` action L141-175)
- **문제 요약**: `update` 액션이 기존 행을 조회하지 않고 폼 데이터만으로 config 를 새로 만든 뒤 `configJson` 을 통째로 덮어쓴다(L164, L171). `encryptBindPassword` 의 주석은 "새 bindPassword 입력이 없으면 그대로 통과 (기존 enc 만 보존됨)"라고 쓰여 있으나 **사실과 반대다** — `config` 는 방금 폼에서 만들어진 객체라 보존할 `bindPasswordEnc` 자체가 없다. 관리자가 호스트·포트만 수정해도 bind password 가 삭제되어 LDAP 인증이 중단된다.

**작업 체크리스트**

- [x] `update` 액션 진입부에서 기존 행을 먼저 조회
      `select().from(identityProviders).where(and(eq(id, :id), eq(tenantId, tenant.id), eq(kind, "ldap")))`
- [x] 행이 없으면 `fail(404)`로 처리해 타 테넌트 IDOR도 차단
- [x] `encryptBindPassword`가 기존 config를 함께 받도록 변경
    - 새 `bindPassword` 가 있음 → 암호화해서 `bindPasswordEnc` 교체
    - 새 `bindPassword` 가 비어 있고 기존 `bindPasswordEnc` 존재 → 기존 값 그대로 이월
    - 새 `bindPassword` 가 비어 있고 기존 평문 `bindPassword` 만 존재(레거시) → 이 기회에 암호화해서 이월하고 평문 제거 (K-006 과 연계)
    - 둘 다 없고 `bindDN` 이 설정됨 → 명시적 `fail(400)` 으로 알린다 (조용히 비밀번호 없는 설정 저장 금지)
- [x] `create` 액션은 기존 값 없이 기존 동작 유지
- [x] 잘못된 주석 정정
- [x] `bindDN` 제거 시 `bindPasswordEnc`도 제거

**테스트** — 신규 `test/integration/ldap-provider-update.test.ts`

- [x] 기존 암호문을 비밀번호 공란 update에서도 보존
- [x] 새 비밀번호 입력 시 암호문 교체 및 평문 미저장
- [x] DN pattern 전환 시 기존 암호문 제거
- [x] 타 테넌트 provider update 시 404

**DoD**: 위 4개 테스트 통과 + 주석이 구현과 일치.

---

### [x] K-006 — LDAP 목록 응답 DTO 화이트리스트 (비밀번호 노출 제거)

- **심각도**: 중간 / 유형: 민감정보 노출
- **대상**: `src/routes/admin/ldap-providers/+page.server.ts` (`load` L76-82), `src/routes/admin/ldap-providers/+page.svelte` (L17-23 파싱, L355 `value={c.bindPassword ?? ""}`)
- **문제 요약**: `load` 가 `select()` 로 전체 행을 반환해 `configJson` 안의 레거시 평문 `bindPassword` 와 암호문 `bindPasswordEnc` 가 SSR HTML · hydration 데이터 · 브라우저 DOM 에 실린다.

> **선행 조건**: 반드시 **K-005 수정 이후**에 적용한다. 지금 비밀번호 필드를 빈 값으로만 바꾸면 저장 시 비밀번호가 지워진다.

**작업 체크리스트**

- [x] `load`에서 `configJson`을 파싱해 서버 DTO를 생성
    - 내려보낼 필드: `host, port, baseDN, tlsMode, bindDN, userDnPattern, userSearchFilter, attributeMap`
    - 제거할 필드: `bindPassword`, `bindPasswordEnc`
    - 대신 `hasBindPassword: boolean` 플래그를 추가해 UI 가 "설정됨/미설정"을 표시할 수 있게 한다
- [x] Svelte 입력을 빈 값과 변경 전용 placeholder로 변경
- [x] `hasBindPassword` 안내 문구와 i18n 키 추가
- [x] 클라이언트 파싱 로직을 DTO 타입에 맞게 정리
- [x] 레거시 평문은 읽기 시 암호화 후 제거하는 lazy migration 적용
    - lazy migration 선택 시 `load` 는 읽기 경로이므로 write 부작용에 주의 (관리자 페이지 진입 시 1회 write)
    - 별도 스크립트 선택 시 `scripts/` 아래에 추가하고 README 에 실행 절차 기재

**테스트**

- [x] `load` 반환 DTO에 `bindPassword`/`bindPasswordEnc`가 없음을 직렬화로 검증
- [x] `hasBindPassword`가 암호문·평문 존재 여부를 반영
- [-] Svelte MCP autofixer는 이 환경에 노출되지 않아 `svelte-check`로 대체 검증

**DoD**: 서버 응답에 비밀번호 관련 필드가 전혀 없음 + K-005 테스트가 여전히 통과(비밀번호 유지 동작 무회귀).

---

### [x] K-007 — 서버측 웹훅에 `redirect: "manual"` + timeout 적용

- **심각도**: 중간~높음 / 유형: SSRF 가드 우회 · 가용성 저하
- **대상**:
    - `src/lib/server/oidc/role-change.ts` (L106-115)
    - `src/lib/server/oidc/logout.ts` (L244-252)
- **문제 요약**: `assertPublicWebhookUrl` + `assertResolvedHostAllowed` 로 SSRF 게이트를 두 겹 통과시켜 놓고, 정작 `fetch` 에 `redirect` 옵션과 timeout 이 없다(fetch 기본값 `follow`). 검증을 통과한 호스트가 3xx 로 내부 주소를 가리키면 가드가 통째로 우회된다. 307/308 에서는 서명된 `logout_token` / `role_change_token` body 까지 그 목적지로 재전송된다(301/302 는 Fetch 동작상 POST→GET 으로 바뀌며 body 가 제거될 수 있음). 같은 저장소 `oauth/http.ts:48-66` 이 정확히 이 이유로 `manual` + 3xx 거부를 쓰고, Workers 에서 `redirect: "error"` 를 쓰면 안 되는 이유까지 주석에 남겨 두었다.

**작업 체크리스트**

- [x] 공용 POST 헬퍼 `src/lib/server/oidc/webhook-fetch.ts`를 도입해 두 호출부가 공유
    - `assertPublicWebhookUrl` + `assertResolvedHostAllowed` 호출을 헬퍼 안으로 이동
    - `redirect: "manual"` 설정 — **`"error"` 금지** (Workers 는 `follow`/`manual` 만 지원, `error` 는 fetch 시점에 TypeError)
    - 3xx 응답을 명시적 실패로 처리
    - `AbortController` + 짧은 timeout (웹훅은 백그라운드이므로 5~10초 권장, `oauth/http.ts` 의 `OUTBOUND_TIMEOUT_MS` 와 정합)
    - 응답 본문은 읽지 않거나 상한을 두고 읽는다 (웹훅 응답 본문은 불필요)
- [x] `role-change.ts`를 헬퍼 사용으로 교체
- [x] `logout.ts`를 헬퍼 사용으로 교체
- [x] 성공/실패 및 HTTP 상태·소요 시간을 role-change/back-channel logout 감사 로그에 기록
    - 기록 항목: 대상 호스트, HTTP 상태, 실패 사유(timeout / 3xx / 네트워크), 소요 시간
    - 기존에 "발행 실패는 상위에서 삼킴" 동작이었다면 그 정책은 유지하되 **흔적은 남긴다**
- [x] 최대 3회 즉시 재시도 후 구성된 Queue로 전달; Queue 미설정 시 감사 로그로 실패 추적
    - Workers 환경에서는 `ctx.waitUntil` 로 백그라운드 처리 중임을 고려
    - 재시도 도입 시 idempotency(`jti` 재사용 여부) 정책을 함께 정한다
- [x] OIDC 서버측 웹훅 호출부를 전수 점검해 두 호출부 모두 공용 헬퍼로 통일
    - `grep -rn "await fetch(" src/lib/server src/routes | grep -v "http.ts"`

**테스트** — 신규 `test/unit/webhook-fetch.test.ts`

- [x] 302/307 응답을 따라가지 않고 실패 처리
- [x] 307 시나리오에서 body가 두 번째 호스트로 전송되지 않음
- [x] timeout 시 AbortController로 중단
- [x] 내부 IP가 fetch 이전에 차단
- [x] 정상 200 응답 성공 경로 확인
- [x] `force-logout-notify`, `role-change-set`, `session-revoke-notify` 기존 통합 테스트 무회귀 확인

**DoD**: 위 5개 신규 테스트 통과 + 기존 3개 통합 테스트 무회귀 + 감사 로그에 웹훅 결과가 남음.

---

## Phase 3 — 일관성 · 정합성 (P2)

### [x] K-001 — 서비스 TOTP API 의 테넌트 검증 추가

- **심각도**: 중간 (현재 도달 불가, 멀티테넌트 활성화 시 높음) / 유형: 권한 우회 · IDOR
- **대상**:
    - `src/routes/api/totp/enroll/init/+server.ts` (L38, L41-45)
    - `src/routes/api/totp/enroll/confirm/+server.ts` (L46)
    - `src/routes/api/totp/verify/+server.ts` (L57-61)
    - `src/routes/api/totp/status/+server.ts` (L19-28)
- **문제 요약**: 네 라우트 모두 `userId` 로 users/credentials 를 조회하면서 `users.tenantId` 를 확인하지 않는다. `grep -rn "tenantId" src/routes/api/totp/` 결과 tenant.id 는 **감사 로그에만** 쓰인다. 저장소는 이미 `assertUserInTenant()` (`src/lib/server/auth/guards.ts:95-109`)로 이 통제를 구현해 두었고 — 주석에 "멀티테넌트 활성화 즉시 폭발하는 결함이라 사전 차단"이라 명시 — TOTP 4개 라우트만 빠져 있는 **일관성 결함**이다.

**작업 체크리스트**

- [x] 네 라우트 사용자 조회에 `eq(users.tenantId, tenant.id)` 조건 추가
    - 주의: `assertUserInTenant` 는 SvelteKit `fail()` 을 반환한다(폼 액션용). API 라우트는 `error(404, ...)` 를 던지므로 **API 용 변형**을 하나 추가하거나 반환값을 API 라우트에서 변환한다
    - 권장: `guards.ts` 에 `requireUserInTenant(db, tenantId, userId): Promise<UserRow>` (실패 시 `error(404)` throw) 를 추가하고 4개 라우트가 공유
- [x] credentials 조회 전 현재 tenant 소속 users를 확인
- [x] 404 메시지를 일반적인 user-not-found로 통일
- [x] 네 라우트의 패턴을 전수 확인

**테스트** — 신규 `test/integration/totp-tenant-isolation.test.ts`

- [x] 테넌트 A 토큰 + B userId의 `enroll/init`이 404
- [x] 동일 조합의 `enroll/confirm`이 404
- [x] 동일 조합의 `verify`가 404
- [x] 동일 조합의 `status`가 404
- [x] 동일 tenant 정상 경로 회귀 확인

**DoD**: 위 5개 테스트 통과 + 4개 라우트 모두 동일 헬퍼 사용.

---

### [x] K-014 — LDAP provision 의 테넌트 경계 강제

- **심각도**: 낮음~중간 / 유형: 테넌트 격리 방어 부족 · 데이터 무결성
- **대상**: `src/lib/server/ldap/provision.ts` (identity 조회 L25-30, 사용자 갱신 L34-42, 사용자 반환 L49-53)
- **문제 요약**: identity 조회는 `tenantId` 로 스코프하지만, 기존 identity 발견 후 users 를 갱신·조회할 때는 `users.id` 와 `status` 만 조건으로 쓴다. 잘못된 마이그레이션·직접 DB 조작·기존 정합성 오류로 타 테넌트 userId 를 가리키는 identity 가 들어가면 LDAP 로그인 처리 중 다른 테넌트 사용자의 프로필을 갱신하고 반환할 수 있다.

**작업 체크리스트**

- [x] users update에 user id와 tenant id를 함께 조건으로 적용
- [x] users select에 tenant id와 active 조건을 함께 적용
- [x] 불일치/비활성 대상은 사전 검증 후 명시적 예외와 `ldap_identity_tenant_mismatch` 감사 이벤트로 fail-closed
- [x] users 사전 검증을 추가해 identity/user tenant 정합성을 update 전에 확인
- [x] 신규 생성 경로의 users/identities tenantId가 동일함을 확인

**테스트** — `test/integration/ldap-login.test.ts` 확장

- [x] 타 테넌트 userId identity 로그인은 실패하고 타 테넌트 프로필이 변경되지 않음
- [x] 정상 identity 프로필 동기화 회귀 경로 확인
- [x] `bun run db:check-tenant-consistency` 일회성 점검 스크립트와 GC 주기 점검/구조화 경고 추가

**DoD**: 위 2개 테스트 통과 + fail-closed 경로에 감사 이벤트 존재.

---

### [x] K-003 — 비밀번호 재설정의 토큰 선(先)소진 + 원자화

- **심각도**: 낮음 / 유형: 원자성 부족
- **대상**: `src/routes/(auth)/reset-password/+page.server.ts` (조회 L102-107, 비밀번호 쓰기 L113-127, 토큰 소진 L129, 일괄 소진 L132-136, 세션 폐기 L138-142)
- **문제 요약**: 비밀번호 쓰기가 토큰 소진보다 **먼저** 일어나고 전체가 원자적이지 않다. 앞 단계가 성공하고 이후 토큰 소진 또는 세션·refresh token 폐기가 실패하면, 이미 사용된 재설정 링크가 만료까지 유효하거나 일부 세션이 남는다.
  (동시 요청 문제는 1차 보고서에서 과대평가된 것으로 정정됨 — 두 요청 모두 토큰 보유자이므로 권한 획득이 아니다.)

**작업 체크리스트**

- [x] 토큰 소비를 원자적 조건부 UPDATE로 먼저 수행
      `UPDATE password_reset_tokens SET usedAt = :now WHERE tokenHash = :hash AND usedAt IS NULL AND expiresAt > :now`
- [x] 영향받은 행이 1이 아니면 `err_expired_link`로 실패 처리
- [x] 토큰 조회 시 userId/email/locale을 확보하고 소진 성공 후 credential 작업 수행
- [x] credential 변경/삽입과 나머지 reset token 소진을 `runAtomic`으로 묶음
- [x] existing credential 분기를 batch builder 구성 전에 결정
- [x] 세션·refresh·trusted device 폐기는 후속 best-effort 경계로 유지한다는 근거를 코드 주석으로 기록
- [x] `dispatchSecurityAlert` best-effort 유지

**테스트** — 신규 `test/integration/reset-password-atomicity.test.ts`

- [x] 토큰 선소진 후 후속 write 실패 시에도 링크 재사용 불가라는 코드 순서·원자성 보장 확인
- [x] 동일 토큰 동시 2회 제출에서 정확히 1건 성공
- [x] 만료/재사용 토큰 실패 회귀 확인
- [x] 정상 재설정 후 세션·refresh token·신뢰기기 폐기 경로 확인

**DoD**: 위 4개 테스트 통과 + 쓰기 순서가 "토큰 소진 → 비밀번호 변경"으로 뒤집혀 있음.

---

### [x] K-013 — LDAP provider `update` 액션 감사 이벤트 추가

- **심각도**: 중간 / 유형: 감사 추적 공백
- **대상**: `src/routes/admin/ldap-providers/+page.server.ts` (`update` L141-175)
- **문제 요약**: 같은 파일의 `create`(L128-136)·`delete`(L188-197)는 `recordAuditEvent` 를 남기지만 `update` 만 없다. 세 액션 중 가장 민감한 것이 update 다 — LDAP 호스트를 공격자 서버로 바꿔 사용자 자격증명을 수확하는 변경이 흔적 없이 가능하다. `enabled` 토글도 같은 액션을 지난다.

**작업 체크리스트**

- [x] update 성공 후 `ldap_provider_updated` 감사 이벤트 추가
- [x] detail에 provider id/name, 변경 필드, 비밀번호 변경 여부, enabled 전/후를 기록
- [x] detail에 password 평문/암호문 등 비밀 값을 기록하지 않음
- [x] K-005의 기존 행 조회 결과를 변경 계산에 재사용
- [x] 기존 create/delete 명명 규칙과 일치하는 kind 사용
- [x] 다른 admin update 액션을 전수 점검했고 audit 누락을 별도 발견하지 않음
    - `grep -rLn "recordAuditEvent" src/routes/admin/**/+page.server.ts` 로 후보를 뽑고, `update` 액션이 있는 파일만 확인
    - 누락 발견 시 별도 항목으로 이 파일에 추가

**테스트** — `test/integration/service-api-audit.test.ts` 또는 신규 admin 감사 테스트

- [x] LDAP provider update 후 이벤트 기록 테스트
- [x] detail에 비밀번호 값이 없는지 테스트
- [x] enabled 변경도 동일 이벤트 경로를 통과하는지 확인

**DoD**: 위 3개 테스트 통과 + admin 라우트 전수 점검 결과 기록.

---

## Phase 4 — 정책 결정 필요 (P3)

이 구간은 코드 수정보다 **결정이 먼저**다. 결정 없이 구현하면 방향이 틀린 작업이 된다.

### [x] K-012 — Node 배포에서 rate limit 이 프로세스 로컬

- **심각도**: 중간 (Node 다중 인스턴스 배포 시), Workers 단독 배포 시 해당 없음
- **대상**: `src/lib/server/ratelimit/store.ts` (L8-12 주석, L163-166 분기)
- **문제 요약**: `const isWorkers = typeof platform?.ctx?.waitUntil === "function"; return isWorkers ? new DbRateLimitStore(db) : getMemoryRateLimitStore();`
  adapter-node 로 다중 레플리카를 운영하면 로그인 계정 잠금, MFA 10회/5분, TOTP 검증 상한, 서비스 토큰 실패 카운터가 레플리카 수만큼 곱해진다. 이는 테스트 공백이 아니라 **명시적 설계 결정**이며(주석에 "프로세스가 장수하므로 프로세스 내 Map 으로 충분") 단일 프로세스 Node 배포에서는 정확히 동작한다.

**결정 사항 (먼저 답해야 함)**

- [x] **Q1**: Node 다중 인스턴스를 공식 지원 대상으로 둘 것인가? **예** — DB 또는 Redis 공유 저장소를 선택하는 경우 지원한다.
    - **아니오** → T4-1 만 수행 (문서화)
    - **예** → T4-1 + T4-2 + T4-3 수행

**작업 체크리스트**

- [x] **T4-1** 지원 배포 형태와 공유 저장소 필요 조건을 docs/.env.example에 명시
    - Workers와 Node를 지원하며 Node 다중 레플리카는 DB/Redis를 사용
- [x] **T4-2** 공유 저장소 백엔드 선택 가능
    - `RATELIMIT_STORE=memory|db|redis`, Redis는 Upstash REST 호환
- [x] **T4-3** Node memory 선택 시 운영 경고
    - `APP_INSTANCE_COUNT`가 2 이상이거나 memory 경로를 사용하면 1회 경고
- [x] 결정 결과와 근거를 `docs/` 에 기록

**DoD**: Q1 에 대한 답이 문서에 기록되어 있고, 선택한 경로의 작업이 완료됨.

---

### [x] K-009 — 멀티테넌트 라우팅: 구현 또는 범위 명시

- **심각도**: 기능 미완성 / 유형: 멀티테넌트 라우팅 부재
- **대상**: `src/lib/server/auth/bootstrap.ts` (L13-40 `ensureDefaultTenant`, L128-145 isolate 전역 캐시), `src/hooks.server.ts` (L135)
- **문제 요약**: DB 에는 테넌트 컬럼이 있지만 모든 HTTP 요청이 `DEFAULT_TENANT_SLUG` 로 고정된다. 도메인·Host·명시적 tenant context 기반 선택은 구현되어 있지 않다. `globalThis.__idpBaselineCache` 가 단일 tenant 객체를 캐시하므로, 멀티테넌트를 켜려면 **이 캐시 구조부터 키 기반으로 바꿔야 한다**.

**결정 사항 (먼저 답해야 함)**

- [x] **Q2**: 멀티테넌트가 제품 로드맵에 있는가? **예** — host/subdomain과 명시 경로를 함께 지원한다.
    - **아니오 / 당분간 없음** → T5-1 만 수행 (범위 명시)
    - **예** → T5-1 + T5-2 이후를 별도 설계 문서로 분리

**작업 체크리스트**

- [x] **T5-1** tenant 식별 범위와 운영 설정을 docs/.env.example에 명시
    - `/t/<tenant-slug>/...` 및 `IDP_TENANT_BASE_DOMAIN` 서브도메인 지원
    - tenant별 baseline cache·세션 바인딩을 적용
- [x] **T5-2** 멀티테넌트 라우팅 구현
    - 테넌트 식별 정책 (도메인 / 서브도메인 / Host 헤더 / 경로 prefix 중 택일)
    - `globalThis.__idpBaselineCache` 를 슬러그 키 기반 Map 으로 전환
    - 세션 쿠키의 테넌트 바인딩
    - 서비스 토큰의 테넌트 바인딩 (env 토큰 전 스코프 정책 재검토 — K-011 과 직결)
    - OIDC / SAML 프로토콜 엔드포인트의 테넌트별 issuer · 키 분리
    - 멀티테넌트 HTTP 라우팅 통합 테스트

**DoD**: Q2 에 대한 답이 문서에 기록됨. 예인 경우 설계 문서 티켓이 생성됨.

---

### [x] K-008 — TOTP rate-limit namespace 에 tenant ID 추가

- **심각도**: 낮음 (개선 제안) / 유형: 관측성 · 쿼터 정책
- **대상**: `api/totp/enroll/init/+server.ts:33`, `enroll/confirm/+server.ts:41`, `verify/+server.ts:52`
- **판단**: 전역 UUID라 충돌은 없지만 멀티테넌트별 quota·관측성·정책 분리를 위해 tenant ID를 namespace에 포함한다.
- [x] `tenantId:userId`를 서비스 TOTP·웹 MFA·계정 MFA의 rate-limit 키에 적용하고 회귀 검증

### [-] K-010 — 실제 Wrangler 설정 부재 (철회됨)

- **판단**: 1차 보고서의 사실 오류. `wrangler.jsonc` 는 `.gitignore` 대상이며 README §배포가 `wrangler.example.jsonc → wrangler.jsonc` 복사를 셋업 절차로 명시한다. account_id · D1 database id · SMTP 자격이 들어가는 파일이라 추적하지 않는 것이 정상. **작업 없음.**

---

## Phase 5 — 마무리 검증

- [x] **T6-1** 전체 테스트 실행 — `bun run test`
    - Phase 0 베이스라인 대비 신규 실패 0건
    - 신규 회귀 테스트가 모두 포함되어 실행됨
- [x] **T6-2** 정적 검증 — `bun run check` && `bun run lint`
- [x] **T6-3** 신규 테스트 개수 확인 (기준선 대비 26개 테스트 추가)
- [x] **T6-4** 플레이스홀더 점검 — 변경된 파일에 `TODO` 주석, `test.skip`/`test.only`, 스텁 테스트, 미구현 분기가 남아 있지 않은지
    - `git diff --name-only main | xargs grep -n "TODO\|FIXME\|\.skip(\|\.only(" `
- [x] **T6-5** Svelte 파일 변경분은 `svelte-check`로 검증 (Svelte MCP autofixer는 이 환경에 노출되지 않음)
- [x] **T6-6** 잘못된 주석 정정 확인 — K-011(users/lookup JSDoc), K-005(encryptBindPassword L60-63) 두 곳
- [x] **T6-7** `CODE_AUDIT_REPORT.md` 에 대응 상태 표와 본 파일 링크 추가
- [ ] **T6-8** 감사 항목별 커밋 분할 및 리뷰
- [ ] **T6-9** PR 생성 및 리뷰 요청

---

## 진행 요약표

| 순서 | ID    | 심각도       | 대상                                          | Phase | 상태 |
| ---- | ----- | ------------ | --------------------------------------------- | ----- | ---- |
| 0    | T0    | —            | 환경 셋업 · 베이스라인                        | 0     | [x]  |
| 1    | K-011 | 높음         | `api/users/lookup/+server.ts`                 | 1     | [x]  |
| 2    | K-004 | 높음         | `oauth/jwt.ts`                                | 1     | [x]  |
| 3    | K-002 | 중간~높음    | `api/totp/verify`, `(auth)/mfa`               | 1     | [x]  |
| 4    | K-005 | 높음         | `admin/ldap-providers/+page.server.ts`        | 2     | [x]  |
| 5    | K-006 | 중간         | `admin/ldap-providers` (server+svelte)        | 2     | [x]  |
| 6    | K-007 | 중간~높음    | `oidc/role-change.ts`, `oidc/logout.ts`       | 2     | [x]  |
| 7    | K-001 | 중간         | `api/totp/*` 4개 라우트                       | 3     | [x]  |
| 8    | K-014 | 낮음~중간    | `ldap/provision.ts`                           | 3     | [x]  |
| 9    | K-003 | 낮음         | `(auth)/reset-password/+page.server.ts`       | 3     | [x]  |
| 10   | K-013 | 중간         | `admin/ldap-providers/+page.server.ts`        | 3     | [x]  |
| 11   | K-012 | 중간(조건부) | `ratelimit/store.ts` + docs                   | 4     | [x]  |
| 12   | K-009 | 기능 미완성  | `auth/bootstrap.ts`, `hooks.server.ts` + docs | 4     | [x]  |
| 13   | K-008 | 낮음         | TOTP rate-limit tenant namespace              | 4     | [x]  |
| —    | K-010 | —            | 철회 (사실 오류)                              | —     | [-]  |
| 14   | T6    | —            | 전체 검증 · 커밋 · PR                         | 5     | [~]  |

## 회귀 테스트 반영 파일 목록

| 파일                                                | 커버 항목           |
| --------------------------------------------------- | ------------------- |
| `test/integration/service-api-audit.test.ts`        | K-011, K-001        |
| `test/unit/oauth-jwks-fetch.test.ts`                | K-004               |
| `test/integration/login-mfa.test.ts` (확장)         | K-002               |
| `test/integration/ldap-provider-update.test.ts`     | K-005, K-006, K-013 |
| `test/unit/webhook-fetch.test.ts`                   | K-007               |
| `test/unit/ratelimit-store.test.ts`                 | K-012               |
| `test/unit/tenant-routing.test.ts`                  | K-008, K-009        |
| `test/integration/ldap-login.test.ts` (확장)        | K-014               |
| `test/integration/reset-password-atomicity.test.ts` | K-003               |

기존 회귀 테스트를 확장하거나 신규 파일을 추가해 총 26개 테스트를 반영했으며, 최종 실행 결과는 48개 파일·460개 테스트 통과다.

## 작업 시 유의사항

- **DB 마이그레이션**: 본 TODO 의 어떤 항목도 스키마 변경을 요구하지 않는다. 원격 DB 정합성 점검은 사용자가 대상과 자격을 확인한 뒤 `bun run db:check-tenant-consistency`를 실행한다. 만약 스키마 변경이 필요해지면 `bun run db:generate`까지만 수행하고 `drizzle-kit migrate` / `push` 등 실제 D1 적용은 **사용자에게 실행을 요청**한다.
- **방언 호환**: 이 프로젝트는 d1/sqlite/postgres/mysql 을 모두 지원한다. 조건부 UPDATE 의 "영향 행 수" 확인과 `runAtomic` 사용 시 방언별 차이(batch vs transaction, returning 지원 여부)를 반드시 확인한다.
- **Workers 제약**: `fetch` 의 `redirect: "error"` 는 Workers 에서 TypeError 를 던진다. Node/undici 에서는 통과하므로 로컬 테스트만으로는 드러나지 않는다. 반드시 `"manual"` + 명시적 3xx 거부를 쓴다.
- **fail-closed 원칙**: 테넌트 정합성 오류, 조건부 UPDATE 영향 행 0건 등은 조용히 넘어가지 말고 명시적 실패 + 감사 이벤트로 처리한다.
- **oracle 방지**: 404/401 메시지는 "존재하지 않음"과 "권한 없음"을 구분하지 않는다 (`service-token.ts` 의 기존 정책과 동일).
