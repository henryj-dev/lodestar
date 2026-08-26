# Lodestar 코드 기반 기능·보안 감사 보고서

> 이 문서는 저장소가 `henryj-dev/keystone` 이던 시점의 감사 기록이다. 2026-08-25 `henryj-dev/lodestar` 로 개명되면서
> 제목·절대경로·링크만 새 이름 기준으로 갱신했다. 발견 사항·근거·판정은 감사 당시 그대로다.

## 감사 범위

- 대상: 애플리케이션 코드, 실행 설정, 테스트 코드
- 제외: README, docs 디렉터리, 설계 문서, 주석의 주장
- 점검 항목: 기능 오류, 보안 취약점, 테넌트 격리, 인증·인가, 입력 검증, 외부 연동, 미구현·더미 동작, 테스트 공백

본 보고서는 1차 감사 이후 코드 재대조를 거쳐 개정되었다. 개정 내역은 문서 말미 "개정 이력" 참조.
감사 대응 구현 상태와 검증 결과는 [CODE_AUDIT_TODO.md](./CODE_AUDIT_TODO.md)에 갱신한다.
발견 사항과 근거는 수정 전 감사 기준이며, 현재 반영 상태는 아래 "감사 대응 상태" 표를 우선한다.

## 요약

우선 수정이 필요한 항목은 다음과 같다.

1. `/api/users/lookup` 의 교차 테넌트 사용자 열거 (쿼리 파라미터 하나로 도달)
2. 외부 OIDC `jwks_uri` fetch 가 SSRF 방어선 전체를 우회
3. TOTP·백업 코드의 동시성 재사용
4. LDAP 설정 수정 시 기존 암호화된 bind password 삭제
5. 서버측 웹훅의 리다이렉트 추종으로 인한 SSRF 가드 우회
6. 서비스 TOTP API 의 교차 테넌트 접근 (현재는 잠재 결함)
7. 레거시 LDAP 평문 비밀번호의 관리자 브라우저 노출
8. LDAP identity 정합성 오류 시 교차 테넌트 사용자 갱신 가능성 (잠재 결함)

## 발견 사항

### K-011 — `/api/users/lookup` 교차 테넌트 사용자 열거

- 심각도: 높음
- 유형: 권한 우회 / 테넌트 격리 실패 / PII 열거

조회 대상 테넌트를 **토큰이 속한 테넌트가 아니라 요청 쿼리 파라미터**에서 가져온다.

근거:

- [users/lookup/+server.ts:42](/Users/henry/github/henryj-dev/lodestar/src/routes/api/users/lookup/+server.ts:42) — `url.searchParams.get("tenant")` 를 그대로 신뢰
- [users/lookup/+server.ts:48](/Users/henry/github/henryj-dev/lodestar/src/routes/api/users/lookup/+server.ts:48) — 그 슬러그로 tenants 행 해석
- [users/lookup/+server.ts:66-94](/Users/henry/github/henryj-dev/lodestar/src/routes/api/users/lookup/+server.ts:66) — 세 조회 경로 모두 이 tenant.id 로 스코프
- [service-token.ts:103](/Users/henry/github/henryj-dev/lodestar/src/lib/server/auth/service-token.ts:103) — 토큰 검증은 `row.tenantId === locals.tenant.id`(=default) 만 확인

현재 요청 컨텍스트가 default 테넌트로 고정되어 있어 DB 저장형 토큰의 경우에는 default 테넌트가 아닌 행과의 조합이 제한된다. 그러나 `requireServiceToken()`의 `DISPATCHER_SERVICE_TOKEN` 환경변수 토큰 경로는 테넌트 행 검증을 하지 않고 전 스코프를 허용한다. 따라서 해당 환경변수 토큰으로 `?tenant=<임의 슬러그>&email=...` 을 보내면 다른 테넌트 사용자의 `id / tenantId / username / email / displayName / role / status` 를 얻을 수 있다. rate-limit 은 IP 당 분당 120회라 열거 상한도 느슨하다.

이 파일의 주석([users/lookup/+server.ts:22-24](/Users/henry/github/henryj-dev/lodestar/src/routes/api/users/lookup/+server.ts:22))은 정반대를 주장한다 — "전역 dispatcher service-token 이 임의 테넌트 사용자 레코드를 조회하는 것을 막는다". 코드는 **요청된** 테넌트로 스코프할 뿐 **토큰의** 테넌트로 스코프하지 않는다.

권장 조치:

- `tenant` 쿼리 파라미터 제거 또는 `locals.tenant.id` 와 일치할 때만 허용
- 조회를 `locals.tenant.id` 기준으로 강제
- 다른 테넌트 슬러그를 지정한 요청에 대한 회귀 테스트 추가
- 주석과 구현의 불일치 정정

### K-004 — 외부 OIDC `jwks_uri` fetch 가 SSRF 방어선 전체를 우회

- 심각도: 높음
- 유형: SSRF / 가용성 저하

`fetchJwks` 는 `oauth/http.ts` 의 `guardedFetch` 가 아니라 **생 `fetch`** 를 호출한다.

근거:

- [oauth/jwt.ts:40](/Users/henry/github/henryj-dev/lodestar/src/lib/server/oauth/jwt.ts:40) — `await fetch(jwksUri, ...)`
- [oauth/client.ts:65](/Users/henry/github/henryj-dev/lodestar/src/lib/server/oauth/client.ts:65) — discovery 응답의 `jwks_uri` 를 검증 없이 전달
- [generic-oidc.ts:76-85](/Users/henry/github/henryj-dev/lodestar/src/lib/server/oauth/providers/generic-oidc.ts:76) — 그 값을 `verifyUpstreamIdToken` 에 전달
- [oauth/http.ts:24-69](/Users/henry/github/henryj-dev/lodestar/src/lib/server/oauth/http.ts:24) — 정상 경로가 갖춘 방어(대조군)

`guardedFetch` 가 제공하는 다음 방어가 **전부** 비켜 간다.

| 방어                                          | `guardedFetch` | `fetchJwks`        |
| --------------------------------------------- | -------------- | ------------------ |
| https 강제 (http 는 loopback 만)              | 있음           | 없음               |
| `isForbiddenWebhookHost` 리터럴 차단          | 있음           | 없음               |
| `assertResolvedHostAllowed` DNS 리바인딩 완화 | 있음           | 없음               |
| `redirect: "manual"` + 3xx 거부               | 있음           | 없음 (기본 follow) |
| 10초 timeout                                  | 있음           | 없음               |
| 512KB 본문 상한                               | 있음           | 없음               |

discovery 서버가 `jwks_uri` 로 내부 주소를 반환하면 로그인 처리 중 내부 네트워크 요청이 발생하고, 응답이 무제한 크기로 메모리에 올라가며, 요청이 무기한 붙잡힌다.

추가로 `jwksCache`는 URL별 최대 개수나 eviction이 없어, 공격자가 서로 다른 JWKS URL을 계속 유도할 수 있는 배포 구성에서는 메모리 증가 위험이 있다. TTL은 만료 시점 이후 조회 시 정리할 뿐 캐시 전체의 상한을 보장하지 않는다. 캐시 최대 크기/LRU 또는 주기적 정리, JWKS JSON 본문을 파싱하기 전 크기 제한을 함께 적용해야 한다.

권장 조치:

- `fetchJwks` 를 `getJson()` 재사용으로 교체 (기존 정책이 그대로 적용됨)
- 악성 `jwks_uri`(내부 IP / http / 3xx / 대용량 본문) 회귀 테스트 추가
- 서로 다른 `jwks_uri` 반복 입력에 대한 캐시 상한/eviction 테스트 추가

### K-002 — TOTP 및 백업 코드 동시성 재사용

- 심각도: 중간~높음 (전제: 공격자가 이미 유효한 코드 1개를 보유)
- 유형: 재사용 방지 실패 / 원자성 부족

TOTP 검증은 counter 를 조회·검증한 뒤 별도 UPDATE 를 수행한다. 백업 코드도 미사용 credential 을 조회·검증한 뒤 별도 UPDATE 를 수행한다.

근거:

- [api/totp/verify/+server.ts:57-78](/Users/henry/github/henryj-dev/lodestar/src/routes/api/totp/verify/+server.ts:57)
- [auth/mfa/+page.server.ts:160-172](</Users/henry/github/henryj-dev/lodestar/src/routes/(auth)/mfa/+page.server.ts:160>) — 백업 코드
- [auth/mfa/+page.server.ts:180-202](</Users/henry/github/henryj-dev/lodestar/src/routes/(auth)/mfa/+page.server.ts:180>) — TOTP

동일 코드를 동시에 제출하면 두 요청이 모두 검증을 통과할 수 있다. 재사용 방지(`counter`, `usedAt`)는 순차 요청만 막는다. 실효 공격은 피싱·중계로 확보한 코드를 정상 사용자의 제출과 병렬로 던지는 시나리오이므로, 단독 우회가 아니라 심층 방어 통제의 실패로 본다.

동일 파일의 enrollment 경로는 이미 올바른 패턴을 쓴다 — `credentials_totp_owner_uidx` UNIQUE 인덱스 + `runAtomic` 으로 동시 이중 등록을 DB 레벨에서 차단한다([enroll/confirm/+server.ts:76-106](/Users/henry/github/henryj-dev/lodestar/src/routes/api/totp/enroll/confirm/+server.ts:76)). 검증 경로만 빠져 있다.

권장 조치:

- TOTP 성공 시 `counter < newCounter` 조건부 UPDATE
- 백업 코드는 `usedAt IS NULL` 조건부 UPDATE
- 영향받은 행 수가 1인 경우에만 인증 성공 처리
- 동일 코드 병렬 요청 테스트 추가

### K-005 — LDAP 설정 수정 시 기존 암호화 비밀번호 삭제

- 심각도: 높음
- 유형: 기능 오류 / 인증 장애

기존 `bindPasswordEnc` 가 있는 LDAP 설정을 비밀번호 입력 없이 수정하면 새 설정에 기존 암호문이 보존되지 않는다.

근거:

- [ldap-providers/+page.server.ts:14-52](/Users/henry/github/henryj-dev/lodestar/src/routes/admin/ldap-providers/+page.server.ts:14) — `buildConfig` 가 폼 데이터만으로 새 객체를 생성
- [ldap-providers/+page.server.ts:164](/Users/henry/github/henryj-dev/lodestar/src/routes/admin/ldap-providers/+page.server.ts:164) — 기존 행 조회 없이 config 재구성
- [ldap-providers/+page.server.ts:171](/Users/henry/github/henryj-dev/lodestar/src/routes/admin/ldap-providers/+page.server.ts:171) — `configJson` 을 통째로 덮어씀

결정적 근거는 코드가 스스로 반대 주장을 하고 있다는 점이다:

```ts
// ldap-providers/+page.server.ts:60-63
if (!config.bindPassword) {
    // 새 bindPassword 입력이 없으면 그대로 통과 (기존 enc 만 보존됨)   ← 사실과 다름
    return config;
}
```

`config` 는 방금 폼에서 만들어진 객체라 보존할 `bindPasswordEnc` 자체가 존재하지 않는다. 관리자가 호스트·포트·속성만 수정해도 LDAP bind password 가 삭제되어 인증이 중단된다.

권장 조치:

- 기존 행을 먼저 조회
- 새 비밀번호가 비어 있으면 기존 `bindPasswordEnc` 유지
- 새 비밀번호가 있을 때만 암호문 교체
- 잘못된 주석 정정
- 설정 일부 수정 회귀 테스트 추가

### K-007 — 서버측 OIDC/SLO 웹훅의 리다이렉트 추종 및 timeout 부재

- 심각도: 중간~높음
- 유형: SSRF 가드 우회 / 가용성 저하

두 웹훅 fetch 에 `redirect: "manual"` 과 timeout 이 모두 없다(fetch 기본값은 `follow`).

근거:

- [oidc/role-change.ts:106-115](/Users/henry/github/henryj-dev/lodestar/src/lib/server/oidc/role-change.ts:106) — `assertPublicWebhookUrl` + `assertResolvedHostAllowed` 직후 무방비 `fetch`
- [oidc/logout.ts:244-252](/Users/henry/github/henryj-dev/lodestar/src/lib/server/oidc/logout.ts:244) — 동일 패턴

등록·발송 시점에 SSRF 게이트를 두 겹 통과시켜 놓고도, 검증을 통과한 호스트가 3xx 로 내부 주소를 가리키면 **가드가 통째로 우회**되어 내부 주소로 요청이 발생한다. 특히 307/308 리다이렉트에서는 서명된 `logout_token` / `role_change_token` body까지 그 목적지로 재전송될 수 있다(301/302는 Fetch 동작상 POST가 GET으로 바뀌어 body가 제거될 수 있음). 수신 서버가 연결을 지연시키면 요청 또는 백그라운드 작업이 장시간 점유된다.

같은 저장소의 [oauth/http.ts:48-66](/Users/henry/github/henryj-dev/lodestar/src/lib/server/oauth/http.ts:48) 은 정확히 이 이유로 `redirect: "manual"` + 3xx 거부를 쓰며, Workers 에서 `redirect: "error"` 를 쓰면 안 되는 이유까지 주석으로 남겨 두었다. 웹훅 경로만 이 패턴이 적용되지 않았다.

권장 조치:

- `redirect: "manual"` 적용 후 3xx 를 실패로 처리 (1순위)
- `AbortController` 와 짧은 timeout 적용
- 실패 시 제한된 재시도 또는 큐 기반 비동기 처리
- 응답 상태와 timeout 을 감사 로그에 기록

### K-001 — 서비스 TOTP API 교차 테넌트 접근

- 심각도: 중간 (현재 도달 불가, 멀티테넌트 활성화 시 높음)
- 유형: 권한 우회 / IDOR / 테넌트 격리 실패

서비스 토큰은 현재 요청 테넌트 기준으로 검증되지만, TOTP API 에서 `userId` 를 조회할 때 사용자의 `tenantId` 를 함께 확인하지 않는다.

근거:

- [enroll/init/+server.ts:38](/Users/henry/github/henryj-dev/lodestar/src/routes/api/totp/enroll/init/+server.ts:38)
- [enroll/init/+server.ts:41-45](/Users/henry/github/henryj-dev/lodestar/src/routes/api/totp/enroll/init/+server.ts:41)
- [enroll/confirm/+server.ts:46](/Users/henry/github/henryj-dev/lodestar/src/routes/api/totp/enroll/confirm/+server.ts:46)
- [verify/+server.ts:57-61](/Users/henry/github/henryj-dev/lodestar/src/routes/api/totp/verify/+server.ts:57)
- [status/+server.ts:19-28](/Users/henry/github/henryj-dev/lodestar/src/routes/api/totp/status/+server.ts:19)

테넌트 A 의 유효 서비스 토큰과 테넌트 B 사용자의 UUID 를 조합하면 TOTP 등록, 검증, 상태 조회가 가능하다.

**현재 도달 가능성**: 모든 HTTP 요청이 `DEFAULT_TENANT_SLUG` 로 고정되므로(K-009) 지금은 두 번째 테넌트 컨텍스트에 도달할 경로가 없다. 다만 이것은 "나중에 볼 문제"라는 뜻이 아니다 — 저장소는 이미 이 통제를 **구현해 두었고**, TOTP 4개 라우트만 빠져 있는 일관성 결함이다.

- [guards.ts:95-109](/Users/henry/github/henryj-dev/lodestar/src/lib/server/auth/guards.ts:95) — `assertUserInTenant()` (admin 라우트용, 주석에 "멀티테넌트 활성화 즉시 폭발하는 결함이라 사전 차단"이라고 명시)
- [users/lookup/+server.ts:70](/Users/henry/github/henryj-dev/lodestar/src/routes/api/users/lookup/+server.ts:70) — 서비스 API 도 `users.tenantId` 로 스코프 (단, K-011 의 결함은 별개)

권장 조치:

- 모든 사용자 조회에 `users.tenantId = tenant.id` 추가 (또는 `assertUserInTenant` 재사용)
- credentials 조회는 테넌트 소속 사용자를 확인한 뒤 수행하거나 users 와 조인
- 서로 다른 테넌트의 사용자를 대상으로 하는 통합 테스트 추가

(1차 보고서의 "rate-limit 키에 테넌트 ID 포함" 권고는 철회한다 — K-008 참조.)

### K-006 — 레거시 LDAP 평문 비밀번호가 관리자 브라우저로 전달됨

- 심각도: 중간
- 유형: 민감정보 노출

LDAP 목록 응답이 `configJson` 을 그대로 내려보내며, UI 가 그 안의 `bindPassword` 를 password input 의 value 로 사용한다.

근거:

- [ldap-providers/+page.server.ts:76-82](/Users/henry/github/henryj-dev/lodestar/src/routes/admin/ldap-providers/+page.server.ts:76) — `select()` 전체 반환
- [ldap-providers/+page.svelte:17-23](/Users/henry/github/henryj-dev/lodestar/src/routes/admin/ldap-providers/+page.svelte:17) — 클라이언트에서 `configJson` 파싱
- [ldap-providers/+page.svelte:355](/Users/henry/github/henryj-dev/lodestar/src/routes/admin/ldap-providers/+page.svelte:355) — `value={c.bindPassword ?? ""}`

레거시 평문 설정이 남아 있으면 SSR HTML, hydration 데이터, 브라우저 DOM 에 비밀번호가 노출된다. 평문뿐 아니라 **`bindPasswordEnc` 암호문도 함께 나간다** — 위험도는 낮지만 같은 DTO 화이트리스트로 처리해야 한다.

권장 조치:

- 서버에서 `bindPassword` 와 `bindPasswordEnc` 를 제거한 DTO 반환
- 비밀번호 필드는 항상 빈 값으로 렌더링 (K-005 수정과 함께여야 함 — 지금 빈 값으로만 바꾸면 저장 시 비밀번호가 지워진다)
- 기존 평문 설정은 읽기 시 암호화 후 평문 제거

### K-003 — 비밀번호 재설정에서 비밀번호 쓰기와 토큰 소진의 비원자성

- 심각도: 낮음
- 유형: 원자성 부족

재설정 토큰을 조회한 뒤 비밀번호 변경과 토큰 소진을 각각 별도 write 로 수행한다.

근거:

- [reset-password/+page.server.ts:102-129](</Users/henry/github/henryj-dev/lodestar/src/routes/(auth)/reset-password/+page.server.ts:102>) — 조회(102) → 비밀번호 쓰기(124/126) → 토큰 소진(129)

1차 보고서는 "동시 요청이 같은 토큰의 `usedAt IS NULL` 조회를 모두 통과할 수 있다"를 근거로 중간~높음으로 평가했으나, 이는 과대평가다. 두 요청 모두 **토큰 보유자**이므로 결과는 "비밀번호가 두 번 쓰인다"이지 권한 획득이 아니며, [line 132-140](</Users/henry/github/henryj-dev/lodestar/src/routes/(auth)/reset-password/+page.server.ts:132>) 이 같은 사용자의 미사용 토큰을 일괄 소진하고 세션·refresh token·신뢰기기를 모두 폐기한다.

실제로 유효한 근거는 **쓰기 순서와 부분 성공**이다. 비밀번호 쓰기가 토큰 소진보다 먼저 일어나고 전체 작업이 원자적이지 않으므로, 앞 단계가 성공하고 이후 토큰 소진 또는 세션·refresh token 폐기가 실패하면 **이미 사용된 재설정 링크가 만료까지 계속 유효**하거나 일부 세션이 남을 수 있다. 동시 요청 문제 외에도 비밀번호 credential 변경/삽입, 토큰 소진, 세션 폐기를 하나의 트랜잭션으로 묶어야 한다.

권장 조치:

- 토큰 소비를 `UPDATE ... WHERE tokenHash = ? AND usedAt IS NULL` 로 원자화하고 **먼저** 수행
- 영향받은 행이 1개가 아니면 실패 처리
- 비밀번호 변경, 토큰 소비를 `runAtomic` 으로 묶기 (동일 유틸이 [db/atomic.ts](/Users/henry/github/henryj-dev/lodestar/src/lib/server/db/atomic.ts:35) 에 이미 존재)

### K-013 — LDAP provider `update` 액션에 감사 로그 없음

- 심각도: 중간
- 유형: 감사 추적 공백

같은 파일의 `create`·`delete` 는 `recordAuditEvent` 를 남기지만 `update` 만 없다.

근거:

- [ldap-providers/+page.server.ts:128-136](/Users/henry/github/henryj-dev/lodestar/src/routes/admin/ldap-providers/+page.server.ts:128) — create: 기록 있음
- [ldap-providers/+page.server.ts:141-175](/Users/henry/github/henryj-dev/lodestar/src/routes/admin/ldap-providers/+page.server.ts:141) — update: 기록 **없음**
- [ldap-providers/+page.server.ts:188-197](/Users/henry/github/henryj-dev/lodestar/src/routes/admin/ldap-providers/+page.server.ts:188) — delete: 기록 있음

세 액션 중 가장 민감한 것이 update 다 — LDAP 호스트를 공격자 서버로 바꿔 사용자 자격증명을 수확하는 변경이 흔적 없이 가능하다. `enabled` 토글도 같은 액션을 지나간다.

권장 조치:

- `ldap_provider_updated` 감사 이벤트 추가 (변경 필드 목록, 비밀번호 교체 여부 플래그 포함, 값 자체는 제외)
- 다른 admin 라우트의 update 액션도 동일 누락이 있는지 점검

### K-014 — LDAP identity 정합성 오류 시 교차 테넌트 사용자 갱신 가능성

- 심각도: 낮음~중간 (전제: 교차 테넌트 identity 행 또는 DB 정합성 오류)
- 유형: 테넌트 격리 방어 부족 / 데이터 무결성

`provisionLdapUser()`는 identity를 조회할 때는 `tenantId`를 사용하지만, 기존 identity가 발견된 뒤 사용자를 갱신·조회할 때는 `users.id`와 `status`만 조건으로 사용한다.

근거:

- [ldap/provision.ts:25-30](/Users/henry/github/henryj-dev/lodestar/src/lib/server/ldap/provision.ts:25) — identity 조회는 tenant 스코프
- [ldap/provision.ts:34-42](/Users/henry/github/henryj-dev/lodestar/src/lib/server/ldap/provision.ts:34) — 사용자 갱신은 `users.id`만 조건
- [ldap/provision.ts:49-53](/Users/henry/github/henryj-dev/lodestar/src/lib/server/ldap/provision.ts:49) — 사용자 반환도 `users.id`와 status만 조건

정상적인 생성 경로에서는 identity와 user의 테넌트가 일치하지만, 잘못된 마이그레이션·직접 DB 조작·기존 정합성 오류로 다른 테넌트의 userId를 가리키는 identity가 들어가면 LDAP 로그인 처리 중 다른 테넌트 사용자의 프로필을 갱신하고 반환할 수 있다. 즉시 원격에서 재현되는 단독 공격이라기보다, 테넌트 경계를 DB 조회 단계에서도 일관되게 강제하지 않은 잠재 결함이다.

권장 조치:

- 사용자 갱신·조회 조건에 `eq(users.tenantId, tenantId)` 추가
- identity의 `tenantId`와 user의 `tenantId`가 다르면 fail-closed
- 잘못된 identity 정합성을 탐지하는 테스트와 무결성 점검 추가

### K-012 — Node 배포에서 rate limit 이 프로세스 로컬

- 심각도: 중간 (Node 다중 인스턴스 배포 시), Workers 단독 배포 시 해당 없음
- 유형: 인증 통제 약화 / 배포 형태 의존

근거:

- [ratelimit/store.ts:163-166](/Users/henry/github/henryj-dev/lodestar/src/lib/server/ratelimit/store.ts:163)

```ts
const isWorkers = typeof platform?.ctx?.waitUntil === "function";
return isWorkers ? new DbRateLimitStore(db) : getMemoryRateLimitStore();
```

기존 구현은 adapter-node 다중 레플리카에서 프로세스별 카운터가 독립되는 구조였다. 이제 `RATELIMIT_STORE=memory|db|redis`를 선택할 수 있고, Node memory 경로에는 운영 경고를 추가했다. DB는 기존 `rate_limits` 테이블을 공유하고 Redis는 Upstash 호환 REST EVAL로 원자 증가한다.

대응:

- `RATELIMIT_STORE=db|redis`로 Node 다중 인스턴스 공유 저장소를 선택
- memory 선택 시 `APP_INSTANCE_COUNT` 및 운영 경고로 잘못된 배포를 알림

### K-008 — TOTP rate-limit namespace 에 테넌트 ID 없음

- 심각도: 낮음 (개선 제안)
- 유형: 관측성 / 쿼터 정책

근거:

- [enroll/init/+server.ts:33](/Users/henry/github/henryj-dev/lodestar/src/routes/api/totp/enroll/init/+server.ts:33)
- [enroll/confirm/+server.ts:41](/Users/henry/github/henryj-dev/lodestar/src/routes/api/totp/enroll/confirm/+server.ts:41)
- [verify/+server.ts:52](/Users/henry/github/henryj-dev/lodestar/src/routes/api/totp/verify/+server.ts:52)

`users.id`는 테넌트 무관 전역 UUID PK라 충돌은 불가능하지만, 멀티테넌트별 quota·관측성을 위해 서비스 TOTP와 웹/계정 MFA의 키를 `tenantId:userId`로 정규화했다.

대응:

- `totp-enroll-init`, `totp-enroll-confirm`, `totp-verify`, 웹 MFA, 계정 MFA에 tenant ID namespace 적용

### K-009 — HTTP 요청 컨텍스트가 기본 테넌트로 고정

- 심각도: 기능 미완성
- 유형: 멀티테넌트 라우팅 부재

근거:

- [bootstrap.ts:13-40](/Users/henry/github/henryj-dev/lodestar/src/lib/server/auth/bootstrap.ts:13) — `ensureDefaultTenant` 가 `DEFAULT_TENANT_SLUG` 로 고정 조회
- [bootstrap.ts:128-145](/Users/henry/github/henryj-dev/lodestar/src/lib/server/auth/bootstrap.ts:128) — isolate 전역 캐시에 단일 tenant 보관
- [hooks.server.ts:135](/Users/henry/github/henryj-dev/lodestar/src/hooks.server.ts:135) — 요청마다 이 값을 `locals.tenant` 로 사용

데이터베이스에는 테넌트 컬럼이 있지만 요청마다 `DEFAULT_TENANT_SLUG` 를 사용한다. 도메인, Host, 명시적 tenant context 에 따른 테넌트 선택은 구현되어 있지 않다. `globalThis.__idpBaselineCache` 가 단일 tenant 객체를 캐시하므로, 멀티테넌트를 켜려면 이 캐시 구조부터 키 기반으로 바꿔야 한다.

멀티테넌트 제품이 목표라면 테넌트 식별 정책과 세션·서비스 토큰·프로토콜 엔드포인트의 테넌트 바인딩이 추가로 필요하다.

## 철회된 항목

### ~~K-010 — 실제 Wrangler 설정 부재~~ (철회)

1차 보고서는 `wrangler.jsonc` 부재를 "기능/배포 차단 가능"으로 분류했으나 **사실 오류다.** 이 파일은 의도적으로 커밋하지 않는다.

```
.gitignore:
  wrangler.jsonc
  wrangler.*.jsonc
  !wrangler.example.jsonc
```

`README.md:212` 가 `wrangler.example.jsonc → wrangler.jsonc` 복사를 셋업 절차로 명시한다. account_id, D1 database id, SMTP 자격 등이 들어가는 파일이라 추적하지 않는 것이 정상이며, `docs/improvement-report-2026-07-02.md` 의 E7 항목은 과거 이 계열 파일에 평문 자격이 방치됐던 사고를 다룬다. 갓 클론한 트리에서 `bun run check` 가 실패하는 것은 셋업 미수행이지 결함이 아니다.

## 잔여 운영 작업·범위

코드 회귀 테스트로 확인할 수 있는 감사 공백은 이번 브랜치에서 보강했다. 남은 항목은 배포 환경에 의존하는 운영 작업이다.

- Queue producer binding과 consumer Worker/Workflow를 배포 환경에 연결하고, consumer에서 `deliverQueuedOidcWebhook`를 호출해야 한다.
- `bun run db:check-tenant-consistency`는 대상 DB 자격과 운영 범위를 확인한 뒤 사용자가 실행해야 한다. 이 브랜치에서는 원격 DB에 연결하지 않았다.
- PR 리뷰와 감사 항목별 커밋 이력 확인이 필요하다.

코드에서 런타임용 명시적 `TODO`, `mock`, `dummy` 구현은 핵심 경로에서 확인되지 않았다. 테스트용 더미 해시와 fixture 는 계정 열거 방지 및 테스트 목적으로 사용되고 있다.

## 감사 대응 상태

| 항목              | 대응 상태                                                                                      |
| ----------------- | ---------------------------------------------------------------------------------------------- |
| K-011             | 수정 완료 — lookup을 현재 요청 tenant에 고정하고 교차 테넌트·rate-limit 테스트 추가            |
| K-004             | 수정 완료 — JWKS가 공용 SSRF/timeout/body-limit 경로를 사용하고 캐시 상한 추가                 |
| K-002             | 수정 완료 — TOTP·백업 코드 조건부 원자 소비 및 동시성 테스트 추가                              |
| K-005/K-006/K-013 | 수정 완료 — LDAP 암호 보존·DTO 비밀 제거·레거시 암호화·update/skin 감사 기록                   |
| K-007             | 수정 완료 — 공용 POST 헬퍼에 manual redirect·timeout·3xx 거부·재시도·Queue 전달·감사 기록 적용 |
| K-001/K-014       | 수정 완료 — 서비스 TOTP와 LDAP provision에 tenant 경계·불일치 감사 기록 추가                   |
| K-003             | 수정 완료 — reset token 선소진 및 후속 credential/token write 원자화                           |
| K-012             | 수정 완료 — Node에서 memory/db/Redis 저장소 선택과 다중 인스턴스 경고 지원                     |
| K-009             | 수정 완료 — `/t/<slug>`·서브도메인 라우팅, tenant별 cache·세션·issuer 전략 지원                |
| K-008             | 수정 완료 — TOTP rate-limit namespace에 tenant ID 추가                                         |
| K-010             | 철회 — Wrangler 설정 부재는 gitignore에 의한 정상 설계                                         |

구체적인 변경 파일·회귀 테스트·잔여 정책 결정은 [CODE_AUDIT_TODO.md](./CODE_AUDIT_TODO.md)의 완료 기준과 진행 요약표를 따른다.

## 검증 결과

감사 대응 브랜치에서 `wrangler.jsonc`를 로컬 셋업하고 의존성을 설치한 뒤 재검증했다. `wrangler.jsonc`는 계정·D1·SMTP 자격이 포함될 수 있어 계속 추적하지 않는다.

| 명령            | 결과                                 |
| --------------- | ------------------------------------ |
| `bun run test`  | 통과 — 48개 파일, 460개 테스트       |
| `bun run check` | 통과 — `svelte-check` 오류 0, 경고 0 |
| `bun run lint`  | 통과 — Prettier 및 ESLint            |
| `bunx eslint .` | 통과                                 |

기존 베이스라인 434개 테스트 대비 26개 회귀 테스트를 추가했다. 교차 테넌트·tenant routing·issuer 전략, TOTP namespace·백업 코드 동시 소비, JWKS SSRF·캐시 상한, Redis rate-limit, 웹훅 리다이렉트·timeout·재시도·감사 기록, LDAP 암호 보존·DTO·감사 로그·정합성, reset token 선소진을 검증한다. Svelte MCP autofixer는 현재 세션의 도구 목록에는 노출되지 않아 `svelte-check`로 검증했다.

## 권장 수정 순서

| 순서 | 항목                                      | 근거                                    |
| ---- | ----------------------------------------- | --------------------------------------- |
| 1    | K-011 `/api/users/lookup` 테넌트 스코프   | 파라미터 하나로 즉시 도달, 수정은 수 줄 |
| 2    | K-004 JWKS fetch 를 `getJson()` 으로 교체 | 방어선 6종이 한 번에 복구됨             |
| 3    | K-002 TOTP·백업 코드 원자적 소비          | 인증 통제                               |
| 4    | K-005 LDAP 암호화 비밀번호 보존           | 운영 장애 직결                          |
| 5    | K-007 웹훅 `redirect: "manual"` + timeout | SSRF 가드 우회                          |
| 6    | K-001 TOTP 테넌트 검증                    | 기존 `assertUserInTenant` 재사용        |
| 7    | K-006 LDAP 응답 DTO 화이트리스트          | K-005 와 같은 파일, 함께 처리           |
| 8    | K-003 재설정 토큰 선(先)소진 + 원자화     | 정합성                                  |
| 9    | K-013 LDAP update 감사 이벤트             | 감사 추적                               |
| 10   | K-012 Node rate limit 배포 형태 명시      | 정책 결정 필요                          |
| 11   | K-008 rate-limit 키 네임스페이스          | 운영 편의                               |
| 12   | K-009 멀티테넌트 라우팅 구현              | `/t/<slug>`·서브도메인·tenant binding   |

## 개정 이력

**2차 (코드 재대조)** — 1차 보고서의 10개 항목을 소스와 전수 대조한 결과:

- **철회 1건**: K-010 (wrangler.jsonc 부재는 gitignore 에 의한 의도된 설계)
- **심각도 하향 2건**: K-003 (중간~높음 → 낮음, 근거를 동시성에서 쓰기 순서로 교체), K-008 (중간 → 낮음, userId 가 전역 UUID 라 이미 충돌 불가)
- **심각도 재조정 2건**: K-001 (높음 → 중간, 현재 도달 불가하나 일관성 결함으로 근거 강화), K-007 (중간 → 중간~높음, timeout 이 아니라 리다이렉트 추종이 본질)
- **신규 4건**: K-011 (users/lookup 교차 테넌트), K-013 (LDAP update 감사 누락), K-012 (Node rate limit 프로세스 로컬 — 1차에서는 테스트 공백으로 오분류), K-014 (LDAP identity/user 테넌트 정합성 방어 부족)
- **근거 보강 3건**: K-004 (우회되는 방어 6종 표로 명시), K-005 (코드 주석이 사실과 반대라는 결정적 근거 추가), K-006 (암호문도 함께 유출)
- **정정·추가 보강**: K-011 환경변수 서비스 토큰 경로 명시, K-004 JWKS 캐시 증가 위험 추가, K-007 리다이렉트 상태 코드별 body 전달 차이 명시, K-003 비원자적 부분 쓰기 범위 확대, 테스트 개수 정정
- **검증 결과 섹션 정정**: 세 실패가 모두 감사 환경 문제였고 `bun test --run` 은 잘못된 명령이었음을 명시

**3차 (선택 옵션 반영)** — 보류 항목을 구현하고 재검증한 결과:

- Node rate-limit DB/Redis 선택 및 memory 운영 경고 추가
- TOTP rate-limit tenant namespace 추가
- `/t/<slug>`·서브도메인 tenant 라우팅, tenant별 baseline cache·세션·issuer 전략 추가
- 웹훅 3회 재시도·Queue 전달 지점 추가
- LDAP 정합성 일회성 스크립트와 GC 주기 점검 추가
- 최종 검증: 48개 파일, 460개 테스트 통과
