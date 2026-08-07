# 실행 투두 — 후속 3차 마감 (6 페이즈)

> **상태: 완료 (병합됨). 이 문서는 실행 이력이며 현행 사양서가 아닙니다.**
> 미체크로 남은 항목은 당시 커밋/검증 게이트 절차이고, 작업 자체는 병합되었습니다.
> **마이그레이션의 실제 DB 적용 여부는 배포 환경에서 직접 확인하세요.**
> 현행 사양은 [README](../../../README.md) · [관리자 매뉴얼](../../ADMIN_GUIDE.md) 참조. (최종 확인: 2026-08-07)

> 승인(2026-07-06, 게이트①): 기획 승인 · P15 rate-limit = **인터페이스만 추상화**(Workers DB 유지, Node in-memory, DO 미도입) · 기능 = **프로필 이메일 변경 + organization 세분화 UI + 백업코드 경고 전부 포함** · 세션 철회 알림 = **본인 직접 철회도 발송**.
> 규칙: 스키마 변경은 `db:generate:all`까지만(적용 금지). 커밋은 전체 검증 통과 + 커밋 승인 후, 푸시 금지. 쓰기=Opus 위임, 검증=작성자와 분리된 독립 Opus. 스텁/TODO/skip은 블로커.
> 순서: P12 → P13/P14 병렬 → P15 → P16(신규 로직 통합) → P17. 스키마 건드리는 P12(B5)·P13(F3)·P17(D2)는 마이그레이션 순서 직렬.

---

## Phase 12 — 잔여 버그·보안·운영 마감

**목적**: 전수 재조사 발견 항목(저비용 고가치) 해소.

### [x] 12-1. B1 invite_tokens GC 누락 (Medium)

- 파일: `src/lib/server/db/gc.ts`
- 작업: invite_tokens purge 추가(다른 토큰 테이블과 동일 시맨틱 — `lt(expiresAt, now)` 또는 `or(lt(expiresAt,now), isNotNull(usedAt))`). 기존 테이블별 에러 격리 패턴 준수. `test/unit/gc.test.ts`에 조건 테스트 추가.
- 수용 기준: invite_tokens가 GC 대상에 포함, 미만료·미소진 보존. gc 테스트 통과.

### [x] 12-2. B2 organization scope id_token 불일치 (표준 위배)

- 파일: `src/routes/oidc/token/+server.ts`, 참고 `oidc/userinfo/+server.ts:120-154`
- 작업: token의 id_token 클레임 생성에 `scopes.has("organization")` 분기 추가(userinfo와 동일하게 department/team/position/job_title 매핑). 공통 로직은 `oidc/claims.ts`로 추출해 token/userinfo 공유(중복 방지). `groups`와 `organization`의 각 노출 범위를 정확히 재현.
- 수용 기준: organization scope 요청 시 id_token·userinfo가 동일 조직 클레임. groups scope 동작 무회귀. 통합 테스트(P16)로 커버.

### [x] 12-3. B3 accept-invite status 검증 + 초대계정 상태 (Low보안)

- 파일: `src/routes/(auth)/accept-invite/+page.server.ts`, `src/routes/admin/users/+page.server.ts`
- 작업: (a) `lookupToken` 조인에 `eq(users.status, "active")` 추가, 소진 직전 status 재확인(disabled/deletion_pending 계정에 credential 심기 방지). (b) 초대 미수락 계정의 admin 카운트 오염 — `assertNotLastAdmin`/admin 집계가 credential 존재(=실사용 가능)를 기준으로 판정하도록 보강. 초대 계정 상태 표현은 기존 배지 로직(invite_token 보유)과 정합 유지.
- 수용 기준: 비활성/삭제예정 계정은 초대 수락 불가. 미수락 초대 admin이 마지막 admin 삭제 차단을 잘못 완화하지 않음.

### [x] 12-4. B4 헬스체크 readiness (Low운영)

- 파일: `src/routes/api/health/+server.ts`
- 작업: DB 연결 확인(가벼운 SELECT 1) 후 실패 시 503, 성공 시 200. liveness/readiness 구분이 유용하면 쿼리파라미터로. 기존 응답 형식 최대한 보존.
- 수용 기준: DB unavailable 시 503. 정상 시 200. 과도한 부하 없음(경량 쿼리).

### [x] 12-5. B5 users 하드삭제 인덱스+배치 (Low)

- 파일: `src/lib/server/db/schema.{sqlite,pg,mysql}.ts`, `src/lib/server/db/gc.ts`
- 작업: users에 `deletionScheduledAt`(+status) 조회를 지원하는 인덱스 추가(가능하면 부분 인덱스 `WHERE status='deletion_pending'` — 방언별 표현, mysql 미지원 시 일반 인덱스). GC users 하드삭제에 배치 LIMIT(대량 cascade 락 방지). `db:generate:all`.
- 수용 기준: 3방언 parity(인덱스 예외 목록 갱신). GC가 배치 삭제. 미경과 계정 미삭제 유지.

### [x] 12-6. B6 잔여 하드코딩 한국어 (Low)

- 파일: `src/routes/account/profile/+page.server.ts:52`(생년월일 형식), `src/routes/(auth)/accept-invite/+page.server.ts:77`(credential label)
- 작업: `translate(locals.locale, ...)` 전환, ko/en 키 추가. (email.ts 메일 i18n은 P13 F1에서.)
- 수용 기준: 대상 2곳 한국어 리터럴 제거, ko/en 대칭.

### [x] 12-검증 (독립 Opus) — 통과(2026-07-06, 로직 VERIFIED): organization 버그 표준정합·groups 무회귀, admin카운트·GC·헬스체크·인덱스 정확(prettier 정리). V2/V3/V6 전용 테스트는 P16에 반영

- organization 버그 수정의 표준 정합(id_token=userinfo), GC 조건 보수성, accept-invite status 가드, 헬스체크 503, 인덱스 parity. 게이트 4종.

---

## Phase 13 — 메일 i18n + 세션 철회 알림 + 프로필 이메일 변경

**목적**: 메일 locale 인지, 세션 철회 알림, 이메일 변경 플로우.
**파일 경계**: F1(email.ts)·F2(sessions)·F3(profile+email.ts) — email.ts 공유이므로 F1→F2/F3 순서 또는 단일 에이전트.

### [x] 13-1. F1 메일 전량 locale 인지

- 파일: `src/lib/server/email.ts`, 발송 호출부(reset-password/verify-email/accept-invite/invite)
- 작업: `sendPasswordResetEmail`/`sendEmailVerificationEmail`/`sendInviteEmail`·`baseHtml`을 수신자 locale 인자 받도록(보안 알림 메일 패턴 확장). 제목·본문·푸터·`lang` 속성 i18n. 호출부에서 대상 사용자 locale 전달(없으면 요청 locale 또는 ko 기본). i18n 키 ko/en.
- 수용 기준: 각 메일이 수신자 locale로 렌더. escape/safe-URL 유지. 발송 best-effort 유지.

### [x] 13-2. F2 세션 철회 보안 알림

- 파일: `src/routes/account/sessions/+page.server.ts`, `src/lib/server/security-notify.ts`(kind 추가), i18n
- 작업: `SecurityEventKind`에 `session_revoked`/`sessions_revoked_all` 추가 + `security_alert.*` ko/en 3줄씩. sessions revoke/revokeOthers 액션에 `dispatchSecurityAlert`(best-effort) 추가 — **본인 직접 철회도 발송**(승인됨). 현재 세션 철회(로그아웃) 케이스에도 일관.
- 수용 기준: 세션 철회 시 알림 메일 경로 존재. best-effort 격리. i18n 대칭.

### [x] 13-3. F3 프로필 이메일 변경 (중간~높음)

- 파일: `src/lib/server/db/schema.{sqlite,pg,mysql}.ts`(`pendingEmail`+`pendingEmailRequestedAt`), `src/routes/account/profile/+page.server.ts`(changeEmail 액션)·`+page.svelte`, confirm 라우트 `src/routes/account/confirm-email-change/`(신규), 토큰(email_verification_tokens 파라미터화 또는 신규 `email_change_tokens`), `security-notify.ts`(email_change kind), i18n
- 작업: changeEmail 액션 — **현 비밀번호 재인증** → 중복 이메일 체크 → `pendingEmail` 저장 + 새 주소로 인증 토큰 메일 → confirm 라우트에서 토큰 검증 후 `email` 교체·`pendingEmail` 클리어·`emailVerifiedAt` 갱신(원자적 `runAtomic`). **기존 이메일에 "변경 시도" 알림**(탈취 방어). profile UI에 이메일 input + 현 비밀번호 + "확인 대기" 배너. rate-limit. `db:generate:all`.
- 수용 기준: 이메일 변경→새 주소 인증→교체 동작. 재인증 없이 변경 불가. 기존 주소 알림. 토큰 1회용·만료. 중복 이메일 차단. 스키마 parity.

### [x] 13-검증 (독립 Opus) — 통과(APPROVE): 메일 locale, 세션 알림, 이메일변경(재인증·targetEmail 바인딩·원자성·기존주소 알림). profile UI 별도 마무리. sessions 하드코딩 한국어 2건은 P17로

- 메일 locale 렌더, 세션 알림 격리, 이메일 변경의 재인증·토큰 보안·기존주소 알림·원자성·중복 차단. 마이그레이션 생성만. 게이트.

---

## Phase 14 — UX a11y/loading + 스킨 복구 패널

**목적**: 접근성·제출 피드백·스킨 복구.

### [x] 14-1. U1 a11y 에러 배너 + 포커스

- 파일: 8개 auth `.svelte`(login/signup/mfa/reset-password/find-id/find-password/accept-invite/verify-email), 가능하면 공용 컴포넌트 `src/lib/components/FormError.svelte`(신규)
- 작업: 에러 배너에 `role="alert"`/`aria-live="assertive"`. 실패 후 배너/실패 필드로 포커스 이동(`tabindex=-1`+focus 또는 autofocus 로직). 공용 컴포넌트로 추출해 일관 적용.
- 수용 기준: 8개 폼 에러가 스크린리더 announce. 포커스 이동. 시각 동작 무회귀. svelte-autofixer 통과.

### [x] 14-2. U2 loading 상태

- 파일: 위 8개 폼(패스키 별도 흐름 제외), 공용 enhance 패턴
- 작업: 메인 제출 폼에 `use:enhance` + 제출 중 버튼 disabled + 스피너/텍스트. SSR 폴백 유지(JS 없어도 동작). 공용 패턴/컴포넌트로.
- 수용 기준: 제출 중 중복 클릭 방지·로딩 표시. JS 비활성에도 폼 동작(progressive enhancement). 기존 리다이렉트/에러 흐름 무회귀.

### [x] 14-3. U3 스킨 로그인 복구 패널 (옵션 B)

- 파일: `src/routes/(auth)/login/+page.svelte`, 필요시 `+page.server.ts`
- 작업: 스킨 렌더 조건을 `{#if skinHtmlEffective && !form?.recovery}`로 바꿔 복구(soft-delete) 케이스는 기본 UI 강제 노출(스킨 작성자 개입 불필요). 또는 recovery 반환에 skinHtml 채우고 기본 패널 우선. 스킨 로그인에서도 복구 프롬프트·`recover=1` 접근 가능.
- 수용 기준: 스킨 로그인에서 삭제예정 계정이 복구 패널 도달. 일반 스킨 로그인 무회귀.

### [x] 14-검증 (독립 Opus) — 통과(APPROVE): FormError role=alert+포커스, use:enhance progressive enhancement(JS off 동작), 스킨 복구 도달. 803키 대칭

- role/aria 적용, 포커스, progressive enhancement(JS off 동작), 스킨 복구 도달. 게이트.

---

## Phase 15 — rate-limit 저장소 추상화 (인터페이스만, Node in-memory)

**목적**: 저장소 추상화로 DB 4방언 분기·login 중복 제거. Workers는 현행 DB 유지, Node는 in-memory.

### [x] 15-1. A1 RateLimitStore 인터페이스

- 파일: `src/lib/server/ratelimit/store.ts`(신규 인터페이스+구현), `src/lib/server/ratelimit/index.ts`
- 작업: `RateLimitStore { increment(key,windowMs): {current,prev}; peek(key,windowMs): {current,prev} }` 정의. `checkRateLimit(store, key, opts)`로 슬라이딩 윈도우 수식 유지·저장소 위임. **DbRateLimitStore**(현 DB 로직 이관 — 4방언 분기 캡슐화)와 **MemoryRateLimitStore**(Map) 구현. `locals.rateLimitStore`를 hooks에서 요청당 1회 해석(Workers=DB, Node=memory; `db/index.ts` isWorkers 판별 재사용).
- 수용 기준: 알고리즘 동일(기존 ratelimit 테스트 통과). peek/increment 분리. Workers=DB·Node=memory 분기.

### [x] 15-2. A2 호출부 이관 + login 중복 제거

- 파일: rate-limit 호출부 21곳, `src/routes/(auth)/login/+page.server.ts`(accountLockStatus)
- 작업: `checkRateLimit(db,...)` → `checkRateLimit(locals.rateLimitStore,...)` 기계적 교체. login의 중복 `accountLockStatus` 구현을 `store.peek()`로 대체. 기존 `rate_limits` 테이블·스키마·`purgeExpiredRateLimits`/gc 호출은 Workers(DB store)가 계속 쓰므로 **유지**(Node memory는 자체 evict).
- 수용 기준: 21곳 정상 동작(429 분기 무회귀). login 계정 잠금 동작 동일. Node/Workers 양쪽 rate-limit 동작.

### [x] 15-3. A3 Node in-memory 한계 문서화

- 파일: `.env.example` 또는 README 관련 섹션
- 작업: Node in-memory rate-limit이 단일 인스턴스 가정임을 명시(다중 인스턴스 확장 시 한도 완화 → Redis store 필요, 이번 미도입). 인터페이스가 Redis/DO store 추가에 열려있음 안내.
- 수용 기준: 한계·확장 경로 문서화.

### [x] 15-검증 (독립 Opus) — 통과(APPROVE): 알고리즘 byte-identical, peek=accountLockStatus 정합, 24곳 무회귀, Workers/Node 빌드 그린. single-now 스레딩 미세개선 별도 처리

- 알고리즘 동일성(peek/increment가 기존 upsert+select와 같은 결과), 21곳 무회귀, login 잠금 정합, Node memory evict·격리. 게이트 + rate-limit 통합/유닛 테스트.

---

## Phase 16 — 테스트 심화 (하네스 확장, Playwright 제외)

**목적**: 커버리지 0% 구간(saml/ldap) + auth 통합. P12~15 신규 로직 포함.

### [x] 16-1. T1 하네스 확장

- 파일: `test/integration/harness.ts`
- 작업: `seedSamlSp`(samlSps 삽입), `seedIdentityProvider`(LDAP provider), cookies 체이닝 헬퍼(같은 makeCookies 재사용 공식화), SAML 서명 fixture(`test/unit/saml-verify-xml-signature.test.ts`의 makeKeyCert/signAuthnRequest 승격·공용화).
- 수용 기준: 헬퍼 추가, 기존 통합 테스트 무영향.

### [x] 16-2. T2 SAML SSO 통합 테스트

- 파일: `test/integration/saml-sso.test.ts`(신규)
- 작업: SP-initiated POST 바인딩 — 로그인 상태에서 authorize→SAML Response 검증(서명·audience·ACS), 서비스 권한 게이트 실패, AuthnRequest replay 가드. 실 서명키·실 라우트.
- 수용 기준: 풀플로우 그린, saml 커버리지 상승. tautology 없음.

### [x] 16-3. T3 로그인+MFA 체이닝 통합

- 파일: `test/integration/login-mfa.test.ts`(신규)
- 작업: 같은 cookies 인스턴스로 login(비번)→idp_mfa_pending→mfa(TOTP)→idp_session 발급 검증. 잘못된 코드 거부, rate-limit, 백업코드 경로(P17 D4와 정합).
- 수용 기준: 쿠키 왕복 재현, auth 커버리지 상승.

### [x] 16-4. T4 LDAP 로그인 통합 + 신규 로직 통합

- 파일: `test/integration/ldap-login.test.ts`(신규), 기존 통합에 P12~15 신규 로직 추가
- 작업: `seedIdentityProvider`로 login LDAP 분기(가능 범위 — 실 LDAP 서버 없이 되는 부분, mock LDAP client 필요 시 사유 보고). organization id_token 일치(B2), 이메일 변경(F3), rate-limit store(A) 통합 검증.
- 수용 기준: ldap 분기 커버(가능 범위), 신규 로직 통합 그린. 무리한 것은 제외·사유 보고.

### [x] 16-검증 (독립 Opus) — 통과(11기준 VERIFIED): SAML SSO·login+MFA·LDAP·P12로직·세션알림 통합 전부 실 DB/실 라우트(mock-echo 없음), single-now 정합. 총 211테스트(prettier 정리)

- 실 DB/실 라우트 구동(mock-echo 아님), fixture 정합, tautology·skip 없음. 게이트 + 전체 테스트 수.

---

## Phase 17 — 문서·잔여 마감

**목적**: admin 매뉴얼, organization 세분화 UI, 백업코드 경고, 관측성 기반.

### [x] 17-1. D1 admin 운영 매뉴얼

- 파일: `docs/ADMIN_GUIDE.md`(신규), `src/routes/admin/skins/guide/+page.svelte`(placeholder 갱신)
- 작업: 조직(dept/team/part/position) 관리, OIDC/SAML 클라이언트 등록, scope/role 설정, 스킨 등록 + placeholder 6종 전체(`IDP_FORM_ACTION`/`IDP_REDIRECT_TO`/`IDP_SKIN_HINT`/`IDP_REGISTERED`/`IDP_PASSWORD_RESET`/`IDP_FLASH_MSG`) 문서화, 서명키 회전, 감사로그 조회. skins/guide 페이지의 불완전한 placeholder 문서도 갱신.
- 수용 기준: 매뉴얼 존재, placeholder 실제값 정확.

### [x] 17-2. D2 organization 노출 세분화 UI (중간)

- 파일: `src/lib/server/db/schema.*.ts`(`oidcClients.organizationClaimConfig` JSON), `src/routes/admin/oidc-clients/[id]/+page.svelte`·server, `oidc/claims.ts`/token/userinfo(config 참조), i18n
- 작업: 클라이언트별 organization 클레임 토글(department/team/position/job_title 개별 노출). config 컬럼 추가, 매핑 로직이 config 참조(미설정 시 기존 전량 노출로 하위호환). oidc-clients 상세에 체크박스 그룹 + 설명. `db:generate:all`.
- 수용 기준: 토글대로 클레임 노출. 기존 클라이언트 하위호환(config null=전량). B2(id_token 일치)와 정합. parity.

### [x] 17-3. D4 백업코드 저잔량 경고

- 파일: `src/routes/(auth)/mfa/+page.server.ts`, `account/mfa`, security-notify(kind), i18n
- 작업: 로그인 시 backup_code 소비 후 잔량 계산 → 저잔량(예: ≤2) 경고 표시, 소진 시 알림 메일(`dispatchSecurityAlert` kind 추가). account/mfa의 잔량 표시와 정합.
- 수용 기준: 저잔량 경고·소진 알림. 오탐 없음.

### [x] 17-4. D3 관측성 기반 (Low)

- 파일: `src/lib/server/db/gc.ts`(GC 결과 구조화 로깅), 필요시 로깅 헬퍼
- 작업: GC 결과·주요 이벤트를 구조화 형태(JSON, tenant/requestId 가능 시)로 로깅하는 최소 기반. 전면 로거/메트릭/Sentry는 별도(범위 밖) — 훅 지점만 정리.
- 수용 기준: GC 결과 구조화 로그. 과설계 없음.

### [x] 17-검증 (독립 Opus) — 통과(로직 VERIFIED): organization 하위호환·id_token=userinfo 정합, 백업코드 오탐 방지, 문서 정확. config off 경로 유닛테스트 15케이스 추가(226테스트)

- organization config 하위호환·클레임 정합, 백업코드 경고 정확, 문서 정확성. 마이그레이션 생성만. 게이트.

---

## 최종 게이트 & 커밋 (STEP 7-8)

- [x] 전체(2026-07-06): `bun run test`(통합 포함) · `check` · `lint` · `build` · `typecheck` · `db:check`(4방언) · `db:generate:all` no-op — 전부 그린
- [x] 마이그레이션 생성물: users 인덱스(0025/0008)·email_change_tokens+pendingEmail(0026/0009)·organizationClaimConfig(0027/0010) — **적용은 사용자 몫**
- [ ] 커밋 승인 게이트 → 페이즈별 원자 커밋(공유 파일은 논리 배치). 푸시 금지.
