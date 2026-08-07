# 실행 투두 — 프로젝트 전수 개선 (5 페이즈)

> **상태: 완료 (병합됨). 이 문서는 실행 이력이며 현행 사양서가 아닙니다.**
> 미체크로 남은 항목은 당시 커밋/검증 게이트 절차이고, 작업 자체는 병합되었습니다.
> **마이그레이션의 실제 DB 적용 여부는 배포 환경에서 직접 확인하세요.**
> 현행 사양은 [README](../../../README.md) · [관리자 매뉴얼](../../ADMIN_GUIDE.md) 참조. (최종 확인: 2026-08-07)

> 승인된 결정(2026-07-06, 게이트 ①): 기획서 승인 · Phase 3 = **제안 범위**(이메일 인증 + 보안 알림 + 강제 로그아웃, 초대/세션 셀프서비스는 후속) · 보안 감사 문서 2건 = **git rm 삭제**(히스토리 rewrite 없음) · rate-limit 저장소 추상화 = **별도 트랙으로 미룸**.
> 규칙: 스키마 변경은 `db:generate`까지만(적용 금지, CLAUDE.md). 커밋은 전체 검증 통과 + 커밋 승인(게이트 이후)에만, 푸시 금지. 쓰기=Opus 위임, 검증=작성자와 분리된 독립 Opus 에이전트. 스텁/TODO 플레이스홀더/`test.skip`은 블로커.
> 순서: Phase 1 → 2 → 3 → 4 → 5 (4는 1~3의 신규 로직 테스트 포함, 5는 독립이라 병렬 가능). 페이즈 내 파일 겹침 태스크는 직렬.

---

## Phase 1 — 보안 Medium 5건 수정

**목적**: 조사에서 확인된 Medium 결함을 스키마 변경 없이 기존 패턴 재사용으로 해소.
**파일 경계**: S1·S2는 login 경로 공유 → 같은 에이전트가 직렬 처리. S3·S4·S5는 서로 독립.

### [x] 1-1. S1 로그인 타이밍 열거 균등화

- 파일: `src/lib/server/auth/users.ts` (46-63 부근), 참고: `find-password/+page.server.ts`의 timing 균등화 패턴
- 작업: username 미존재 시에도 더미 scrypt 검증(고정 더미 해시에 대한 verify)을 수행해 존재/미존재 응답시간을 균등화. 더미 해시는 실제 파라미터(N=2^15,r=8,p=3)와 동일 비용.
- 수용 기준: 미존재/존재-오답 경로 모두 scrypt 1회 비용 발생. 기존 로그인 성공/실패 동작·에러 메시지 무변경. 레거시 해시(argon2id/PBKDF2) 업그레이드 경로 회귀 없음.

### [x] 1-2. S2 계정 단위 잠금(backoff)

- 파일: `src/routes/(auth)/login/+page.server.ts` (120 부근), `src/lib/server/ratelimit/` 재사용
- 작업: 기존 rate-limit 인프라를 `login:user:<usernameLower>` 키로 추가 적용(스키마 무변경). 보수적 임계값(예: 10회 실패/15분)으로 IP 제한과 병행. 실패 시에만 카운트(성공 로그인은 미카운트). 잠금 시 에러 메시지는 계정 존재를 새로 노출하지 않는 문구(기존 generic 실패 문구 계열, i18n ko/en 키 추가).
- 수용 기준: 분산 IP에서도 동일 계정 연속 실패가 제한됨. 정상 사용자 오탐 최소화(임계값·창 명시). MFA/LDAP 로그인 경로와 충돌 없음. i18n 키 ko/en 대칭.

### [x] 1-3. S3 lookup API tenant 격리

- 파일: `src/routes/api/users/lookup/+server.ts` (35-38)
- 작업: `?id=` 경로에도 tenant 스코프 강제. 기존 호출자(dispatcher)의 사용 방식을 먼저 읽기 위임으로 확인 후, tenant 명시 파라미터 요구 또는 요청 컨텍스트의 tenant로 필터 — 호환성 깨지지 않는 쪽 선택.
- 수용 기준: 타 tenant 사용자 id 조회가 차단됨. 기존 정상 호출 시나리오 무회귀(주석의 "tenant 무관" 의도가 실제 요구사항이었는지 확인 근거 포함).

### [x] 1-4. S4 authorization_code 교환 시 세션 폐기 검사

- 파일: `src/routes/oidc/token/+server.ts` (392-438), 참고: 같은 파일 refresh 경로(305-318)의 세션 검사
- 작업: code 교환 시 `grant.sessionId` 세션의 `revokedAt`/만료를 확인, 폐기된 세션이면 `invalid_grant` 반환. refresh 경로 검사 로직을 헬퍼로 추출해 양쪽 재사용.
- 수용 기준: 로그아웃된 세션의 미소진 code가 교환 거부됨. 정상 플로우(authorize→token) 무회귀. 세션 없는 grant(있다면 service 계열)의 기존 동작 보존.

### [x] 1-5. S5 issuer fail-closed + 필수 env 검증

- 파일: `src/lib/server/auth/runtime.ts` (55-62), `src/lib/server/auth/bootstrap.ts` (106 부근)
- 작업: 프로덕션(`import.meta.env.PROD` 또는 동등 판별)에서 `IDP_ISSUER_URL` 미설정 시 host fallback 대신 명시적 오류(503). `IDP_SIGNING_KEY_SECRET` 미설정 시 조용한 스킵 대신 명확한 오류/경고 집계(부트스트랩 1회). dev 모드는 기존 fallback 유지(로컬 DX 보존). `.env.example`·README 해당 항목에 "프로덕션 필수" 명시.
- 수용 기준: 프로덕션 미설정 시 토큰 발급 시점이 아니라 요청 초기에 명확한 오류. dev 로컬 플로우 무회귀. 문서 갱신 포함.

### [x] 1-검증 (독립 Opus 에이전트) — 통과(2026-07-06): 5건 전부 VERIFIED, 게이트 4종 그린(README prettier·wrangler types 스테일은 기계적 정리 완료). 참고: 잠금 실효 임계 11회(peek 1회 지연, 코드 주석화), argon2id 레거시 계정 잔존 타이밍 편차는 마이그레이션 창 고유 한계.

- 수용 기준 5건 각각 통과/실패 판정(파일:라인 근거). `bun run test`·`bun run check`·`bun run lint`·`bun run build` 그린. 타이밍 균등화가 실제로 동일 비용 경로인지, 계정 잠금이 사용자 열거 신규 오라클을 만들지 않는지 중점 리뷰. 가짜 완료(스텁/skip) 스캔.

---

## Phase 2 — 운영 안정성 (GC·마이그레이션·원자성·캐시·스키마 정리)

**목적**: 무한 성장 테이블 GC, 4트랙 마이그레이션 대칭화, 비원자 write 해소, 핫패스 캐시.
**파일 경계**: 2-1(GC)과 2-3(원자화)이 `refresh.ts`를 공유 → 직렬. 2-2/2-4/2-5는 독립.

### [x] 2-1. O1 만료 데이터 GC — Workers는 adapter 제약으로 cron 대신 확률적 waitUntil GC(1%), Node는 setInterval. sessions 유예 30일(refresh 우회 방지 근거 검증됨)

- 파일: `src/worker.ts`(또는 Workers 엔트리 — 실제 엔트리 파일은 읽기 위임으로 확인), `src/lib/server/db/gc.ts`(신규), `wrangler.example.jsonc`, 기존 `webauthn.ts:158`·`refresh.ts:178`·`ratelimit/index.ts:84` purge 함수
- 작업: (a) `gc.ts`에 만료 대상 전 테이블 purge 통합 함수 — sessions(만료+revoked 유예 경과), oidc_grants(만료/소진), oidc_refresh_tokens, password_reset_tokens, webauthn_challenges, rate_limits(경과 윈도우), saml_slo_states, saml_authn_request_ids, saml_sessions. 배치 크기 제한(예: 테이블당 LIMIT n 반복 또는 1패스)으로 타임아웃 방지. (b) Workers: `triggers.crons`(예: 1시간 간격) + `scheduled()` 핸들러. (c) Node: 서버 기동 시 setInterval(중복 기동 가드). (d) 기존 orphan purge 3함수는 gc.ts로 통합하거나 호출 연결.
- 수용 기준: 두 런타임 모두에서 GC 실행 경로 존재. 만료되지 않은 데이터는 절대 삭제 안 됨(각 테이블 조건 명시). wrangler.example.jsonc에 cron 문서화. 삭제 실패가 요청 처리에 영향 없음(격리된 에러 처리).

### [x] 2-2. O2 마이그레이션 트랙 대칭화 — db:generate:all + CI 드리프트 체크 + d1 offline generate 침묵 버그(d1-http driver) 수정

- 파일: `package.json`(scripts), `drizzle/**`(4트랙), `test/unit/`(신규 parity 체크) 또는 `.github/workflows/ci.yml`
- 작업: (a) `db:generate:all` 스크립트(4방언 순차 실행). (b) pg/mysql/sqlite 트랙의 밀린 마이그레이션을 `db:generate:{pg,mysql,sqlite}`로 생성 — **생성만, 적용 금지**. (c) 미생성 diff 감지 장치: CI 스텝(4방언 generate 후 git diff 검사) 또는 스냅샷 기반 테스트 중 실행 가능한 쪽. (d) `drizzle.config.ts:9`의 사실과 다른 ".gitignore 대상" 주석 제거(트랙 커밋 정책 확정 반영).
- 수용 기준: 4트랙 모두 현 스키마와 스냅샷 일치(추가 generate 시 no-op). 이후 스키마 변경 시 한 트랙만 갱신하면 CI/테스트가 실패하는 안전망 존재. 마이그레이션 SQL은 커밋 대상으로 보고만.

### [x] 2-3. O3 refresh 회전 원자화 + atomic 유틸 — 무조건 insert+원자 단위 설계, 패자 stray는 family 폐기로 무효화(검증 증명됨)

- 파일: `src/lib/server/db/atomic.ts`(신규), `src/lib/server/oidc/refresh.ts` (147 부근), `src/routes/admin/signing-keys/+page.server.ts` (86-93), `src/routes/api/totp/enroll/confirm/+server.ts` (93-100)
- 작업: d1/sqlite=batch, pg/mysql=transaction 분기를 `atomic()` 공용 유틸로 추출. refresh 회전의 claim(UPDATE)→insert 2-write를 원자화(단, 기존 "원자적 claim으로 동시 회전 경쟁 판정" 시맨틱 보존 — claim 결과 확인 후 insert가 같은 원자 단위에 들어가도록 설계 검토, batch 제약상 불가하면 claim은 유지하고 insert 실패 시 claim 롤백/복구 경로라도 확보). 기존 2곳 복붙 분기를 유틸로 치환.
- 수용 기준: claim 성공·insert 실패로 old-revoked+new-부재가 되는 창이 제거(또는 복구 가능). 재사용 감지(family 폐기) 시맨틱 무회귀. 기존 signing-keys/totp-confirm 동작 무변경. 3곳 모두 유틸 사용.

### [x] 2-4. O4 서명키/JWKS 캐시 — tenant별 60초 TTL, 회전 시 무효화, null 미캐시

- 파일: `src/lib/server/crypto/keys.ts`, 참고: `bootstrap.ts:94-110`의 globalThis 캐시 패턴
- 작업: `getActiveSigningKey`/`getPublicJwks`에 tenant별 globalThis 단기 캐시(TTL 예: 60~300초). admin 서명키 회전/비활성화 액션에서 캐시 무효화 호출.
- 수용 기준: 토큰 발급·JWKS 요청이 캐시 히트 시 DB 미조회. 키 회전 후 TTL 내 무효화로 새 키 반영. 멀티테넌트 키 혼선 없음(캐시 키에 tenant 포함).

### [x] 2-5. O5 스키마 정리 (`db:generate`까지만) — legacy code drop + client_skins ×1000 보정(가드 포함), 4트랙 생성·no-op 확인, 적용은 사용자 몫

- 파일: `src/lib/server/db/schema.{sqlite,pg,mysql}.ts`, `drizzle/**`(생성물)
- 작업: (a) `client_skins.createdAt` sqlite `timestamp` → `timestamp_ms` 통일. (b) legacy `oidc_grants.code` 컬럼 + `oidc_grants_code_uidx` 3방언 drop(잔존 평문 code 데이터가 있어도 TTL 5분이라 안전 — 마이그레이션 주석에 명시). (c) 4트랙 `db:generate:all`로 마이그레이션 생성. **적용 명령 실행 금지.**
- 수용 기준: schema-parity 테스트 통과. 4트랙 마이그레이션 생성됨. codeHash 경로만 남고 `code` 참조 코드 0건(사전 grep 확인). 적용은 사용자 요청으로 보고.

### [x] 2-검증 (독립 Opus 에이전트) — 통과(2026-07-06): A1~D5 전부 VERIFIED, 게이트 4종 그린(refresh.ts prettier만 정리). 잔여 권고: gc.ts SESSION_GC_GRACE_MS 주석 근거를 revoke-on-logout 불변식 기준으로 정밀화(Phase 4-2 에이전트에 위임)

- GC 삭제 조건의 안전성(미만료 데이터 삭제 불가) 집중 리뷰, 마이그레이션 SQL 4트랙 내용 검토(파괴적 변경 없는지), refresh 원자화 시맨틱 검증. `bun run test`·`check`·`lint`·`build` 그린.

---

## Phase 3 — 기능 추가 (이메일 인증 · 보안 알림 · 강제 로그아웃)

**목적**: `email_verified` 클레임 정상화(현재 항상 false), 보안 이벤트 사용자 통지, admin 세션 강제 종료.
**파일 경계**: 3-1과 3-2가 `email.ts`를 공유 → 직렬(또는 같은 에이전트). 3-3은 독립.

### [x] 3-1. F1 이메일 인증 플로우 — email_verification_tokens 3방언+마이그레이션 생성(0022/0005×3), verify-email 라우트(GET 비소진·POST 원자 소진), 재발송+미인증 배너, GC 연결

- 파일: `src/lib/server/email.ts`(템플릿 추가), `src/routes/(auth)/signup/+page.server.ts`, `src/routes/verify-email/+server.ts`(또는 `(auth)/verify-email/` — 기존 라우트 관례에 맞춤, 읽기 위임으로 확인), 스키마(인증 토큰 — `password_reset_tokens` 패턴 재사용해 신규 테이블 또는 범용화), `account/profile`(재발송 UI)
- 작업: (a) 가입 성공 시 인증 메일 발송(토큰 SHA-256 해시 저장, 24시간 TTL, rate-limit). (b) 검증 라우트: 토큰 검증 → `users.emailVerifiedAt` 세팅 → 완료 화면. (c) 재발송 액션(rate-limit, 이미 인증 시 no-op). (d) 미인증 사용자도 로그인은 허용(비파괴적) — account 화면에 미인증 배너+재발송 버튼. (e) i18n ko/en, 스키마 변경은 `db:generate:all`까지만.
- 수용 기준: 신규 가입→메일 링크→`email_verified=true` 클레임 확인 가능(토큰/userinfo). 토큰 1회용·만료 준수. 기존 사용자 로그인 무영향. 이메일 템플릿은 기존 escape/safe-URL 패턴 준수. 발송 실패가 가입 자체를 실패시키지 않음.

### [x] 3-2. F2 보안 알림 메일 — 9종 이벤트(security-notify.ts, waitUntil 격리, users.locale 기반 ko/en), errors.rate_limit 잠복 키 부재 버그도 함께 해소

- 파일: `src/lib/server/email.ts`(알림 템플릿), 발송 지점: `(auth)/reset-password`(완료 시), `account/mfa/+page.server.ts`(TOTP 등록·삭제·백업코드 재생성), `account/passkeys/+page.server.ts`(등록·삭제), `admin/users/+page.server.ts`·`admin/users/[id]/+page.server.ts`(resetPassword·updateStatus 잠금 시)
- 작업: 공용 `sendSecurityNotification(...)` 헬퍼 + 이벤트별 문구(i18n은 수신자 locale 기반 — 사용자 profile locale 활용 가능 여부 읽기 위임으로 확인, 불가하면 ko 기본+en 병기). **발송은 best-effort**(실패해도 본 동작 성공, waitUntil 활용).
- 수용 기준: 나열된 각 이벤트에서 대상 사용자에게 메일 발송 경로 존재. 발송 실패가 본 액션을 실패시키지 않음. 이메일 주소 없는 계정은 조용히 스킵. 템플릿 escape 준수.

### [x] 3-3. F3 admin 강제 로그아웃 액션 — forceLogout(세션+refresh 폐기, tenant 가드, audit, confirm UI)

- 파일: `src/routes/admin/users/[id]/+page.server.ts`(액션 추가), `admin/users/[id]/+page.svelte`(버튼), `src/lib/server/auth/session.ts`(`revokeAllUserSessions` 재사용)
- 작업: 상태/비번 변경 없이 세션만 전체 폐기하는 전용 액션(확인 다이얼로그, audit `user_sessions_revoked` 기록, refresh token cascade 포함 — 기존 revoke 유틸 시맨틱 확인). i18n ko/en.
- 수용 기준: 대상 사용자의 모든 세션+refresh token 폐기. audit 기록. `assertUserInTenant` 가드 적용. UI 무결(기존 페이지 액션 패턴 준수).

### [x] 3-검증 (독립 Opus 에이전트) — 통과(2026-07-06): V1~V6 전부 VERIFIED, 게이트 그린(prettier 2건 정리 완료). 참고: 재발송 시 기존 미사용 토큰 병존은 rate-limit+TTL로 한정(결함 아님)

- 이메일 인증 토큰 보안(해시 저장·1회용·만료·rate-limit), 발송 best-effort 격리, 강제 로그아웃 tenant 가드 집중 리뷰. `bun run test`·`check`·`lint`·`build` 그린. 마이그레이션 생성물 확인(적용 안 함).

---

## Phase 4 — 테스트 확충 (P0/P1 + 인프라)

**목적**: 보안 핵심 로직 회귀 안전망 구축. Phase 1~3 신규 로직 포함.
**의존성**: Phase 1~3 완료 후 착수(신규 로직 테스트 포함 위해). 태스크 간 파일 독립 → 병렬 가능.

### [x] 4-1. T1a 암호·토큰 코어 테스트 — crypto-keys(22)·password(19), WebCrypto 독립 교차검증, argon2 레거시 포함

- 파일: `test/unit/crypto-keys.test.ts`(신규), `test/unit/password.test.ts`(신규)
- 작업: `crypto/keys.ts` — JWT 서명/검증 라운드트립(RS256, typ/aud/exp), HMAC access token 발급/검증/변조 거부, private JWK 래핑/언래핑 라운드트립, HKDF 도메인 분리(용도별 키 상이). `auth/password.ts` — scrypt 해시/검증, 오답 거부, 레거시(argon2id/PBKDF2) 검증→scrypt 자동 업그레이드, PBKDF2 하한 거부, 상수시간 비교 경로.
- 수용 기준: 실제 WebCrypto/node:crypto로 동작(mock 최소화). 전체 스위트 그린.

### [x] 4-2. T1b OIDC grant/refresh/세션/rate-limit 테스트 — grant(6)·refresh(8)·ratelimit(7)·email-verification(6) + session(9)·gc(7)는 4-3에서. mysql 분기는 d1 하네스 한계로 미커버(보고됨)

- 파일: `test/unit/oidc-grant.test.ts`, `test/unit/oidc-refresh.test.ts`, `test/unit/session.test.ts`, `test/unit/ratelimit.test.ts` (모두 신규)
- 작업: 기존 crud-factory 테스트의 mock DB 패턴 재사용 — grant 1회 소진·만료 거부·codeHash 검증, refresh 회전·재사용 감지 family 폐기·원자화(2-3 결과) 경로, 세션 생성/검증/만료/revoke cascade, 슬라이딩 윈도우 경계(윈도우 전환·한도 초과·`login:user:` 키), Phase 1 신규 로직(더미 해시 경로·code 교환 세션 검사)과 Phase 3 이메일 인증 토큰 로직.
- 수용 기준: 각 모듈 핵심 분기 커버. mock DB 계약이 실제 drizzle 호출 shape와 일치(기존 패턴 준수). 전체 그린.

### [x] 4-3. T2 schema-parity 강화 — nullable·타입 계열·인덱스/unique 비교, 예외 목록(signing_keys mysql 1건), drift 주입 자가검증 통과

- 파일: `test/unit/schema-parity.test.ts`
- 작업: 컬럼명 집합 비교에 더해 — 컬럼 타입 계열/nullable/default 유무 비교, 인덱스·unique 제약 이름/컬럼 비교. 방언별 정당한 차이(mysql partial-unique 불가 등)는 **명시적 예외 목록**으로 테스트 코드에 문서화(신규 drift만 실패).
- 수용 기준: 현 스키마로 그린(기존 known-gap은 예외 목록에). 가상의 drift(한 방언만 인덱스 누락) 주입 시 실패함을 확인.

### [x] 4-4. T3 테스트 인프라·스크립트 — test:coverage(v8)·typecheck(tsc)·lint:fix·db:check(4방언), lefthook eslint --cache. 커버리지: 핵심 모듈 74~90%(keys 74.5/password 90.2/session 87/ratelimit 86.4), 전체 29%(미테스트 I/O 모듈 0% 영향)

- 파일: `package.json`, `lefthook.yml`, `vitest.config.ts`
- 작업: `@vitest/coverage-v8` 추가 + `test:coverage` 스크립트, `lint:fix`, `db:check`(drizzle-kit check 4방언). lefthook pre-commit에 staged 파일 eslint 추가(느리면 --cache). CI에 coverage 아티팩트는 선택(과설계 금지 — 스크립트만 우선).
- 수용 기준: 각 스크립트 정상 동작. pre-commit이 정상 커밋 흐름을 과도하게 늦추지 않음(수 초 내).

### [x] 4-검증 (독립 Opus 에이전트) — 통과(2026-07-06): 비-tautology 표본 검증, skip/only 0, 게이트 8종 그린

- 테스트가 실제 로직을 검증하는지(tautology/mock-echo 테스트 아닌지) 샘플 리뷰, `test.skip`/`.only` 0건, 전체 `bun run test` + `check`+`lint`+`build` 그린, coverage 리포트 생성 확인.

---

## Phase 5 — 품질·문서 정리 (Phase 1~4와 독립, 병렬 가능)

**목적**: 파일 비대 해소, admin 언어 혼재 해소, 보안 문서 격리, 문서·메모리 drift 정리.
**파일 경계**: 5-2와 5-3이 admin 라우트 겹침 가능 → 5-2 먼저(구조 확정) 후 5-3.

### [x] 5-1. Q1 보안 감사 문서 삭제 (승인됨) — git rm 완료, 잔존 참조 0건

- 파일: `docs/security-audit-2026-05-12.md`, `docs/security-pentest-report.md`
- 작업: `git rm` 두 파일. README/다른 문서에서 이 파일들 참조가 있으면 제거. (히스토리 잔존 한계는 커밋 메시지에 명시하지 않음 — 문서 위치만 정리.)
- 수용 기준: 워킹트리에서 두 파일 제거, 깨진 참조 0건.

### [x] 5-2. Q2 `users/[id]/+page.server.ts` 분리 — 677→181줄, user-actions/{profile,org,service,security}.ts 4모듈, 순수 이동 독립 검증 통과(11개 액션 계약 동일)

- 파일: `src/routes/admin/users/[id]/+page.server.ts` (677줄) → `src/lib/server/admin/user-actions/{profile,org,service}.ts`(또는 라우트 인접 모듈 — 리포 관례에 맞춰 읽기 위임으로 결정)
- 작업: actions 10개를 도메인별 모듈로 분리, `+page.server.ts`는 조립만. **동작·에러 shape·audit kind 완전 보존**(순수 이동 리팩터). load 함수도 비대하면 함께 정리.
- 수용 기준: diff가 이동 중심(로직 변경 0). 모든 액션 이름·계약 무변경. `check`·`lint`·`build` 그린.

### [x] 5-3. Q3 admin 에러 i18n + 공통 헬퍼 — adminError/requireFormId 헬퍼, 98곳 전환, ko/en 605키 대칭. 잔존(의도적 범위 외): crud-factory/schemas 한국어(테스트 계약과 충돌해 유지, 후속 시 테스트와 함께 전환), saml-sps/[id] 7건, validation.ts reason 문자열, 프로토콜 API 에러

- 파일: `src/routes/admin/{users,users/[id],oidc-clients,oidc-clients/[id],ldap-providers,skins,signing-keys,saml-sps,login}/+page.server.ts`, `src/lib/i18n/{ko,en}.json`, 공통 헬퍼(`src/lib/server/admin/form.ts` 신규 등)
- 작업: (a) `requireFormId` 류 공통 헬퍼 추출(중복 문구 12곳+). (b) admin 서버 액션의 하드코딩 한국어 에러를 auth 서버와 동일한 `translate(locals.locale, ...)` 패턴으로 전환, ko/en 키 대칭 추가. 프로토콜 레이어(oidc/saml/webauthn API 에러)는 이번 범위 제외(운영자·개발자 대상, 후속).
- 수용 기준: admin 라우트 서버 에러 하드코딩 한국어 0건(grep 근거). ko/en 키 대칭 유지(기존 대칭성 테스트 있으면 통과). 에러 shape(`{error}`/`{create:true,error}`) 무변경.

### [x] 5-4. Q4 문서·메모리 정합 — improvement-report 정오표 추가, deferred-followups 상태 갱신, SECRET_ROTATION.md 신설(읽기 위임 사실관계 기반: 7용도·재암호화 3종·무중단 회전 불가 명시), 프로젝트 메모리 최신화

- 파일: `docs/improvement-report-2026-07-02.md`(stale 표기 갱신 — refresh token/OIDC scope/TOTP TOCTOU/E9 처리 현황), `docs/plans/deferred-followups/TODO.md`(1행 "커밋 승인 대기" → 병합 완료로), `docs/SECRET_ROTATION.md`(신규 — `IDP_SIGNING_KEY_SECRET` 회전 절차: 용도 4가지 나열, 회전 시 영향·순서·재암호화 필요 대상), 프로젝트 메모리(`oidc-scope-expansion.md` — groups/address/organization 구현 완료로 갱신)
- 작업: 문서 갱신은 Fable가 직접 가능(기획 산출물·문서). 단 SECRET_ROTATION.md의 기술 사실관계(어떤 데이터가 이 시크릿으로 암호화돼 있는지)는 읽기 위임으로 확인 후 작성.
- 수용 기준: 문서와 코드 현실 일치. 메모리 갱신 완료.

### [x] 5-검증 (독립 Opus 에이전트) — 통과(2026-07-06): W1~W5 전부 VERIFIED, APPROVE. 스코프 오염 0(전 변경 파일 5페이즈 귀속 확인)

- 5-2 diff의 순수-이동 여부(로직 변경 혼입 없는지) 집중 리뷰, 5-3 grep 검증(한국어 하드코딩 잔존 0), `bun run test`·`check`·`lint`·`build` 그린.

---

## 최종 게이트 & 커밋 (STEP 7-8)

- [x] 전체 스위트: `bun run test`(151) · `bun run check`(0 err) · `bun run lint` · `bun run build` · `typecheck` · `db:check`(4방언) · `test:coverage` · `db:generate:all` no-op — 전부 그린 (2026-07-06 최종 검증)
- [ ] 마이그레이션: **적용은 사용자 몫** — d1: `drizzle/0021`(legacy code drop+client_skins 보정)·`0022`(email_verification_tokens) / pg·mysql·sqlite: 각 `0004`·`0005`
- [x] 커밋 승인 게이트 → 승인(2026-07-06), 페이즈별 원자 커밋 7개 완료(fix(security)/chore(db)/refactor(db)/feat(gc)/feat(email)/test/refactor(admin)+docs). 푸시는 하지 않음.
