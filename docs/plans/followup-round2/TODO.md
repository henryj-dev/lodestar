# 실행 투두 — 후속 2차 개선 (6 페이즈)

> **상태: 완료 (PR #75 등으로 병합됨). 이 문서는 실행 이력이며 현행 사양서가 아닙니다.**
> 아래 체크박스 중 마지막 "게이트" 항목들(전체 검증·마이그레이션 적용·커밋 승인)은 당시 진행
> 절차라 미체크로 남아 있을 뿐, 작업 자체는 병합되었습니다. **마이그레이션의 실제 DB 적용
> 여부는 배포 환경에서 직접 확인하세요.** 현행 사양은 [README](../../../README.md) ·
> [관리자 매뉴얼](../../ADMIN_GUIDE.md) 를 보세요. (최종 확인: 2026-08-07)

> 승인(2026-07-06, 게이트①): 기획 승인 · Phase 8 = **소프트 삭제+유예기간**(enum 확장+GC 배치) · Phase 10 프로토콜 = **전량 번역**(표준 필드 포함) · Phase 9 audit hash 재계산 = **제외**(문서 안내만).
> 규칙: 스키마 변경은 `db:generate:all`까지만(적용 금지, CLAUDE.md). 커밋은 전체 검증 통과 + 커밋 승인 후, 푸시 금지. 쓰기=Opus 위임, 검증=작성자와 분리된 독립 Opus. 스텁/TODO/skip은 블로커.
> 순서: 6·9·10 병렬 착수 가능 → 7 → 8(7의 계정 생명주기 확장) → 11(마지막, 신규 로직 통합 테스트 포함). 스키마 건드리는 7·8은 마이그레이션 생성 순서 조율(직렬).

---

## Phase 6 — 세션 셀프서비스 (스키마 무변경, 최저 비용)

**목적**: 사용자가 활성 세션 목록 확인 + 개별/일괄 철회.

### [x] 6-1. 세션 조회·철회 헬퍼

- 파일: `src/lib/server/auth/session.ts`
- 작업: `listActiveSessions(db, userId)`(revokedAt null·미만료 세션의 id/ip/userAgent/lastSeenAt/createdAt 반환), `revokeSessionById(db, sessionId, userId, revokedAt)`(**userId 조건 필수** — IDOR 방지, sessionId+userId 동시 일치만 revoke).
- 수용 기준: 타 사용자 sessionId 철회 불가(userId 불일치 시 no-op/0행). 만료·이미 revoked 세션은 목록 제외.

### [x] 6-2. account/sessions 라우트

- 파일: `src/routes/account/sessions/+page.server.ts`·`+page.svelte`(신규)
- 작업: load(목록 + `locals.session.id`로 "현재 세션" 배지, account 라우트 관례 준수). 액션 `revoke`(개별 — `revokeSessionById` + **`revokeRefreshTokensForSession` 세트 호출**로 refresh 연쇄 폐기), `revokeOthers`(기존 `revokeOtherSessions` 재사용, 현재 세션 유지). audit(`session_revoked`) + `dispatchSecurityAlert`(best-effort). i18n ko/en. 현재 세션 개별 철회 시 로그아웃 처리 일관성 확인.
- 수용 기준: 목록에 메타 정상 표시, 개별 철회 시 해당 세션+refresh 폐기, 다른 세션 유지. IDOR 없음. ko/en 대칭.

### [x] 6-검증 (독립 Opus) — 통과(2026-07-06, APPROVE): IDOR·refresh 연쇄·현재세션 검증. 보안알림은 스코프 제약으로 audit 갈음(후속 소량 추가 여지)

- IDOR(userId 조건), refresh 연쇄 폐기 세트 호출, 현재 세션 철회 동작. 게이트 4종.

---

## Phase 7 — 초대 플로우 (스키마 변경 — 옵션 B: enum 무변경)

**목적**: admin 초대 메일 → 수신자 비밀번호 최초 설정. "초대중" = `emailVerifiedAt IS NULL AND credential 부재`.

### [x] 7-0. 로그인 안전성 선점검 (관문)

- 파일: `src/lib/server/auth/users.ts`(로그인 크레덴셜 조회), `src/routes/(auth)/login/+page.server.ts`
- 작업: password credential이 **없는** 계정의 로그인 시도가 안전하게 실패하는지 확인. 취약(예외/우회)하면 보강 — credential 부재 시 명확한 인증 실패(타이밍 균등화 유지, Phase 1의 더미 scrypt 경로와 정합). LDAP/패스키 사용자와의 구분 확인.
- 수용 기준: credential 없는(초대 대기) 계정으로 비밀번호 로그인 불가. 사용자 열거 오라클 신규 발생 없음.

### [x] 7-1. invite_tokens 테이블

- 파일: `src/lib/server/db/schema.{sqlite,pg,mysql}.ts`
- 작업: `password_reset_tokens` 동일 구조(userId cascade FK, tokenHash, expiresAt, usedAt, createdAt) 3방언 추가. TTL은 발급부에서(예: 72시간). parity 유지.
- 수용 기준: 3방언 컬럼·인덱스 동일. schema-parity 테스트 통과.

### [x] 7-2. 발급·메일·admin invite 액션

- 파일: `src/lib/server/auth/invite.ts`(신규, email-verification 패턴), `src/lib/server/email.ts`(`sendInviteEmail`), `src/routes/admin/users/+page.server.ts`(`invite` 액션)
- 작업: admin `invite` 액션 — email/displayName/role 받아 **비밀번호 없이** 계정 생성(credentials row 생략, emailVerifiedAt NULL), 초대 토큰 발급+메일. users insert를 `runAtomic`로(기존 create의 비원자성 답습 금지). 기존 create 액션은 유지(직접 비밀번호 생성 경로 병존).
- 수용 기준: 초대 계정 생성 + 메일 발송(best-effort 격리). role 검증. 중복 이메일 차단. audit(`user_invited`).

### [x] 7-3. accept-invite 라우트

- 파일: `src/routes/(auth)/accept-invite/+page.server.ts`·`+page.svelte`(신규, verify-email/reset-password 패턴)
- 작업: 토큰 검증(해시·만료·1회용) → 비밀번호 최초 설정(정책 준수) + `emailVerifiedAt` 세팅(초대 클릭=이메일 소유 증명) + credentials(password) insert를 원자적으로(`runAtomic`). i18n. `db:generate:all`(7-1 반영).
- 수용 기준: 유효 토큰으로 비밀번호 설정→로그인 가능. 만료/재사용 거부. emailVerifiedAt·credential 동시 반영(원자). admin UI에 초대중 배지.

### [x] 7-검증 (독립 Opus) — 통과(2026-07-06, APPROVE): 열거 오라클 없음, 원자성·토큰 보안·정상계정 구분 확인. federated 사용자 배지 오표시(V5 엣지) 별도 수정

- 로그인 선점검 보강 유효성, 토큰 보안(해시·1회용·만료), 계정 생성/수락 원자성, 초대중 판별. 마이그레이션 생성만. 게이트.

---

## Phase 8 — 계정 삭제 셀프서비스 (소프트 삭제 + 유예기간)

**목적**: step-up 재인증 후 탈퇴 신청 → 유예기간 후 GC 하드 삭제. 복구 가능.

### [x] 8-1. status enum 확장 + 삭제예정 메타

- 파일: `src/lib/server/db/schema.{sqlite,pg,mysql}.ts`
- 작업: `users.status` enum에 `deletion_pending`(또는 유사) 추가(3방언 동시). 하드삭제 시점 판단용 `deletionScheduledAt`(nullable timestamp_ms) 컬럼 추가. parity 유지. `db:generate:all`.
- 수용 기준: 3방언 enum·컬럼 동일. 기존 status 값 무영향. parity 통과.

### [x] 8-2. self-delete(탈퇴 신청) 액션

- 파일: `src/routes/account/danger-zone/+page.server.ts`·`+page.svelte`(신규)
- 작업: step-up 재인증(비밀번호 또는 TOTP — passkey delete 패턴 재사용). `assertNotLastAdmin`(마지막 admin 자기삭제 차단). 상태를 `deletion_pending` + `deletionScheduledAt = now + 유예(예: 30일)` 세팅, 전 세션+refresh 즉시 폐기(로그아웃). audit(`user_deletion_requested`) + 탈퇴 접수 메일(세션 만료 전 발송). 복구 안내 포함.
- 수용 기준: step-up 없이는 탈퇴 불가. 마지막 admin 차단. 신청 즉시 로그아웃+상태 전환, 유예기간 기록. 확인 메일 발송.

### [x] 8-3. 로그인 차단 + 복구 + GC 하드삭제

- 파일: `src/routes/(auth)/login/+page.server.ts`(deletion_pending 처리), 복구 경로(로그인 시 유예 내 복구 옵션 또는 admin 복구), `src/lib/server/db/gc.ts`(유예 경과분 하드 삭제)
- 작업: `deletion_pending` 계정 로그인 시 → 유예기간 내면 "복구하시겠습니까"(복구=status active 환원, deletionScheduledAt null) 또는 로그인 거부. GC에 `deletionScheduledAt < now`인 users 하드 삭제 추가(FK cascade가 자식 정리, audit set null 보존). 보수적 삭제 조건.
- 수용 기준: 유예 내 복구 가능. 유예 경과 시 GC가 하드 삭제(미경과·활성 계정 절대 삭제 안 함). 로그인 흐름 일관.

### [x] 8-검증 (독립 Opus) — 통과(2026-07-06, APPROVE): GC 활성/미경과 계정 삭제 불가(NULL 비교), step-up 우회 불가, 타이밍 오라클 없음, 복구 회귀 없음, 배지 정확(prettier 2건 정리). 엣지: 스킨 로그인은 복구 패널 미표시(기본 스킨만, 후속)

- step-up 우회 불가, 마지막 admin 차단, GC 삭제 조건 보수성(미경과 삭제 없음), 복구 경로, cascade 정합. 마이그레이션 생성만. 게이트.

---

## Phase 9 — 마스터 시크릿 무중단 회전 (audit 재계산 제외)

**목적**: old/new secret 동시 검증 + 재암호화 스크립트로 무중단 회전.

### [x] 9-1. runtime 다중 시크릿 + tryWithSecrets 헬퍼

- 파일: `src/lib/server/auth/runtime.ts`, `src/lib/server/crypto/keys.ts`(헬퍼 배치)
- 작업: `IDP_SIGNING_KEY_SECRET_PREVIOUS` env 추가. `signingKeySecret: string` → `signingKeySecrets: string[]`(current 우선, previous 후행; previous 없으면 길이1). 공용 `tryWithSecrets(secrets, fn)`(순차 시도, 마지막 실패만 throw) 도입. **발급/암호화(wrapPrivateKey/서명/encryptSecret)는 항상 `secrets[0]`(current)**, 검증/복호만 fallback.
- 수용 기준: previous 미설정 시 기존과 동일 동작(회귀 0). current로 실패한 복호가 previous로 성공. 발급은 current 고정.

### [x] 9-2. 복호/검증 소비처 fallback 적용

- 파일: unwrapPrivateKey/verifyAccessToken/decryptSecret/decryptTotpSecret 호출부 및 HMAC 검증부(mfa/webauthn/audit 검증), `bootstrap.ts:62`(try/catch 없는 unwrapPrivateKey 전수 점검)
- 작업: 검증·복호 경로를 `tryWithSecrets`로 감싸 current→previous 순차. **소비처 25+ 파일 전수 점검** — 발급 경로가 실수로 previous를 쓰지 않는지, 무보호 예외 지점(bootstrap unwrap)이 fallback 루프에 들어가는지. RuntimeConfig 타입 변경 파급을 기계적으로 반영.
- 수용 기준: 모든 복호/검증이 회전 창에서 old/new 양쪽 수용. 발급은 current. 회귀 0(전체 게이트+통합 테스트).

### [x] 9-3. 재암호화 스크립트 + 문서

- 파일: `scripts/reencrypt-secrets.ts`(신규, openScriptDb 패턴), `docs/SECRET_ROTATION.md`(무중단 절차로 갱신)
- 작업: signing_keys 활성행·credentials(totp)·identity_providers(LDAP bindPassword)를 old→new 재작성(4방언, `DB_DIALECT` 분기). dry-run 옵션 권장. **스크립트는 사용자가 실행**(자동 실행 금지). SECRET_ROTATION.md를 "previous 설정→배포→재암호화→previous 제거" 무중단 순서로 갱신, audit hash 재계산은 **제외하되 필요 시 수동 절차만 문서 안내**.
- 수용 기준: 스크립트가 dry-run으로 대상 건수 보고. 실제 재작성 로직이 unwrap(any secret)→wrap(current) 정확. 문서가 무중단 절차 반영. 자동 실행 안 함.

### [x] 9-검증 (독립 Opus) — 통과(2026-07-06, APPROVE): 발급=current 위반 0건, fallback 헬퍼 선택 정확, 무보호 지점 커버, reencrypt dry-run. 158 테스트

- 발급=current 고정(previous 오사용 없음), 복호 fallback 정확, 무보호 예외 지점 커버, 재암호화 로직 정합. 게이트+통합 테스트.

---

## Phase 10 — 잔존 한국어 에러 i18n (프로토콜 전량 번역)

**목적**: admin 잔여 + validation.ts + 프로토콜 API(60건+) 전량 i18n. ko/en 대칭.

### [x] 10-1. admin 잔여 + validation.ts

- 파일: `src/routes/admin/saml-sps/[id]/+page.server.ts`(7건 `adminError`), `src/lib/server/admin/schemas.ts`+`crud-factory.ts`(i18n화), `src/lib/server/validation.ts`(`reason: string`→`{key,params}` 시그니처 변경)+호출부(oidc-clients/saml-sps/skins/ldap-providers), `src/lib/i18n/{ko,en}.json`
- 작업: schemas/crud-factory i18n화 시 **`test/unit/admin-zod.test.ts`·`crud-factory.test.ts`의 한국어 기대값도 함께 갱신**(별도 검증 레인은 유지 — 작성자가 테스트 갱신, 독립 에이전트가 검증). validation reason은 키+파라미터로 바꿔 호출부에서 `translate(locals.locale, ...)`.
- 수용 기준: 대상 파일 하드코딩 한국어 0(grep). 갱신된 테스트 통과. ko/en 대칭. 에러 shape 무변경.

### [x] 10-2. 프로토콜 API 전량 번역

- 파일: OIDC(`oidc/{authorize,introspect,revoke,end-session,userinfo}`), SAML(`saml/{sso,slo,metadata}`), WebAuthn(`api/webauthn/**` + `passkey-client/+server.ts` 클라이언트 문자열), TOTP(`api/totp/{verify,enroll/confirm}`), `src/lib/i18n/{ko,en}.json`(oidc/saml/webauthn/totp 네임스페이스 신설)
- 작업: 사람이 보는 에러 문구를 `translate(locals.locale, "<ns>.errors.<key>")`로 전환. **전량 번역 결정** — 단, OAuth `error`/SAML StatusCode 등 **기계 파싱 규격 코드값 자체는 표준 유지**하고 `error_description`·사람 대면 텍스트를 번역(표준 필드에 로케일 문구를 넣는 것이 규격 위반이 아닌 범위에서). `passkey-client`의 클라이언트 JS 문자열은 서버에서 로케일별 문자열을 주입하는 방식으로.
- 수용 기준: 프로토콜 라우트 사용자 대면 한국어 리터럴 0(grep). RP/SP 파싱 대상 코드값은 불변(표준 준수 확인). ko/en 대칭. 각 라우트 정상 동작.

### [x] 10-검증 (독립 Opus) — 통과(2026-07-06, APPROVE): 표준 error 코드·StatusCode 보존, 사람대면 한국어 0, 704 대칭, 82키 신설. token 제외 타당. + 인접 버그(mfa_login 5키 부재) 별도 수정

- 한국어 리터럴 grep 0, 표준 코드값 불변(OAuth/SAML 파싱 호환), ko/en 대칭, 테스트 갱신 정합. 게이트.

---

## Phase 11 — 통합 테스트 하네스 (마지막)

**목적**: 실 DB(libSQL 인메모리) + 실 라우트 직접 호출로 OIDC 풀플로우 + 6~10 신규 로직 통합 검증.

### [x] 11-1. 하네스 구축

- 파일: `vitest.config.ts`(`$app/environment` alias 스텁 추가), `test/integration/harness.ts`(신규 — libSQL `:memory:` + `drizzle/sqlite/*.sql` 프로그래매틱 적용, RequestEvent 빌더)
- 작업: `$app/environment` 스텁(`dev:false` export)로 runtime/bootstrap import 가능화. `scripts/lib/db.ts`의 SQL 실행 유틸 참고해 마이그레이션 순차 적용. `IDP_SIGNING_KEY_SECRET`/`IDP_ISSUER_URL` 테스트 값 주입. 테스트 격리(케이스별 새 DB 또는 트랜잭션 롤백).
- 수용 기준: 하네스로 실 스키마 인메모리 DB 구성 + 라우트 핸들러 import 성공. 순수 유닛 테스트(기존 151)와 공존(설정 충돌 없음).

### [x] 11-2. 통합 테스트 작성

- 파일: `test/integration/*.test.ts`(신규)
- 작업: **OIDC authorize→token→userinfo 풀플로우**(실 서명키·PKCE·code 소진·클레임). 6~10 신규 로직: 세션 개별 철회(refresh 연쇄), 초대 수락(credential 생성), 계정 삭제 유예/복구, 시크릿 current/previous fallback(회전 시나리오). 프로토콜 i18n 로케일별 에러 문구 스모크.
- 수용 기준: 풀플로우 그린. 신규 로직 통합 경로 커버. `test.skip`/tautology 없음. 전체 `bun run test` 그린.

### [x] 11-검증 (독립 Opus) — 통과(2026-07-06, APPROVE): 실 libSQL DB+실 라우트 구동(tautology 없음), 159 유닛 + 15 통합 = 174 그린

- 하네스가 실 SQL/실 라우트 구동하는지(mock-echo 아님), 격리 정상, 풀플로우 단정 실질성. 게이트 전체.

---

## 최종 게이트 & 커밋 (STEP 7-8)

- [ ] 전체: `bun run test`(통합 포함) · `check` · `lint` · `build` · `typecheck` · `db:check`(4방언) · `db:generate:all` no-op — 전부 그린
- [ ] 마이그레이션: invite_tokens·users status enum/deletionScheduledAt 생성물 보고, **적용은 사용자 요청** (migrate/push 금지)
- [ ] 재암호화 스크립트: 실행하지 않음(사용자 몫), dry-run 사용법 안내
- [ ] 커밋 승인 게이트 → 페이즈별 원자 커밋(리포 스타일). 푸시 금지.
