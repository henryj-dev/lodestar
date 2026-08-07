# 후속 2차 개선 기획서 — KeyStone (rate-limit 추상화 제외)



> 요청: "rate-limit을 제외하고 나머지 계속 다 진행" — 1차 감사(`project-improvement-audit`)에서 후속 후보로 남긴 항목 전부.
> 조사: 2026-07-06, 2개 병렬 Explore. 코드 근거 확인 완료.
> 규칙: 스키마 변경은 `db:generate:all`까지만(적용은 사용자). 커밋은 검증 통과 + 승인 후.

---

## 배경 / 목표

1차에서 "별도 트랙" 또는 "후속"으로 남긴 것 중 rate-limit 저장소 추상화만 제외하고 진행:

- **G1 세션 셀프서비스** — 사용자가 활성 세션 목록을 보고 개별/일괄 철회. (메타 컬럼 이미 존재 → 최저 비용)
- **G2 초대(invite) 플로우** — admin이 초대 메일 발송, 수신자가 비밀번호 최초 설정.
- **G3 계정 삭제(탈퇴) 셀프서비스** — step-up 재인증 후 하드 삭제.
- **G4 마스터 시크릿 다중 버전(무중단 회전)** — old/new secret 동시 시도 + 재암호화 스크립트.
- **G5 잔존 한국어 에러 i18n** — saml-sps/[id], validation.ts, crud-factory/schemas, (정책 결정 후) 프로토콜 API.
- **G6 통합 테스트 하네스** — libSQL 인메모리 + 라우트 직접 호출로 OIDC 풀플로우.

---

## 범위 (In / Out)

### Phase 6 — 세션 셀프서비스 (G1, 최저 비용)

- **In**: `listActiveSessions(db, userId)` + `revokeSessionById(db, sessionId, userId)`(IDOR 방지 userId 조건) 신규. 신규 라우트 `account/sessions/`(목록 — ip/userAgent/lastSeenAt/createdAt 표시, `locals.session.id`로 현재 세션 배지, 개별 revoke, "다른 세션 모두 로그아웃"=기존 `revokeOtherSessions` 재사용). 개별 철회 시 `revokeRefreshTokensForSession` 세트 호출(refresh 연쇄 폐기). audit + 보안 알림. i18n ko/en.
- **Out**: step-up 재인증(세션 철회는 passkey 삭제만큼 파괴적이지 않음 — 열린 질문 ②). **스키마 변경 없음.**

### Phase 7 — 초대 플로우 (G2)

- **In**: `invite_tokens` 테이블(신규, password_reset 패턴). admin `invite` 액션(비밀번호 없이 계정 생성 — `credentials` row 생략, `emailVerifiedAt` NULL) + 초대 메일. `accept-invite` 라우트(토큰 검증 → 비밀번호 최초 설정 + `emailVerifiedAt` 세팅 → credentials insert, 초대 클릭이 이메일 소유 증명이므로 별도 인증 스킵). 로그인 경로에서 "credential 없는 계정"의 로그인 시도가 안전하게 실패하는지 확인·보강. 계정 생성 원자화(`runAtomic`). i18n. `db:generate:all`.
- **Out**: `users.status`에 `pending` enum 추가(옵션 A) — 대신 **옵션 B 채택**: `emailVerifiedAt IS NULL AND credential 부재`로 초대중 판별(스키마 enum 무변경). admin UI에서 초대중 배지 표시.

### Phase 8 — 계정 삭제 셀프서비스 (G3)

- **In**: `account/danger-zone/` 라우트 + self-delete 액션. step-up 재인증(비밀번호 또는 TOTP — passkey delete 패턴 재사용). `assertNotLastAdmin` 재사용(마지막 admin 자기삭제 차단). **하드 삭제**(FK cascade가 credentials/sessions/grants/refresh/saml/memberships 전부 정리; audit는 set null로 보존). audit(`user_self_deleted`) + 탈퇴 확인 메일(세션 만료 전 발송). i18n.
- **Out**: 소프트 삭제/유예기간+복구(enum·GC 배치 필요 — 규모 크고 법적 보존 요건 미정, 열린 질문 ①). 즉시 하드 삭제로 진행.

### Phase 9 — 마스터 시크릿 무중단 회전 (G4)

- **In**: `IDP_SIGNING_KEY_SECRET_PREVIOUS` env 추가. `runtime.ts`의 `signingKeySecret: string` → `signingKeySecrets: string[]`(current 우선, previous 후행) 또는 `{current, previous?}`. 공용 `tryWithSecrets(secrets, fn)` 헬퍼로 복호/검증 함수(unwrapPrivateKey/verifyAccessToken/decryptSecret/decryptTotpSecret/HMAC 검증)를 감싸 순차 시도(호출부 최소 변경). **서명·암호화(발급)는 항상 current로**, 검증·복호만 fallback. 재암호화 스크립트 `scripts/reencrypt-secrets.ts`(openScriptDb 패턴 — signing_keys 활성행·TOTP·LDAP bindPassword를 old→new 재작성). `SECRET_ROTATION.md`를 무중단 절차로 갱신.
- **Out**: `audit_events.hash` 재계산 스크립트(선택 후처리 — 별도, 열린 질문 ③). HMAC 도메인 분리 리팩터(#2/#5/#6/#7 원문 공유 — 별도).

### Phase 10 — 잔존 한국어 에러 i18n (G5)

- **In**:
    - **admin 잔여**: `saml-sps/[id]/+page.server.ts`(7건) `adminError` 전환, `admin/schemas.ts`+`crud-factory.ts` i18n화(`test/unit/admin-zod.test.ts`·`crud-factory.test.ts`의 한국어 기대값 **테스트도 함께 갱신** — 작성/검증 레인 분리 유지).
    - **validation.ts**: `reason: string` → `{key, params}`로 시그니처 변경, 호출부(oidc-clients/saml-sps/skins/ldap-providers)에서 `translate()`.
    - **프로토콜 API**: 사람이 보는 에러 문구만 i18n(`oidc/saml/webauthn/totp` 네임스페이스 신설). **OAuth/SAML 표준 필드(`error`/`error_description` RFC 규격)는 영어 유지** — RP/SP 파싱 대상이므로. 사용자 대면 HTML 에러 페이지·플래시만 번역. (범위는 열린 질문 ④에서 확정)
- **Out**: `passkey-client/+server.ts`의 클라이언트 JS 문자열(클라이언트 i18n 전략 별도 — 소규모라 이번 포함 검토).

### Phase 11 — 통합 테스트 하네스 (G6)

- **In**: `$app/environment` alias 스텁(`dev:false`) 추가로 runtime/bootstrap import 가능화. `drizzle/sqlite/*.sql` 프로그래매틱 적용 유틸(libSQL `:memory:`). 실 라우트 직접 호출 통합 테스트: **OIDC authorize→token→userinfo 풀플로우**(실 DB·실 서명키). 이 하네스 위에 Phase 6~10 신규 로직의 통합 테스트도 추가(초대 수락, 세션 철회, 시크릿 fallback).
- **Out**: SAML SSO 통합(XML 서명 fixture 비용 큼 — 후속), 로그인+MFA HTTP 통합(어댑터-node 기동 필요 — 후속), Playwright 브라우저 e2e(신규 의존성·부트스트랩 — ROI 최하, 제외).

---

## 코드베이스 사실관계 (조사 근거)

- **세션**: 메타(ip/userAgent/lastSeenAt/createdAt) 이미 저장(`schema.sqlite.ts:180-208`), `locals.session.id`로 현재 세션 식별. `revokeSessionById`·목록 헬퍼만 신규. refresh 연쇄는 `revokeRefreshTokensForSession`(`refresh.ts:73-78`) 세트 호출 필요.
- **초대**: `credentials.secret` nullable(`schema.sqlite.ts:92`) → 비밀번호 없는 계정 생성이 스키마상 가능. `username` nullable, `email` NOT NULL. status enum엔 pending 없음(`:45-47`). admin create는 password 필수(`admin/users/+page.server.ts:77-84`), users+credentials insert가 비원자적(`:109-126`).
- **삭제**: 모든 직접 자식 FK cascade(credentials/sessions/grants/refresh/saml/memberships), audit는 set null. `assertNotLastAdmin`(`guards.ts:40-61`) 재사용.
- **시크릿**: `signingKeySecret?: string` 단일(`runtime.ts:7,32`), 소비처 25+ 파일. 복호/검증 함수 전부 `secret: string` 단일 인자 순수함수 → 래퍼로 순차 시도 가능. `bootstrap.ts:62` unwrapPrivateKey는 try/catch 없음(전수 점검 필요). 재암호화 스크립트 자리 = `scripts/`(openScriptDb 패턴).
- **i18n 잔여**: saml-sps/[id] 7건, validation.ts 6 reason 문자열(시그니처 변경 필요), schemas.ts 8건+crud-factory 2건(테스트가 한국어 단정), 프로토콜 60건+(SAML 31·WebAuthn 19·OIDC 9·TOTP 4). `translate(locale, key)`(`i18n/server.ts:5`), `locals.locale`(`hooks.server.ts:48`).
- **테스트**: vitest 순수 유닛만, 라우트 구동 0건. runtime/bootstrap만 `$app/environment` 사용(alias 부재로 현재 import 불가). libSQL 인메모리 가능(`@libsql/client` 기설치), `scripts/lib/db.ts`에 SQL 실행 유틸 존재. adapter-node 경로가 e2e 마찰 최소.

---

## 접근법 / 리스크 / 순서

| Phase     | 접근                                                                        | 리스크 & 완화                                                                                                          |
| --------- | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| 6 세션    | 기존 함수·account 라우트 패턴 복제, 스키마 무변경                           | 개별 철회 시 refresh 연쇄 누락 → 세트 호출 강제. IDOR → userId 조건 필수                                               |
| 7 초대    | credentials 생략 계정 + 토큰 패턴, 옵션 B(enum 무변경)                      | credential 없는 계정 로그인 안전 실패 확인이 관문 → 로그인 경로 점검·보강 필수                                         |
| 8 삭제    | admin delete 복제 + step-up + assertNotLastAdmin                            | 비가역 → step-up 재인증·확인 메일·마지막 admin 차단                                                                    |
| 9 시크릿  | tryWithSecrets 래퍼(호출부 최소 변경), 발급은 current                       | 25+ 소비처 파급 → 헬퍼로 국소화, unwrapPrivateKey 무보호 지점 전수 점검. 재암호화 스크립트는 사용자가 실행(적용 안 함) |
| 10 i18n   | admin/validation은 완전 전환, 프로토콜은 사용자 대면만(표준 필드 영어 유지) | 테스트 계약 깨짐 → 작성/검증 레인 분리해 테스트 동반 갱신. 표준 준수 위해 범위 신중                                    |
| 11 테스트 | libSQL 인메모리 + 라우트 직접 호출                                          | $app/environment 스텁·마이그레이션 적용 유틸이 관문 → Phase 11을 6~10 뒤에 둬 신규 로직까지 커버                       |

**순서**: 6 → 7 → 8(계정 생명주기 묶음, 일부 병렬) → 9(독립) → 10(독립, 병렬 가능) → 11(마지막, 신규 로직 통합 테스트 포함). 6·9·10은 파일 겹침 적어 병렬 착수 가능.

---

## 열린 질문 (승인 시 확정)

1. **계정 삭제(Phase 8) 방식** — 즉시 하드 삭제(권장, 저비용) vs 소프트 삭제+유예기간(법적 보존/오탈퇴 복구 필요 시). 하드 삭제로 진행할지?
2. **세션/삭제 step-up 재인증** — 세션 개별 철회에도 비밀번호 재확인을 요구할지(계정 삭제는 필수 권장). 세션은 생략, 삭제만 step-up이 기본안.
3. **audit_events.hash 재계산(Phase 9)** — 무중단 회전에 필수는 아님(향후 무결성 검증 오탐 방지용). 이번 스크립트에 포함할지, 제외할지(권장: 제외, 문서로만 안내).
4. **프로토콜 API i18n 범위(Phase 10)** — (a) 사용자 대면 문구만 번역·표준 필드 영어 유지(권장), (b) 전량 번역, (c) 프로토콜은 이번 제외하고 admin/validation만. SAML/WebAuthn가 60건+라 범위가 작업량을 크게 좌우.

---

## 산출물

- `docs/plans/followup-round2/PLAN.md` (본 문서) → 승인 후 `TODO.md`
- 스키마 변경분(invite_tokens 등)은 `db:generate:all`까지만 — 적용은 사용자.
