# 프로젝트 전수 개선 감사 기획서 — KeyStone

> **상태: 완료 (병합됨). 이 문서는 실행 이력이며 현행 사양서가 아닙니다.**
> 미체크로 남은 항목은 당시 커밋/검증 게이트 절차이고, 작업 자체는 병합되었습니다.
> **마이그레이션의 실제 DB 적용 여부는 배포 환경에서 직접 확인하세요.**
> 현행 사양은 [README](../../../README.md) · [관리자 매뉴얼](../../ADMIN_GUIDE.md) 참조. (최종 확인: 2026-08-07)

> 요청: "이 프로젝트 내에서 개선하거나 수정할 내용들, 추가할 내용들을 모두 파악해서 적용될 수 있도록"
> 조사: 2026-07-05~06, 5개 병렬 Explore 에이전트(보안=Opus, 아키텍처·DB=Opus, 품질/테스트·CI/기능·UX=Sonnet).
> 전제: Critical/High 보안 취약점 없음. 이전 리포트(2026-07-02)·deferred-followups(TOTP TOCTOU/i18n/CRUD 팩토리)는 모두 구현·커밋 완료 확인.

---

## 배경 / 목표

프로젝트는 문서·CI·보안 방어(세션/CSRF/OIDC/SAML/LDAP) 수준이 이미 높으나, 조사 결과 다음 5축의 격차가 확인됨:

1. **보안 Medium 6건** — 타이밍 열거, 계정 잠금 부재, tenant 격리 우회 1건, code 교환 세션 검사 누락 등.
2. **운영 시한폭탄** — 만료 데이터 GC 전무(purge 함수 3개가 orphan, cron 없음 → 9종 테이블 무한 성장), 마이그레이션 4트랙 비대칭(d1 21개 vs 나머지 4개).
3. **기능 공백** — 이메일 인증 플로우 부재로 `email_verified` 클레임이 **항상 false**(RP 신뢰 시 실질 버그), 보안 알림 메일 부재.
4. **테스트 불균형** — 62개 유닛 테스트가 전부 그린이지만 정작 **토큰 서명/발급·세션·패스워드·rate-limit 알고리즘은 테스트 0건**. schema-parity가 인덱스/제약 drift를 못 잡음.
5. **품질·문서 부채** — `users/[id]` 677줄, admin "라벨은 영어·에러는 한국어" 혼재, **보안 감사 문서 2건 public repo 잔존(E9 미처리)**, 문서·메모리 drift.

목표: 위 격차를 페이즈별로 해소해 적용 가능한 상태로 만든다. 스키마 변경은 `db:generate`까지만(적용은 사용자).

---

## 범위 (In / Out)

### Phase 1 — 보안 Medium 일괄 해소

- **In**:
    - **S1 로그인 타이밍 열거**: 미존재 계정에도 더미 scrypt 검증 수행해 응답시간 균등화 (`src/lib/server/auth/users.ts:46-63`; find-id/find-password의 기존 균등화 패턴 재사용).
    - **S2 계정 단위 잠금**: 기존 rate-limit 인프라를 `login:user:<username>` 키로 재사용해 계정별 backoff 추가 — **스키마 변경 없이** 구현 (IP rate-limit과 병행).
    - **S3 lookup API tenant 격리**: `api/users/lookup/+server.ts:35-38`의 `?id=` 경로에 tenant 스코프 강제(또는 호출자 tenant 명시 요구).
    - **S4 code 교환 세션 검사**: authorization_code 교환 시 `grant.sessionId` 세션의 `revokedAt`/만료 확인 (`oidc/token/+server.ts:392-438`; refresh 경로의 기존 검사 로직 재사용).
    - **S5 issuer fail-closed**: 프로덕션에서 `IDP_ISSUER_URL` 미설정 시 host-header fallback 대신 명시적 실패(503) + 부트스트랩 시 필수 env(`IDP_SIGNING_KEY_SECRET` 포함) 검증(fail-fast).
- **Out**: 마스터 시크릿 용도 분리·회전 절차(운영 하드닝 트랙, 별도 작업 — 회전 절차 문서화만 Phase 5에 포함), skin sanitize 강화(Low, CSP로 완화 중), WebAuthn rpID(Low, 실질 위조 불가).

### Phase 2 — 운영 안정성 (GC·마이그레이션·원자성·캐시)

- **In**:
    - **O1 만료 데이터 GC**: Cloudflare Cron Trigger + `scheduled()` 핸들러 신설, 만료 대상 전 테이블(sessions/oidc_grants/refresh_tokens/password_reset_tokens/webauthn challenges/rate_limits/saml_slo_states/saml_authn_request_ids/saml_sessions) 일괄 purge. Node 런타임 대응 경로 포함. 기존 orphan purge 함수 3개 재사용·확장. wrangler.example.jsonc에 cron 설정 추가.
    - **O2 마이그레이션 트랙 대칭화**: `db:generate:all` 스크립트 추가, 4트랙 미생성 diff를 잡는 CI 체크(또는 parity 테스트), pg/mysql/sqlite 트랙의 밀린 마이그레이션 생성(**적용은 안 함**).
    - **O3 refresh 회전 원자화**: claim→insert 2-write를 signing-keys/totp-confirm과 동일한 batch/transaction 분기로 원자화. 이 분기 패턴을 `atomic()` 공용 유틸로 추출(3곳 재사용).
    - **O4 서명키 캐시**: `getActiveSigningKey`/`getPublicJwks`에 baseline과 동일한 globalThis 단기 캐시(회전 시 무효화).
    - **O5 스키마 정리**: `client_skins.createdAt` sqlite 단위 통일(timestamp_ms), legacy `oidc_grants.code` 컬럼+인덱스 drop — `db:generate`까지만. `drizzle.config.ts:9`의 사실과 다른 gitignore 주석 정리.
- **Out**: **rate-limit 저장소 DO/KV 추상화**(H3 — 구조 변경이 커서 별도 트랙 권장, 열린 질문 ③), mysql signing_keys 부트스트랩 경로 FOR UPDATE(Low, 발생 조건 희귀).

### Phase 3 — 기능 추가 (이메일 인증 + 보안 알림)

- **In**:
    - **F1 이메일 인증 플로우**: 가입 시 인증 메일 발송 → 토큰 검증 라우트 → `users.emailVerifiedAt` 세팅 → `email_verified` 클레임 정상화. 재발송·만료 처리 포함. (토큰 테이블은 기존 password_reset_tokens 패턴 재사용, 스키마 필요 시 `db:generate`까지만.)
    - **F2 보안 알림 메일**: 비밀번호 변경/재설정 완료, MFA 등록·삭제, 패스키 등록·삭제, admin의 비밀번호 초기화·계정 잠금 시 대상 사용자에게 통지 메일 (기존 email.ts 템플릿 패턴 확장).
    - **F3 admin 강제 로그아웃 액션**: `revokeAllUserSessions` 재사용한 전용 버튼/액션 (소규모).
- **Out(별도 후속 후보)**: 초대(invite) 플로우, 셀프서비스 활성 세션 목록/철회, 계정 삭제 — 각각 독립 기획 필요(열린 질문 ①). 새 기기/위치 로그인 알림(기기 지문 인프라 필요).

### Phase 4 — 테스트 확충 (P0/P1)

- **In**:
    - **T1 P0 유닛 테스트**: `crypto/keys.ts`(JWT 서명·access token HMAC·키 래핑), `oidc/grant.ts`, `oidc/refresh.ts`(회전·재사용 감지), `auth/session.ts`, `auth/password.ts`(scrypt·레거시 업그레이드), `ratelimit/index.ts`(슬라이딩 윈도우 본체). Phase 1~3 신규 로직(계정 잠금, 이메일 인증 토큰, GC purge) 테스트 포함.
    - **T2 schema-parity 강화**: 인덱스/unique 제약 parity 비교 추가(방언별 API 차이는 명시적 예외 목록으로 — mysql partial-unique 등 known gap을 테스트가 문서화), 컬럼 타입·nullable 비교.
    - **T3 인프라**: `test:coverage`(@vitest/coverage-v8) + `typecheck`·`lint:fix`·`db:check` 스크립트, lefthook pre-commit에 eslint 추가.
- **Out**: 통합/e2e 하네스(Playwright 등 — 가치 크지만 별도 기획 규모), LDAP/SAML response 유닛(P2, 후속).

### Phase 5 — 품질·문서 정리

- **In**:
    - **Q1 보안 문서 격리**: `docs/security-audit-2026-05-12.md`·`docs/security-pentest-report.md` repo에서 제거(E9) — 처리 방식은 열린 질문 ②.
    - **Q2 `users/[id]/+page.server.ts`(677줄) 분리**: actions를 도메인별 모듈(profile/org/service)로 분리, 동작 무변경.
    - **Q3 admin 에러 메시지 i18n**: 비정형 admin 라우트의 하드코딩 한국어 에러를 t()/translate() 전환(UI 라벨은 이미 영어 — 혼재 해소). 공통 `requireFormId` 류 헬퍼 추출로 중복 문구 12곳+ 정리.
    - **Q4 문서·메모리 정합**: improvement-report의 stale 항목(refresh token "미구현" 표기 등) 갱신, deferred-followups TODO 상태 갱신, 프로젝트 메모리(OIDC scope 후속) 최신화, 시크릿 회전 절차 문서화.
- **Out**: saml/sso·oidc/token 파일 물리 분리(Low, 함수 단위로는 이미 정리됨), knip/depcheck 도입(Low), en.json 원어민 검수(외부 작업).

---

## 코드베이스 사실관계 (조사 근거 요약)

- **보안 양호 확인**: 세션(해시 저장·회전·cascade 폐기), CSRF(전역 Origin 강제+double-submit), OIDC(PKCE S256 전용, redirect_uri 정확일치, code 1회 소진, refresh 회전+family 폐기), SAML(XSW 다층 방어, ACS 강제), LDAP(필터/DN 이스케이프), scrypt(N=2^15,r=8,p=3)+레거시 자동 업그레이드, hash 기반 CSP.
- **보안 결함 근거**: S1=`users.ts:46-63`(미존재 시 해시 미수행), S2=`login/+page.server.ts:120`(IP rate-limit뿐), S3=`api/users/lookup/+server.ts:35-38`(id 경로 tenant 무필터), S4=`oidc/token/+server.ts:392-438`(code 경로만 세션 미검사), S5=`runtime.ts:55-62`(Host fallback)+`bootstrap.ts:106`(시크릿 미설정 시 조용히 스킵).
- **GC 부재**: `webauthn.ts:158`·`refresh.ts:178`·`ratelimit/index.ts:84`의 purge 함수 호출부 0건, wrangler cron 전무. sessions/oidc*grants/password_reset_tokens/saml*\* 은 purge 함수조차 없음. rate_limits는 요청마다 신규 key 생성으로 폭증.
- **마이그레이션 비대칭**: d1 트랙 21개(0000–0020) vs pg/mysql/sqlite 각 4개. d1·sqlite가 같은 스키마 공유하는데 히스토리 상이. `drizzle.config.ts:9` 주석은 gitignore라 하나 실제 tracked.
- **테스트 현황**: 10파일 62테스트 전부 순수 로직. `+server.ts` 23 + `+page.server.ts` 27개 라우트 핸들러 직접 구동 테스트 0. CI(lint/check/test/build/CodeQL/gitleaks/dependabot)는 양호.
- **기능 공백 근거**: `emailVerifiedAt` 세팅 코드 0건(읽기 전용)인데 `token/+server.ts:86`·`userinfo/+server.ts:73`이 클레임으로 노출. email.ts 템플릿 2종(find-id/reset)뿐.
- **이미 구현 확인(문서만 stale)**: OIDC groups/address/organization scope, refresh_token grant, introspect/revoke, 감사 해시, TOTP TOCTOU, CRUD 팩토리+zod+FK 검증, i18n en 476키 1:1 대칭+LocaleToggle+SSR 로케일. SAML assertion 암호화도 구현된 것으로 판단(saml-encrypt.test.ts 라운드트립 + verify:saml-encryption 스크립트 존재; 기능 조사 레인의 "미구현" 보고는 오판으로 보이며 실행 시 재확인).

---

## 접근법 / 리스크 / 트레이드오프

| Phase    | 접근                                                                                          | 리스크 & 완화                                                                                                                   |
| -------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| 1 보안   | 기존 패턴 재사용(타이밍 균등화·rate-limit 키·refresh의 세션 검사)으로 스키마 무변경 최소 수정 | 인증 핫패스 수정 → Phase 4 테스트가 커버 + 독립 검증 레인. S2는 정상 사용자 오탐 위험 → 창/임계값 보수적(예: 10회/15분 backoff) |
| 2 운영   | cron+scheduled 신설, 나머지는 기존 유틸 패턴 추출·재사용                                      | O2 마이그레이션 생성물은 커밋만, 적용은 사용자(CLAUDE.md 규칙). GC DELETE는 만료분만·배치 크기 제한으로 타임아웃 방지           |
| 3 기능   | password_reset_tokens 검증된 패턴 복제로 이메일 인증 구현                                     | 기존 가입 사용자 처리(전원 미인증 상태) → 로그인 차단은 하지 않고 클레임·배너만(비파괴적)                                       |
| 4 테스트 | WebCrypto/HMAC은 실제 키로, DB는 기존 mock 패턴                                               | 없음(추가만)                                                                                                                    |
| 5 품질   | 동작 무변경 리팩터 + 문서 갱신                                                                | Q2는 diff 리뷰로 회귀 방지, Q1은 히스토리에 문서가 남는 한계 명시                                                               |

**의존성**: Phase 1·2·3은 파일 겹침 적어 부분 병렬 가능(단 S5와 O1이 hooks/bootstrap 근처에서 겹칠 수 있어 순서 조율). Phase 4는 1~3 이후(신규 로직 테스트 포함). Phase 5는 독립.

---

## 열린 질문 (승인 시 확정)

1. **Phase 3 범위** — 이메일 인증+보안 알림+강제 로그아웃(제안)만? 아니면 초대 플로우/세션 셀프서비스까지 이번에 포함? (후자는 규모가 커져 별도 기획 권장)
2. **보안 감사 문서 2건(E9)** — (a) repo에서 삭제만(히스토리 잔존 감수, 권장), (b) private 위치로 이동 후 삭제, (c) 유지. ※ 히스토리 rewrite는 파괴적이라 제안하지 않음.
3. **rate-limit 저장소 추상화(DO/KV)** — 이번 범위에 포함할지, 별도 트랙으로 미룰지(권장: 미룸 — 구조 변경이 크고 GC(O1)로 폭증 문제는 완화됨).
4. **진행 방식** — 5페이즈 전체 승인 후 순차(1→2→3→4→5) 진행 권장. 일부 페이즈만 선별 진행도 가능.

---

## 산출물

- `docs/plans/project-improvement-audit/PLAN.md` (본 문서)
- 승인 후 `docs/plans/project-improvement-audit/TODO.md` (페이즈별 상세 투두 + 수용 기준)
- 스키마 변경분은 `db:generate` 마이그레이션 생성까지만 — 적용은 사용자 요청.
