# KeyStone 개선 리포트 & 수정 계획 (2026-07-02)

> 3개 병렬 분석(미구현·갭 전수 탐색 / 보안 취약점 리뷰 / 아키텍처·품질 리뷰) 결과를 종합.
> 분석 기준 브랜치: `chore/remove-d1-binding` (origin/main과 동일, 미커밋 변경 없음).

> # ⚠️ 이 문서는 2026-07-02 시점의 스냅샷입니다 — 현행 사실로 읽지 마세요
>
> 아래 본문의 "미구현 / 부재 / 전무" 서술은 **대부분 이미 해소되었습니다.** 이력 보존을 위해
> 본문은 그대로 두되, 현재 상태는 이 블록을 기준으로 판단하세요.
> 현행 문서: [README](../README.md) · [관리자 매뉴얼](ADMIN_GUIDE.md) · [시크릿 회전](SECRET_ROTATION.md).
>
> **정오표 (2026-07-06 작성 → 2026-08-07 갱신)**
>
> | 본문 서술                                   | 현재 상태                                                                                                                                                 |
> | ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
> | A1 "Refresh Token 미구현"                   | **구현 완료** — `oidc/token` refresh_token grant, 회전 + 재사용 감지 family 폐기                                                                          |
> | A2 "SAML Assertion 암호화 미구현"           | **구현 완료** — `saml/encrypt.ts`, `verify:saml-encryption` 스크립트                                                                                      |
> | A3 "admin users 무페이지네이션"             | **해소** — 커서 페이지네이션 + 검색                                                                                                                       |
> | A4 "OIDC introspection·revocation 부재"     | **구현 완료** — `/oidc/introspect`(RFC 7662), `/oidc/revoke`(RFC 7009)                                                                                    |
> | A5 "authorize 파라미터 미처리"              | **부분 해소** — `prompt`(none/login) · `max_age` · `id_token_hint` · `login_hint` 처리됨. `claims` · `request`/`request_uri` 는 여전히 미지원             |
> | A6 "discovery 정직성"                       | **해소** — 실제 발급 클레임과 일치(2026-08-07 `entitlements` 추가로 재정합)                                                                               |
> | A7 "AuthnRequest HTTP-POST 바인딩 미지원"   | **해소** — `POST /saml/sso` 구현됨. **IdP-initiated SSO 는 여전히 미지원**                                                                                |
> | B1 "테스트·CI 테스트 단계 전무"             | **해소** — vitest 36 파일 340 테스트(2026-08-07 기준), CI 게이트 구축                                                                                     |
> | B2/B3/B4 "헬스체크·관측성·에러 페이지 부재" | **해소** — `/api/health`, wrangler `observability`, 루트 `+error.svelte`                                                                                  |
> | C1~C10 신규 보안 발견                       | **전건 처리** — 본문 "적용 현황" 절 참조                                                                                                                  |
> | D1/D2 미반영                                | **해소** — admin CSRF 토큰, `audit_events.hash` 행 단위 MAC                                                                                               |
> | D3 "argon2 구현체 전환 권고 미이행"         | **다른 방향으로 해소** — argon2id 가 아니라 **scrypt**(`node:crypto` 네이티브)로 전환. 아래 "의도적 보류" 절의 _"현행 유지 권장"_ 결론은 **뒤집혔습니다** |
> | E1/E2/E3/E5/E7/E8 부채                      | **해소**                                                                                                                                                  |
> | E4 "admin CRUD 보일러플레이트"              | **해소** — `lib/server/admin/crud-factory.ts` + Zod 스키마 도입(본문의 "의도적 보류" 는 이후 뒤집힘)                                                      |
> | E9 "감사 문서 public repo 잔존"             | **처리 완료** (repo 에서 제거 — 히스토리에는 잔존)                                                                                                        |
> | E10 "i18n en.json 없음"                     | **해소** — `src/lib/i18n/en.json` 존재, 콘솔 ko/en 지원                                                                                                   |
> | 230행 "OIDC 스코프 확장 별도 메모"          | **구현 완료** — `groups` · `address` · `organization` 전부 발급됨                                                                                         |
>
> **아직 열려 있는 것**
>
> - A5 잔여 — `prompt=consent`, `claims`, `request` / `request_uri` 미지원.
> - A7 — SAML **IdP-initiated SSO** 미지원(SP-initiated 만).
> - A8 — `WantAuthnRequestsSigned` 는 SP 설정을 반영하도록 고쳐졌으나, metadata 에 **암호화용
>   KeyDescriptor 가 여전히 없습니다**(`use="signing"` 만 출력).
> - R1 — 회원가입 계정 열거. 제품 판단으로 의도적 미채택.
> - R9 — admin Zod `.strict()`. 정상 폼을 깨뜨려 **권장하지 않음**으로 결론.
> - (해소됨) SAML `Entitlements` 속성 — 발행·정의 UI 는 있었으나 허용 속성 화이트리스트에 키가
>   빠져 저장이 불가능해 무동작이었다. 2026-08-07 화이트리스트 보강 + 관리자 폼 경로 회귀 테스트 추가.
> - `audit_events.hash` 재계산 전용 배치 부재 — [SECRET_ROTATION.md](SECRET_ROTATION.md) §3 참조.

---

## 종합 판정

기존 보안 감사(2026-05-12)의 Critical/High 대부분이 실제 코드에 반영되어 있고, **신규 Critical/High 취약점은 없다**. 현재 프로젝트의 부채는 세 갈래로 요약된다.

1. **기능-문서 불일치**: README/스키마가 광고하지만 실제로는 없는 기능 (Refresh Token, SAML Assertion 암호화).
2. **품질 인프라 공백**: 테스트 프레임워크·테스트·CI 테스트 단계 전무, 관측성(헬스체크·에러 모니터링) 부재.
3. **이식성의 유지비**: 4개 DB 방언 × 2개 배포 타깃을 타입/추상화가 아닌 파일 복제와 수동 검증으로 지탱 → drift와 보일러플레이트 누적.

---

## A. 기능 갭 (미구현 / 부분 구현)

| #   | 항목                                                                                                                                                                                                | 근거                                                                             | 심각도 |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------ |
| A1  | **Refresh Token 미구현** — README·스키마(`oidc_refresh_tokens`)·클라이언트 기본 grantTypes에는 있으나 token 엔드포인트가 `authorization_code` 외 전부 거부. access token TTL 5분이라 갱신 수단 없음 | `src/routes/oidc/token/+server.ts:79-82,257-264`, `schema.sqlite.ts:216,286-308` | High   |
| A2  | **SAML Assertion 암호화 미구현** — `encryptAssertion` DB 컬럼/플래그만 존재, `saml/` 전체에 암호화 코드 0건. 관리자가 켜도 무동작                                                                   | `schema.sqlite.ts:332`, `src/lib/server/saml/*`                                  | Medium |
| A3  | **관리자 users 목록 무페이지네이션** — 테넌트 전 사용자 로드(limit/offset/검색 없음). audit 페이지는 커서 페이지네이션 있음(불균일)                                                                 | `src/routes/admin/users/+page.server.ts:24-26`                                   | Medium |
| A4  | **OIDC 표준 엔드포인트 부재** — introspection·revocation 라우트 없음                                                                                                                                | `src/routes/oidc/`                                                               | Medium |
| A5  | **OIDC authorize 파라미터 미처리** — `prompt`(none/login/consent), `max_age`, `login_hint`, `id_token_hint`, `claims`, `request`/`request_uri` 등 미처리                                            | `src/routes/oidc/authorize/+server.ts:33-40`                                     | Medium |
| A6  | **discovery 정직성** — `claims_supported`에 `title`(실제는 `job_title`), `scopes_supported`에 `phone` 누락(코드는 처리함)                                                                           | `src/routes/.well-known/openid-configuration/+server.ts:16,23`                   | Low    |
| A7  | **SAML IdP-initiated SSO 부재 / AuthnRequest HTTP-POST 바인딩 미지원** — GET(Redirect)만 처리                                                                                                       | `src/routes/saml/sso/+server.ts:26`                                              | Low    |
| A8  | **SAML metadata 하드코딩** — `WantAuthnRequestsSigned="false"` 고정(SP별 필드 무시), 암호화 KeyDescriptor 없음                                                                                      | `src/lib/server/saml/metadata.ts:50`                                             | Low    |

## B. 품질/운영 인프라 공백

| #   | 항목                                                                                                                                                     | 근거                                                                                | 심각도 |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ------ |
| B1  | **테스트 인프라 전무** — vitest/playwright 등 없음, 테스트 파일 0건, CI(`ci.yml`)는 lint+typecheck+build만                                               | `package.json`, `.github/workflows/ci.yml`                                          | High   |
| B2  | **헬스체크 엔드포인트 없음** — `/health` 등 부재                                                                                                         | 라우트 전반                                                                         | Medium |
| B3  | **관측성 미설정** — wrangler에 `observability`/`logpush`/`tail_consumers` 블록 없음, 에러 트래킹 통합 없음                                               | `wrangler*.jsonc`                                                                   | Medium |
| B4  | **루트 `+error.svelte` 없음** — 500/503 시 SvelteKit 기본 화면 노출                                                                                      | `src/routes/`                                                                       | Low    |
| B5  | **`guards.ts` 503 메시지가 D1 전용 문구** — postgres/mysql 배포에서 오해                                                                                 | `src/lib/server/auth/guards.ts:8`                                                   | Low    |
| B6  | **nodemailer SMTP의 Workers 런타임 미검증** — raw TCP 소켓 의존, Cloudflare 배포에서 동작 보장 안 됨. `IDP_ISSUER_URL` 미설정 시 재설정 메일 silent skip | `src/lib/server/email.ts`, `src/routes/(auth)/find-password/+page.server.ts:99-125` | Medium |

## C. 신규 보안 발견 (모두 Medium 이하)

| #   | 항목                                                                                                                                                                                      | 근거                                                                       | 심각도 |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | ------ |
| C1  | **SAML LogoutRequest 파서 방어 비대칭** — DOCTYPE/ENTITY 차단·`onErrorStopParsing` 없음, 서명 검증 前 파싱                                                                                | `src/lib/server/saml/slo.ts:205-233`, `routes/saml/slo/+server.ts:262,288` | Medium |
| C2  | **SAML LogoutRequest replay** — IssueInstant skew/request-ID 1회성 소비/Destination 검증 없음                                                                                             | `src/lib/server/saml/slo.ts:205-233`                                       | Medium |
| C3  | **TOTP verify 브루트포스** — `/api/totp/verify`·enroll/confirm rate-limit 없음, `lastUsedStep` 미전달로 재사용 방지 없음                                                                  | `src/routes/api/totp/verify/+server.ts`                                    | Medium |
| C4  | **스킨 `<style>` CSS 인젝션** — sanitizer `FORBIDDEN_TAGS`에 `style` 누락 + CSP `style-src 'unsafe-inline'` → UI 리드레싱/피싱(admin이 URL 설정 전제)                                     | `src/lib/server/skin/sanitize.ts:18`                                       | Medium |
| C5  | **find-id 타이밍 계정 열거** — 존재 시에만 동기 SMTP 왕복                                                                                                                                 | `src/routes/(auth)/find-id/+page.server.ts:88-98`                          | Medium |
| C6  | **IPv6 /128 rate-limit 우회** — IP 키 정규화(/64) 없음                                                                                                                                    | `src/lib/server/audit/index.ts:23`                                         | Medium |
| C7  | **LDAP 레거시 평문 bindPassword 런타임 사용** — 신규 저장은 암호화 강제하나 레거시 평문은 warn 후 그대로 bind                                                                             | `src/routes/(auth)/login/+page.server.ts:148-152`                          | Medium |
| C8  | reset-password 제출 action rate-limit 없음(토큰 256bit라 실익 낮으나 정합성 결함)                                                                                                         | `src/routes/(auth)/reset-password/+page.server.ts:63-125`                  | Low    |
| C9  | userinfo `verifyAccessToken`에 `expectedAud` 미전달 + access token `sid` 부재(로그아웃 후 TTL 내 접근)                                                                                    | `src/routes/oidc/userinfo/+server.ts:36,45`                                | Low    |
| C10 | 기타 Low: SLO IdP-initiated LogoutResponse 서명 미검증, SLO/SSO replay-ID를 서명 검증 前 소비, `xmlEscape` 제어문자 미제거, webauthn rate-limit 키 XFF fallback, end-session GET drive-by | 각 파일 참조                                                               | Low    |

## D. 기존 보안 감사 미반영 항목 (High)

| #   | 항목                                                                                                                                           | 상태                                   |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| D1  | **H-OIDC-5** — admin oidc-clients 액션(regenerateSecret/delete/update)에 명시적 CSRF 토큰 없음(전역 Origin 검사에만 의존)                      | `ctrls` 마커 없음, 미반영              |
| D2  | **H-ADMIN-2** — 감사 로그 무결성(chained-hash/append-only/Logpush 미러) 미구현                                                                 | 미반영                                 |
| D3  | **H-DEP-1** — `@hicaru/argon2-pure.js ^0.0.x`(단일 maintainer 순수 JS)를 패스워드 해시 신뢰 뿌리에 사용. `@node-rs/argon2` 등 전환 권고 미이행 | 미반영(파라미터는 OWASP 최소로 상향됨) |

## E. 아키텍처/품질 부채

| #   | 항목                                                                                                                                                                                                                                                                    | 근거                                                                           | 심각도     |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ---------- |
| E1  | **스키마 3벌 수동 동기화 → drift 실재** — MySQL만 `signing_keys` "tenant당 active 1개" partial unique index 누락(sqlite/pg는 DB 강제). MySQL 배포 시 race로 중복 active 키 가능                                                                                         | `schema.mysql.ts:513-517` vs `schema.sqlite.ts:515-517`/`schema.pg.ts:469-471` | High       |
| E2  | **`users/[id]` load 14개 쿼리 순차 워터폴** — 대시보드/skins는 `Promise.all` 사용(불일치)                                                                                                                                                                               | `src/routes/admin/users/[id]/+page.server.ts:14-136`                           | High(즉효) |
| E3  | **런타임 의존성 7종이 devDependencies에 오분류** — `@simplewebauthn/server`, `xmldsigjs`, `@xmldom/xmldom`, `xpath`, `@peculiar/x509`, `reflect-metadata`, `@yrneh_jang/ldapjs`. Cloudflare 번들은 무해하나 **adapter-node + `npm ci --omit=dev`에서 MODULE_NOT_FOUND** | `package.json`                                                                 | Medium     |
| E4  | **admin CRUD 보일러플레이트 대량 중복** — teams/parts/positions/departments near-identical, `fail(400)` 12곳+ 반복, URL/host 검증 라우트마다 재발명                                                                                                                     | `src/routes/admin/{teams,parts,positions,departments}/+page.server.ts`         | Medium     |
| E5  | **검증 라이브러리 부재** — 전량 `String(fd.get()).trim()` 수동 검증, 에러 payload shape 불일치                                                                                                                                                                          | admin 라우트 전반                                                              | Medium     |
| E6  | **세션 매 요청 DB 조인 무캐싱** (보안상 무캐싱이 안전한 기본값 — 트레이드오프)                                                                                                                                                                                          | `src/lib/server/auth/session.ts:84-89`                                         | Low        |
| E7  | **디스크 위생** — `wrangler.backup.jsonc`에 평문 SMTP 실자격/account_id/D1 id 방치(gitignore는 커밋만 차단), `wrangler.example copy.jsonc` 열화 사본, 빈 `.ignore/`                                                                                                     | 워킹트리                                                                       | Medium     |
| E8  | **`chore/remove-d1-binding` 미완** — `driver-d1.ts` 잔존, `wrangler.jsonc`에 D1 vars 잔존하며 Hyperdrive/postgres와 혼재                                                                                                                                                | 현 브랜치                                                                      | Medium     |
| E9  | 보안 감사 문서(`security-audit`/`pentest-report`)가 public repo에 포함(감사 self-지적)                                                                                                                                                                                  | `docs/`                                                                        | Low        |
| E10 | i18n: `en.json` 없음(ko 단일), admin `.svelte` 다수 하드코딩 한국어, 이메일 `lang="ko"` 고정                                                                                                                                                                            | `src/lib/i18n/`, admin 라우트                                                  | Low        |

---

## 수정 계획 (단계별)

### 0단계 — 즉시/저위험 (반나절)

- **E2**: `users/[id]` load 14쿼리 `Promise.all` 병렬화 (즉효 성능).
- **E7**: `wrangler.backup.jsonc`(평문 SMTP 자격) + `wrangler.example copy.jsonc` + 빈 `.ignore/` 삭제. (삭제 전 유효 값은 별도 시크릿 스토어로 이전 확인.)
- **C4**: skin sanitizer `FORBIDDEN_TAGS`에 `"style"` 추가.
- **B5**: `guards.ts:8` 503 메시지 방언 중립화.
- **A6**: discovery `claims_supported`/`scopes_supported`를 실제 코드와 일치.

### 1단계 — 보안 하드닝 (2~3일)

- **C1/C2**: LogoutRequest 파서에 DOCTYPE/ENTITY 차단 + `onErrorStopParsing`, 서명 검증을 파싱 앞으로, IssueInstant skew + request-ID 1회성 소비 + Destination 대조.
- **C3**: TOTP verify/enroll-confirm에 rate-limit + 실패 카운터, `verifyTotp`에 `lastUsedStep` 전달.
- **C6**: rate-limit IP 키 IPv6 /64 정규화.
- **D1(H-OIDC-5)**: admin oidc-clients 액션에 폼 CSRF 토큰.
- **C5/C8**: find-id 균등 지연(또는 메일 `waitUntil` 분리), reset-password 제출 rate-limit.
- **C7(M-D)**: LDAP 레거시 평문 bindPassword 강제 마이그레이션 경로.

### 2단계 — 기능-문서 정합성 (1~2주)

- **A1**: Refresh Token을 **구현**하거나 **문서/스키마/기본 grantTypes에서 제거** (택1 결정 필요 — 아래 질문 참조).
- **A2**: SAML Assertion 암호화를 구현하거나 `encryptAssertion` 플래그 제거 + UI 비활성.
- **A3**: users 목록 커서 페이지네이션 + 검색 (audit 페이지 패턴 재사용).
- **A4/A5**: OIDC introspection/revocation, `prompt`/`id_token_hint`/`max_age` 등 우선순위 높은 authorize 파라미터.

### 3단계 — 품질 인프라 (1~2주)

- **B1**: vitest 도입 + 핵심 보안 로직(password/totp/oidc grant/saml 서명/rate-limit) 유닛 테스트 + CI 테스트 단계 추가.
- **E1**: 스키마 3파일 스냅샷 크로스체크 테스트를 CI에 추가(우선), 이후 공통 컬럼 팩토리 검토. MySQL signing_keys 불변식 앱 레벨 가드 확인/보강.
- **E3**: 런타임 의존성 7종을 `dependencies`로 이동.
- **B2/B3/B4**: `/health` 엔드포인트, wrangler `observability` 활성, 루트 `+error.svelte`.
- **D2(H-ADMIN-2)**: 감사 로그 chained-hash/append-only.

### 4단계 — 리팩터/장기 (여유 시)

- **E4/E5**: 조직 CRUD 팩토리 추출 + zod/valibot 도입(폼 스키마 타입 공유).
- **E8**: `chore/remove-d1-binding` 완료(driver-d1 제거 or D1 vars 정리) — 방향 결정 필요.
- **D3(H-DEP-1)**: argon2 구현체 신뢰성 재평가(`@node-rs/argon2` 벤치/호환).
- **E10**: i18n en.json + admin 하드코딩 문자열 `t()` 전환.
- **E9**: 보안 문서 저장소 외부 이전.

### 사용자 직접 실행 권장 (샌드박스 미실행)

```bash
bun audit --audit-level=high
bunx osv-scanner --lockfile=bun.lock
gitleaks detect --log-opts="--all" --redact
```

---

## 적용 현황 (2026-07-03 업데이트)

사용자 결정: **Refresh Token = 구현 완성**(2단계), **D1 = 옵션 유지**(4단계), 실행 범위 **0+1단계**.

### ✅ 0단계 완료

- **E2** `users/[id]` load 14쿼리 → `Promise.all` 병렬화.
- **E7** `wrangler.backup.jsonc`(평문 SMTP 자격)·`wrangler.example copy.jsonc`·빈 `.ignore/` 삭제. 활성 config(`wrangler.jsonc`/`.prod`) 유지.
- **C4** skin sanitizer `FORBIDDEN_TAGS` 에 `style` 추가.
- **B5** `guards.ts` 503 메시지 방언 중립화.
- **A6** discovery `scopes_supported`(+phone)·`claims_supported`(title→실제 발급 클레임 정합).

### ✅ 1단계 완료 (보안 하드닝)

- **C1/C2** LogoutRequest 파서에 DOCTYPE/ENTITY 차단 + `onErrorStopParsing` + IssueInstant skew(±5분), SLO 라우트에 Destination 대조 + 서명 검증 후 request-ID 1회용 소비. `xmlEscape` 제어문자 제거(N-8)도 포함.
- **C3** `/api/totp/verify`·`enroll/confirm` rate-limit(5분/10회) + `counter` 기반 코드 재사용 방지, 등록 스텝 즉시 재사용 차단.
- **C6** `normalizeIpForRateLimit`(IPv6 /64) 도입, rate-limit 12개 호출부를 `ipKey` 로 전환(audit 는 원본 IP 유지). webauthn verify 2곳의 x-forwarded-for fallback 제거(N-12).
- **D1(H-OIDC-5)** `csrf.ts` double-submit 토큰 유틸 신설, admin oidc-clients load/4개 액션/4개 폼에 적용.
- **C5** find-id 메일 발송을 응답 경로에서 분리(waitUntil/fire-and-forget)해 타이밍 열거 차단.
- **C8** reset-password 제출 action rate-limit(15분/10회).
- **C7(M-D)** LDAP 레거시 평문 bindPassword 를 로그인 시 자동 암호화 마이그레이션(bindPasswordEnc 로 전환).

**검증**: `svelte-check` 0 errors / 0 warnings (1191 files), 변경 파일 eslint·prettier 통과. `wrangler types --check` 는 사전 존재하던 `worker-configuration.d.ts` 스테일(D1 브랜치 작업 잔재)로 실패 — 본 변경과 무관하며 사용자가 `wrangler types` 재생성 필요.

### ✅ 2단계 일부 완료 (2026-07-03)

- **A1 Refresh Token 구현** — `src/lib/server/oidc/refresh.ts` 신설(발급·회전·재사용 감지). token 엔드포인트에 `refresh_token` grant 추가:
    - authorization_code 플로우: `offline_access` scope + 클라이언트 `refresh_token` grant 허용 시 refresh token 발급.
    - refresh_token grant: 회전(old revoke + `replacedById` + 새 토큰), 재사용/동시사용 감지 시 family 폐기(RFC 6819), scope 축소 지원, 로그아웃(`revokedAt`)된 세션 거부(단 자연 만료는 offline_access 수명 존중).
    - 전역 무효화: 로그아웃(즉시/SAML SLO 체인)·비밀번호 재설정·관리자 role 변경 시 refresh token 폐기.
    - discovery 에 `refresh_token` grant + `offline_access` scope 광고. README 의 Refresh Token 표기가 실제와 일치하게 됨.
    - 검증: `svelte-check` 0 errors(1192 files), eslint 통과.

- **A4 OIDC introspection/revocation** — `/oidc/introspect`(RFC 7662), `/oidc/revoke`(RFC 7009) 엔드포인트 신설. 공통 클라이언트 인증 헬퍼(`authenticateOidcClient`) 추출. access token(HMAC 검증)·refresh token(해시 조회) 모두 처리, discovery 광고. rate-limit 적용.
- **A3 admin users 목록 페이지네이션·검색** — 커서 페이지네이션(PAGE_SIZE=50, createdAt 기준) + 방언 무관 `lower() LIKE` 검색(email/username/displayName, LIKE 와일드카드 이스케이프). audit 페이지 패턴 재사용. UI 검색창·다음 페이지 링크 + i18n 키.

- **A5 OIDC authorize 파라미터** — `prompt`(none/login), `max_age`, `id_token_hint`, `login_hint` 처리. `prompt=none` 시 상호작용 필요하면 `login_required` 를 redirect_uri 로 반환(무UI), 그 외엔 `forceAuthn` 로그인/재인증. `id_token_hint` 는 서명 검증(만료 무시) 후 sub 대조. `login_hint` 는 로그인 아이디 프리필. `verifyIdToken` 에 `ignoreExpiry` 옵션 추가.

- **A2 SAML Assertion 암호화** — `saml/encrypt.ts` 신설. WebCrypto 로 AES-256-CBC(assertion) + RSA-OAEP-mgf1p SHA-1(세션키) `EncryptedAssertion` 구현(외부 라이브러리 없음). `response.ts` 가 서명 후·Response 서명 전에 암호화(exc-c14n 이라 서명 유효). SSO 라우트가 `sp.encryptAssertion`+`sp.cert` 전달. admin saml-sps UI 에 암호화 토글(cert 없으면 활성 거부). `scripts/verify-saml-encryption.ts` 라운드트립 검증 통과(`bun run verify:saml-encryption`).
    - **주의**: 자체 라운드트립은 통과했으나 실제 SP(Shibboleth/ADFS/SimpleSAMLphp 등) XML-Enc 복호화기와의 상호운용은 별도 테스트 필요.

### ✅ 2단계 완료 — A1/A2/A3/A4/A5 모두 처리됨

### ✅ 3단계 대부분 완료 (2026-07-03)

- **B1 테스트 인프라** — vitest 도입(`vitest.config.ts`, 전용 alias/env 스텁), 핵심 보안 로직 유닛 테스트 6파일 26건(IPv6 정규화·PKCE·TOTP 재사용·SAML 암호화 라운드트립·OIDC scope/redirect·스키마 parity). CI 에 Test 단계 + `test/**` path filter 추가. `bun run test`.
- **E1 스키마 parity 테스트** — 3방언 schema.{sqlite,pg,mysql} 의 테이블·컬럼 집합 동일성을 CI 에서 강제(컬럼 drift 차단; 인덱스 parity 는 범위 밖 명시).
- **E3 의존성 재분류** — 런타임 서버 패키지 7종(@simplewebauthn/server, @peculiar/x509, @xmldom/xmldom, @yrneh_jang/ldapjs, reflect-metadata, xmldsigjs, xpath)을 dependencies 로 이동(adapter-node prod prune 대비).
- **B2 헬스체크** — `/api/health` (liveness + 얕은 DB readiness).
- **B4 루트 에러 페이지** — `src/routes/+error.svelte` (404/403/503 등 정돈된 화면).
- **B3 관측성** — `wrangler.example.jsonc` 에 `observability.enabled` 추가(Workers Logs).

### ⏭️ 남은 단계 (미착수)

(모두 처리됨 — 아래 "최종 처리 현황" 참조)

---

## 최종 처리 현황 (2026-07-04)

### ✅ 3단계 잔여 완료

- **D2 (H-ADMIN-2) 감사 로그 무결성** — `audit_events.hash` 컬럼(3방언) + `recordAuditEvent` 가
  안정 필드를 IDP_SIGNING_KEY_SECRET 으로 HMAC-SHA256 계산·저장(행 단위 MAC). prev-hash 체인이
  아니라 동시 쓰기 fork 문제 없음. 행 삭제 탐지는 Logpush 외부 미러 권장(주석 명시). 유닛 테스트 3건.
  마이그레이션 생성만(drizzle/0018, {pg,mysql,sqlite}/0001) — 적용은 사용자.

### ✅ 4단계 처리

- **E8 D1 정리** — 사용자 결정(옵션 유지)에 맞춰 `app.d.ts` DB optional 타입(f1e6dc6) + 코herent 한
  `wrangler.example.jsonc`(d1 기본, postgres/mysql 대안 명시)로 이미 정합. driver-d1/index.ts d1 분기 유지.
  추가 변경 불필요(혼재는 로컬 gitignore config 영역).
- **E5 CRUD 검증 중복 제거** — loopback 판정을 `$lib/server/validation.ts` 공통 모듈로 추출(3곳 통합).
- **관련 후속 완료** — find-password 타이밍(waitUntil 분리)까지 적용.

### ⏸️ 의도적 보류 (품질·리스크 사유, 별도 작업 권장)

> **⚠️ 이 절의 결론은 이후 전부 뒤집혔습니다** — E4/E5(CRUD 팩토리 + zod), D3(argon2 유지),
> E10(i18n en.json), TOTP TOCTOU 모두 나중에 실제로 처리되었습니다. 문서 상단 정오표 참조.

- **E4/E5 CRUD 팩토리 + zod 전면 도입** — teams/parts/positions/departments 팩토리화는 라우트별 고유
  검증(계층/키회전)과의 경계 설계가 필요하고, admin CRUD 통합 테스트 하네스 없이 10개 라우트를 일괄
  리팩터하면 회귀 위험이 큼. 안전한 슬라이스(검증 중복 제거)만 반영. 팩토리+zod 는 통합 테스트와 함께 별도 PR 권장.
- **D3 (H-DEP-1) argon2 재평가** — 결론: `@node-rs/argon2`(네이티브)는 **Cloudflare Workers 에서 동작 불가**
  → 현 타깃에 부적합. 순수 JS `@hicaru/argon2-pure.js` 는 Workers 호환이나 CPU 비용 큼. WASM 구현(hash-wasm 등)
  이 성능 개선 대안이나, 비밀번호 해싱 교체는 버그 시 전원 락아웃 리스크가 커 Workers WASM 검증 + 점진 롤아웃이
  필요. **현행 유지 권장**, WASM 전환은 별도 검증된 작업으로.
- **E10 i18n en.json + admin 하드코딩 t() 전환** — 엔진은 locale-keyed(멀티로케일 준비됨)이나, 품질 있는 영어
  카탈로그(400+ 문자열)와 SSR locale 결정/전환 배선이 필요한 콘텐츠 작업. 기계번역 부분 적용은 UX 저하라
  보류. 원어민 검수 포함 별도 작업 권장.
- **TOTP enroll TOCTOU** — 완전 해소엔 (userId, type=totp) partial unique 필요하나 MySQL 미지원(신규 dialect
  drift 유발). enroll/confirm rate-limit(C3)로 창(window)을 크게 완화한 상태 유지.
- **OIDC 스코프 확장(별도 메모)**: `groups`/`address`/`organization` — 프로젝트 메모리 `oidc-scope-expansion` 참고.
