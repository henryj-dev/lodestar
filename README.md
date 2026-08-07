# Keystone IDP

Cloudflare Workers 위에서 동작하는 오픈소스 Identity Provider입니다.
OIDC, SAML 2.0, WebAuthn/Passkey, TOTP 2FA, LDAP 연동을 지원하며 멀티테넌트 조직 관리를 포함합니다.

> **개발 단계 안내**: 본 프로젝트는 활발히 개발 중인 학습/실험 성격의 IdP입니다. 프로덕션 도입 전에는 위협 모델에 맞춘 자체 보안 검토를 권장합니다. 보안 관련 알려진 한계는 [보안 참고사항](#보안-참고사항)을 참조하세요.

## 목차

- [주요 기능](#주요-기능)
- [기술 스택](#기술-스택)
- [디렉터리 구조](#디렉터리-구조)
- [엔드포인트 개요](#엔드포인트-개요)
- [시작하기](#시작하기)
- [환경변수](#환경변수)
- [개발 워크플로](#개발-워크플로)
- [데이터베이스 마이그레이션](#데이터베이스-마이그레이션)
- [보안 참고사항](#보안-참고사항)
- [라이선스](#라이선스)

## 주요 기능

| 기능                   | 설명                                                                                                                          |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **OIDC**               | Authorization Code + PKCE, Refresh Token(회전·재사용 감지), UserInfo, JWKS, Introspection, Revocation, End-Session            |
| **SAML 2.0**           | SP-Initiated SSO (HTTP-Redirect · HTTP-POST 바인딩), Assertion 서명·암호화, ForceAuthn, IsPassive, RequestedAuthnContext, SLO |
| **ACR / AMR**          | 인증 방식에 따른 ACR 자동 결정 — SAML Assertion 및 OIDC ID Token에 포함                                                       |
| **WebAuthn / Passkey** | 패스키 등록 및 인증, challenge 1회용 DB 처리, 테넌트 격리                                                                     |
| **TOTP 2FA**           | Google Authenticator 등 호환, 백업 코드 지원                                                                                  |
| **LDAP 연동**          | LDAP 인증 및 JIT 사용자 프로비저닝, 관리자 UI에서 프로바이더 설정                                                             |
| **계정 자가 관리**     | 프로필 편집, 이메일 변경, 비밀번호 재설정/찾기, MFA 등록, Passkey 등록·해제, 활성 세션 조회·철회, 탈퇴(30일 유예)             |
| **서비스 권한**        | 서비스(RP)별 `roles` 배정과 `entitlements` 부여 — OIDC 클레임으로 발행, 변경 시 RP 에 SET 통지                                |
| **서비스 API 토큰**    | 호출자별 스코프 제한 Bearer 토큰 발급·폐기 (관리 콘솔)                                                                        |
| **조직 관리**          | 부서 → 팀 → 파트 계층, 직급/직책, 복수 소속                                                                                   |
| **멀티테넌트**         | 테넌트별 독립 사용자/클라이언트/키 관리                                                                                       |
| **관리자 UI**          | 사용자, 조직(부서·팀·파트·직급), OIDC 클라이언트, SAML SP, LDAP 프로바이더, 서명 키, 서비스 토큰, 로그인 스킨, 감사 로그 CRUD |
| **커스텀 로그인 스킨** | OIDC 클라이언트별 커스텀 CSS/스크립트, R2 또는 S3 호환 캐시로 배포                                                            |
| **감사 로그**          | 로그인, SSO, 토큰 발급 등 주요 이벤트 자동 기록, 행 단위 무결성 MAC, 관리자 UI에서 조회 가능                                  |
| **국제화**             | 메시지 카탈로그 기반 i18n — 한국어·영어(`ko`/`en`) 제공                                                                       |

### ACR / AMR 매핑

세션의 인증 방식(AMR)에 따라 ACR이 자동으로 결정되어 SAML Assertion 및 OIDC ID Token에 포함됩니다.

| 인증 방식            | AMR 값        | ACR 값                                                              |
| -------------------- | ------------- | ------------------------------------------------------------------- |
| 비밀번호만           | `pwd`         | `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport` |
| 비밀번호 + TOTP      | `pwd`, `totp` | `https://refeds.org/profile/mfa`                                    |
| 비밀번호 + 백업 코드 | `pwd`, `swk`  | `https://refeds.org/profile/mfa`                                    |
| WebAuthn / Passkey   | `hwk`         | `https://refeds.org/profile/mfa`                                    |

SAML SP가 `RequestedAuthnContext`로 특정 ACR을 요구하는 경우, 세션 ACR이 해당 수준을 만족하지 않으면 재인증이 강제됩니다. MFA 미설정 등으로 만족 불가 시 `NoAuthnContext` 오류가 ACS URL로 반환됩니다.

### SAML SP별 속성 필터링

각 SP에 `allowedAttributes` 목록을 설정하여 Assertion에 포함할 속성을 제어할 수 있습니다. 미설정 시 `email`, `username`, `displayName`만 기본 포함됩니다. 조직 정보(`department`, `team`, `jobTitle`, `position`)는 SP가 명시적으로 허용한 경우에만 포함됩니다.

## 기술 스택

- **Runtime**: Cloudflare Workers(기본, `nodejs_als`·`nodejs_compat`) 또는 순수 Node 서버(`adapter-node`, `BUILD_TARGET=node`) — [배포 타깃](#배포-타깃-cloudflare-workers-vs-순수-node) 참고
- **Framework**: SvelteKit 2 + Svelte 5 (runes), `@sveltejs/adapter-cloudflare`
- **Database**: Cloudflare D1(SQLite) / libSQL(SQLite) / PostgreSQL / MySQL 중 택1 (Drizzle ORM). PostgreSQL·MySQL 은 Hyperdrive · Workers VPC · `DATABASE_URL` 직결 중 선택 ([DB 방언 선택](#db-방언-선택-d1--sqlite--postgresql--mysql) 참고)
- **Object Storage**: Cloudflare R2 또는 S3 호환(AWS S3·MinIO 등) — 커스텀 로그인 스킨 캐시
- **Styling**: Tailwind CSS 4
- **Crypto**: Web Crypto API (RSA/EC 서명, HKDF 키 파생, AES-256-GCM), `node:crypto` scrypt 비밀번호 해시, `@simplewebauthn/*`, `xmldsigjs`
- **Language / Tooling**: TypeScript, Bun, ESLint, Prettier

## 디렉터리 구조

```
src/
├── hooks.server.ts        # 세션 복원, 보안 헤더, CSRF origin 검사, 테넌트 컨텍스트
├── app.html
├── routes/
│   ├── +error.svelte      # 루트 에러 페이지 (404/403/503 등)
│   ├── (auth)/            # login, signup, logout, mfa, find-id, find-password,
│   │                      #   reset-password, verify-email, accept-invite
│   ├── account/           # profile, mfa, passkeys, sessions, danger-zone,
│   │                      #   confirm-email-change (계정 자가 관리)
│   ├── admin/             # 관리자 UI (users, departments, teams, parts, positions,
│   │                      #   oidc-clients, saml-sps, ldap-providers, signing-keys,
│   │                      #   service-tokens, skins, audit, login)
│   ├── oidc/              # authorize, token, userinfo, jwks, end-session,
│   │                      #   introspect, revoke
│   ├── saml/              # sso, slo, metadata
│   ├── .well-known/       # openid-configuration (Discovery)
│   └── api/               # health, webauthn/*, totp/*, users/lookup, skin-scripts/*
└── lib/
    ├── components/        # 공용 Svelte 컴포넌트
    ├── i18n/              # 메시지 카탈로그 (ko.json, en.json)
    ├── assets/
    └── server/
        ├── auth/          # session, password(scrypt), mfa, totp, webauthn, guards,
        │                  #   csrf, redirect, invite, email-verification, email-change,
        │                  #   trusted-device, service-token, breach-check, bootstrap
        ├── oidc/          # client, grant, pkce, refresh, claims, logout, role-change
        ├── saml/          # sp, metadata, parse-authn-request, response, slo,
        │                  #   verify-xml-signature, encrypt, cert-validity
        ├── ldap/          # auth, client, provision
        ├── access/        # 서비스 role/entitlement 판정
        ├── admin/         # admin CRUD 팩토리 · Zod 스키마 · 사용자 액션
        ├── crypto/        # 서명 키 관리, JWT 발급, 키 회전, HKDF 파생
        ├── audit/         # 감사 이벤트 기록 (행 단위 무결성 MAC)
        ├── org/           # 조직 멤버십 조회
        ├── ratelimit/     # 인증 엔드포인트 레이트 리밋 (저장소 추상화)
        ├── skin/          # 커스텀 로그인 스킨 (resolver, sanitize, storage)
        └── db/            # Drizzle 방언별 스키마 · 드라이버 · GC

drizzle/                   # 마이그레이션 SQL (drizzle-kit generate 산출물, 방언별 하위 디렉터리)
test/                      # vitest 유닛·통합 테스트
docs/                      # 운영 매뉴얼 · 설계/감사 문서
scripts/setup.ts           # 대화형 초기 셋업 스크립트
```

## 엔드포인트 개요

### OIDC (Discovery: `/.well-known/openid-configuration`)

| 경로                                | 설명                                                                                                          |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `/.well-known/openid-configuration` | OIDC Discovery 문서                                                                                           |
| `/oidc/authorize`                   | 인증 요청 (Authorization Code + PKCE). `prompt`(none/login) · `max_age` · `id_token_hint` · `login_hint` 처리 |
| `/oidc/token`                       | 토큰 교환 (Authorization Code, Refresh Token)                                                                 |
| `/oidc/userinfo`                    | UserInfo 엔드포인트                                                                                           |
| `/oidc/introspect`                  | 토큰 인트로스펙션 (RFC 7662)                                                                                  |
| `/oidc/revoke`                      | 토큰 폐기 (RFC 7009)                                                                                          |
| `/oidc/jwks`                        | JSON Web Key Set                                                                                              |
| `/oidc/end-session`                 | RP-Initiated Logout ([구현 노트](docs/oidc-rp-initiated-logout.md))                                           |

#### 발행 클레임 — `groups` 와 `roles` 는 용도가 다릅니다

| 클레임                  | 의미                                        | 용도                  |
| ----------------------- | ------------------------------------------- | --------------------- |
| `groups`                | 조직 소속 (부서 · 팀 · 파트)                | **표시용. 인가 금지** |
| `organization` 계열     | 조직 세부 (부서/직위/직책 등)               | **표시용**            |
| `roles` · `roles_label` | 서비스 역할 (사용자별 서비스 배정)          | **인가용**            |
| `entitlements`          | 서비스 세부 권한 (role 과 직교하는 권한 축) | **인가용**            |

> ⚠️ **`groups` 로 인가하지 마세요.** 이름이 인가용처럼 읽히고 값이 여러 개라 권한 집합처럼 보이지만, 실제 내용은 **인사 구조**입니다. `groups` 로 인가하면 팀 이동이 보안 경계를 움직이고 부서 개편이 권한을 재배정하며, 조직도를 고치는 사람과 권한을 주는 사람을 분리할 수 없게 됩니다. 서비스 권한은 `roles` / `entitlements` 를 쓰세요.

`roles` 는 **사용자당 서비스당 하나**입니다(배열이지만 원소는 항상 1개 — 스키마 제약). `entitlements` 는 같은 배정에 붙는 다중 권한 키로, `roles` 와 달리 개수 제한이 없습니다. `groups`/`organization` 은 해당 scope 를 요청해야 발행되고, `roles`/`entitlements` 는 scope 와 무관하게 서비스 배정이 있으면 발행됩니다(값이 없으면 키 자체가 생략됩니다). 역할·권한 정의와 배정 방법은 [관리자 운영 매뉴얼](docs/ADMIN_GUIDE.md#발행-클레임) 참고.

관리자가 역할/권한을 바꾸면, 해당 클라이언트에 `role_change_uri` 가 등록돼 있을 때 **Security Event Token(SET)** 이 그 URI 로 POST 됩니다. RP 는 세션을 끊지 않고 권한만 갱신하므로 재로그인 없이 다음 요청부터 반영됩니다(fire-and-forget, 재시도 없음 — RP 는 `txn` 순서 표식으로 늦게 도착한 스냅샷을 버려야 합니다). 계약 상세는 `src/lib/server/oidc/role-change.ts` 주석 참고.

SAML 도 같은 값을 내보냅니다 — Assertion 의 **`Entitlements` 속성**(목록이므로 하나의 `<saml:Attribute>` 안에 여러 `<saml:AttributeValue>`)입니다. 단, `Role`·`RoleLabel` 과 마찬가지로 SP 의 **허용 속성 목록(`allowedAttributes`)에 `Entitlements` 를 넣어야** 실제로 전달됩니다.

`sub` 클레임은 `users.id` 와 같은 값이며, 아래 [Service-to-Service TOTP API](#service-to-service-totp-api-dispatcher_service_token-필요) 의 `userId` 로 그대로 사용할 수 있습니다.

### SAML 2.0

| 경로             | 설명                                 |
| ---------------- | ------------------------------------ |
| `/saml/metadata` | IdP 메타데이터 XML                   |
| `/saml/sso`      | SP-Initiated SSO (AuthnRequest 처리) |
| `/saml/slo`      | Single Logout (체인 SLO 지원)        |

### WebAuthn / 기타 API

| 경로                                 | 설명                                    |
| ------------------------------------ | --------------------------------------- |
| `/api/health`                        | 헬스체크 (liveness + 얕은 DB readiness) |
| `/api/webauthn/register/options`     | Passkey 등록 challenge 발급             |
| `/api/webauthn/register/verify`      | Passkey 등록 attestation 검증           |
| `/api/webauthn/authenticate/options` | Passkey 인증 challenge 발급             |
| `/api/webauthn/authenticate/verify`  | Passkey 인증 assertion 검증             |
| `/api/skin-scripts/*`                | OIDC 클라이언트별 커스텀 스킨 스크립트  |

### Service-to-Service TOTP API (`DISPATCHER_SERVICE_TOKEN` 필요)

신뢰된 서비스가 사용자 대신 TOTP 등록 / 검증을 위탁하기 위한 API. 모든 요청은
`Authorization: Bearer <서비스 토큰>` 헤더가 필요합니다.

토큰은 **관리 콘솔 → 서비스 토큰**(`/admin/service-tokens`)에서 호출자별로 발급하고, 필요한
스코프만 줍니다. 평문은 발급 직후 한 번만 표시되며 DB 에는 해시만 저장됩니다.

| 스코프         | 여는 엔드포인트                                      |
| -------------- | ---------------------------------------------------- |
| `totp.verify`  | `/api/totp/verify`                                   |
| `totp.status`  | `/api/totp/status`                                   |
| `totp.enroll`  | `/api/totp/enroll/init` · `/api/totp/enroll/confirm` |
| `users.lookup` | `/api/users/lookup`                                  |

> `DISPATCHER_SERVICE_TOKEN`(환경변수)은 **모든 스코프**를 가진 레거시 경로입니다. 기존 호출자
> 무중단을 위해 남아 있으며, 호출자를 전부 발급 토큰으로 옮긴 뒤 제거하세요.

| 경로                       | 메서드 | 설명                                                          |
| -------------------------- | ------ | ------------------------------------------------------------- |
| `/api/totp/enroll/init`    | POST   | `{userId}` → `{secret, otpAuthUri, username}` (stateless)     |
| `/api/totp/enroll/confirm` | POST   | `{userId, secret, code}` → 검증 + 영구 저장 + `{backupCodes}` |
| `/api/totp/verify`         | POST   | `{userId, code}` → step-up 검증 + `{ok, verifiedAt}`          |
| `/api/totp/status`         | GET    | `?userId=...` → `{enrolled, backupCodeCount, lastUsedAt}`     |

## 시작하기

### 사전 요구사항

- [Bun](https://bun.sh) 1.x
- [Cloudflare 계정](https://dash.cloudflare.com) (D1, R2, Workers 활성화)
- Wrangler CLI (`bun add -g wrangler`)

### 설치 및 셋업

```bash
git clone https://github.com/mack-erel/KeyStone.git
cd KeyStone
bun install
bun run setup
```

`bun run setup`은 아래 과정을 대화형으로 안내합니다. DB 방언은 `--dialect`(`d1`(기본) | `postgres` | `mysql` | `sqlite`) 또는 `DB_DIALECT` 환경변수로 선택하며, 방언에 따라 3~5단계가 갈라집니다:

1. **설정 파일 생성** — `wrangler.example.jsonc` → `wrangler.jsonc`, `.env.example` → `.env`
2. **DB 방언 결정** — `--dialect` > `DB_DIALECT` env > `.env` > 프롬프트
3. **DB 설정**
    - `d1`: wrangler 로그인 확인 후 D1 새로 생성 또는 기존 DB 선택 (프리뷰 DB 선택적), DB ID·계정 ID를 `wrangler.jsonc`/`.env`에 자동 기입
    - `postgres`/`mysql`/`sqlite`: `DATABASE_URL` 입력(또는 기존 값 재사용), postgres/mysql 은 Hyperdrive 구성 ID 입력 시 `wrangler.jsonc` 의 `HYPERDRIVE` 바인딩 자동 설정
4. **마이그레이션** — 방언별 `db:generate*` 실행 후 스키마 적용 (D1 은 충돌 테이블 감지 및 처리 포함)
5. **초기 관리자 계정 생성** — 조직명, 관리자 계정 정보, Issuer URL 입력 후 DB에 시드 (비밀번호 미입력 시 자동 생성)
6. **서명 키** — `IDP_SIGNING_KEY_SECRET` 자동 생성 또는 직접 입력 후 `.env`에 저장

```bash
# 예: PostgreSQL 로 셋업
bun run setup -- --dialect postgres --database-url "postgres://user:pass@host:5432/db" --hyperdrive-id <id>
```

> R2 버킷(`keystone-skin-cache`)은 커스텀 로그인 스킨 기능을 사용할 때 필요합니다. 사용하지 않는다면 `wrangler.jsonc`의 `r2_buckets` 항목을 주석 처리해도 됩니다.

셋업 완료 후 로컬 개발 서버를 시작합니다:

```bash
bun run dev
```

### 프로덕션 배포

```bash
bun run deploy
```

배포 전 Wrangler Secret으로 민감한 값을 설정합니다:

```bash
wrangler secret put IDP_SIGNING_KEY_SECRET
```

> **참고**: 로컬 개발에서는 `.env`에 평문으로 저장해도 무방하지만, 프로덕션에서는 반드시 Secret으로 관리하세요.

## 환경변수

전체 목록과 상세 주석은 [`.env.example`](.env.example) 을 참고하세요. 아래는 자주 쓰는 값입니다.

| 변수                                | 필수 | 설명                                                                                                                                                  |
| ----------------------------------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `IDP_ISSUER_URL`                    | ✅   | OIDC/SAML 발급자 URL (배포 도메인과 일치). **프로덕션 필수** — 미설정 시 요청 초기 503(fail-closed). dev 에서만 요청 origin 자동 대체                 |
| `IDP_SIGNING_KEY_SECRET`            | ✅   | 서명 키 암호화 KEK (프로덕션은 반드시 Secret). **프로덕션 필수** — 미설정 시 요청 초기에 오류로 차단(fail-fast)                                       |
| `IDP_SIGNING_KEY_SECRET_PREVIOUS`   | 선택 | 마스터 시크릿 **무중단 회전** 중에만 이전 값을 병기. 복호/검증이 current→previous 로 폴백 ([회전 절차](docs/SECRET_ROTATION.md))                      |
| `BUILD_TARGET`                      | 선택 | `cloudflare`(기본) \| `node` — 어댑터 선택. **빌드 시점** 값                                                                                          |
| `DB_DIALECT`                        | 선택 | `d1`(기본) \| `sqlite` \| `postgres` \| `mysql`. **빌드·타입체크·마이그레이션 생성 시점에도** 참조됨                                                  |
| `DATABASE_URL`                      | 조건 | postgres/mysql/sqlite 연결 문자열. Cloudflare 에서 `HYPERDRIVE` 바인딩이 있으면 그쪽이 우선                                                           |
| `DATABASE_AUTH_TOKEN`               | 선택 | Turso 등 원격 libSQL 인증 토큰 (`sqlite` + 원격일 때만)                                                                                               |
| `DISPATCHER_SERVICE_TOKEN`          | 선택 | **전 스코프** service API Bearer 토큰(레거시). 호출자별 토큰은 관리 콘솔 → 서비스 토큰에서 발급하세요. 이 값도 없고 발급된 토큰도 없으면 해당 API 503 |
| `IDP_DEFAULT_TENANT_NAME`           | 선택 | 기본 테넌트 이름 (기본: `My Organization`)                                                                                                            |
| `IDP_ENFORCE_SP_CERT_VALIDITY`      | 선택 | SAML SP 인증서 유효기간 강제 검증. **기본 on** — `"false"` 로만 완화                                                                                  |
| `PASSWORD_BREACH_CHECK`             | 선택 | 유출 비밀번호(HIBP k-anonymity) 스크리닝. 기본 off(opt-in), API 오류는 fail-open                                                                      |
| `SMTP_HOSTNAME` 외 `SMTP_*`         | 선택 | 메일 발송(비밀번호 찾기·초대·이메일 인증·보안 알림). 미설정 시 해당 메일은 skip                                                                       |
| `S3_ENDPOINT` 외 `S3_*`             | 선택 | 스킨 캐시용 S3 호환 스토리지 (R2 바인딩이 없을 때 폴백)                                                                                               |
| `CLOUDFLARE_ACCOUNT_ID`             | 선택 | Cloudflare 계정 ID (마이그레이션 스크립트에서 사용)                                                                                                   |
| `CLOUDFLARE_D1_DATABASE_ID`         | 선택 | D1 데이터베이스 ID (마이그레이션 스크립트에서 사용)                                                                                                   |
| `CLOUDFLARE_D1_PREVIEW_DATABASE_ID` | 선택 | 프리뷰용 D1 데이터베이스 ID                                                                                                                           |
| `CLOUDFLARE_D1_TOKEN`               | 선택 | D1 API 토큰 (`db:migrate` 스크립트에서 사용)                                                                                                          |

> **참고**: 초기 관리자 계정은 `bun run setup` 이 생성합니다. 수동/CI 시드가 필요하면 `IDP_BOOTSTRAP_ADMIN_USERNAME` / `IDP_BOOTSTRAP_ADMIN_EMAIL` / `IDP_BOOTSTRAP_ADMIN_PASSWORD` (+선택 `IDP_BOOTSTRAP_ADMIN_NAME`) 를 설정하고 `bun run db:seed`(방언별: `db:seed:pg` 등)를 실행하세요. 비대화 환경에서는 `SEED_RESET=0|1` 로 초기화 여부를 지정합니다.

### Cloudflare 바인딩 (`wrangler.jsonc`)

| 바인딩       | 종류       | 용도                                                       |
| ------------ | ---------- | ---------------------------------------------------------- |
| `DB`         | D1         | 메인 데이터베이스 (`DB_DIALECT=d1` 일 때)                  |
| `HYPERDRIVE` | Hyperdrive | PostgreSQL/MySQL 연결 (`DB_DIALECT=postgres\|mysql` 일 때) |
| `SKIN_CACHE` | R2         | 커스텀 로그인 스킨 캐시                                    |
| `ASSETS`     | 정적       | SvelteKit 빌드 산출물 (`.svelte-kit/cloudflare`)           |

## 개발 워크플로

| 명령                         | 설명                                               |
| ---------------------------- | -------------------------------------------------- |
| `bun run dev`                | Vite 개발 서버 실행                                |
| `bun run build`              | 프로덕션 빌드                                      |
| `bun run preview`            | Wrangler로 빌드 산출물 미리보기 (`localhost:4173`) |
| `bun run check`              | `wrangler types` + `svelte-check` 타입 검사        |
| `bun run lint`               | Prettier + ESLint 검사                             |
| `bun run format`             | Prettier 자동 포맷                                 |
| `bun run test`               | vitest 실행 (`test:watch` / `test:coverage`)       |
| `bun run gen`                | Wrangler 환경 타입 재생성                          |
| `bun run db:generate`        | Drizzle 마이그레이션 SQL 생성 (D1)                 |
| `bun run db:generate:sqlite` | Drizzle 마이그레이션 SQL 생성 (libSQL/SQLite)      |
| `bun run db:generate:pg`     | Drizzle 마이그레이션 SQL 생성 (PostgreSQL)         |
| `bun run db:generate:mysql`  | Drizzle 마이그레이션 SQL 생성 (MySQL)              |
| `bun run db:migrate`         | 마이그레이션 적용 + seed 마이그레이션 (D1)         |
| `bun run db:migrate:pg`      | 마이그레이션 적용 + seed 마이그레이션 (PostgreSQL) |
| `bun run db:seed`            | 기본 데이터 시드 — 테넌트/관리자/서비스 role (D1)  |
| `bun run db:seed:pg`         | 기본 데이터 시드 (PostgreSQL)                      |
| `bun run db:studio`          | Drizzle Studio 실행 (스키마/데이터 GUI)            |
| `bun run deploy`             | Cloudflare Workers 배포                            |

> `db:migrate` / `db:seed` / `db:push` / `db:studio` 는 `:pg` / `:mysql` / `:sqlite` 접미사로 방언별 실행이 가능합니다. postgres/mysql/sqlite 는 `DATABASE_URL`, D1 은 `CLOUDFLARE_*` 환경변수를 사용합니다. `scripts/seed.ts` 와 `scripts/seed-migrate.ts` 는 방언 무관(공용 헬퍼 `scripts/lib/db.ts`)이며, D1 은 REST API 로 접근합니다.

## DB 방언 선택 (d1 / sqlite / postgresql / mysql)

D1(SQLite)·libSQL(SQLite)·PostgreSQL·MySQL 을 지원하며, **배포 단위로 하나만** 사용합니다. D1 은 편의성이 높지만 지연이 큰 편이라, 낮은 지연이 필요하면 Cloudflare Hyperdrive 로 PostgreSQL/MySQL 에 연결하거나 자체 DB 에 직결할 수 있습니다.

방언은 `DB_DIALECT` 환경변수로 선택합니다 (`d1`(기본) | `sqlite` | `postgres` | `mysql`). 이 값은 **런타임뿐 아니라 빌드·타입체크·마이그레이션 생성 시점에도** 참조되어 스키마·드라이버를 결정합니다.

| 방언       | 드라이버         | 연결 대상                                    |
| ---------- | ---------------- | -------------------------------------------- |
| `d1`       | `drizzle-orm/d1` | Cloudflare D1 (Workers 전용 바인딩)          |
| `sqlite`   | libSQL           | 로컬 파일(`file:`) 또는 Turso (순수 Node 등) |
| `postgres` | postgres-js      | Hyperdrive 또는 `DATABASE_URL` 직결          |
| `mysql`    | mysql2           | Hyperdrive 또는 `DATABASE_URL` 직결          |

```bash
# PostgreSQL 로 빌드·배포
DB_DIALECT=postgres bun run build
DB_DIALECT=postgres bun run deploy   # 또는 wrangler deploy

# MySQL 로 빌드·배포
DB_DIALECT=mysql bun run build

# 로컬 SQLite 파일(libSQL) 로 Node 구동
BUILD_TARGET=node DB_DIALECT=sqlite DATABASE_URL="file:./keystone.db" bun run build && node build
```

동작 방식:

- 스키마는 방언별로 분리되어 있습니다: `schema.sqlite.ts`(d1·sqlite 공용) / `schema.pg.ts` / `schema.mysql.ts`. 세 스키마는 테이블·컬럼·인덱스명과 JS 추론 타입이 동일하게 유지되며, 배럴 `schema.ts` 가 `DB_DIALECT` 에 맞는 파일로 해석됩니다.
- `src/lib/server/db/index.ts` 의 `getDb()` 가 방언에 맞는 드라이버(d1 / libSQL / postgres-js / mysql2)를 선택합니다. 빌드 시 활성 방언의 드라이버만 번들에 포함됩니다.
- **연결 문자열 우선순위**: `sqlite` 는 `DATABASE_URL`/`SQLITE_URL`(`file:` 스킴 없으면 로컬 파일로 간주). `postgres/mysql` 은 Cloudflare 에서 `HYPERDRIVE` 바인딩 → `DATABASE_URL`(var/secret), 순수 Node 에서 `DATABASE_URL`.
- **사설망 Postgres/MySQL — Workers VPC**: `wrangler.jsonc` 에 `vpc_networks` 로 **`VPC`** 바인딩(이름 고정 — 코드가 `platform.env.VPC` 를 참조)을 두면, 드라이버의 TCP 연결이 Cloudflare Tunnel 을 통해 사설 IP 로 나갑니다. 이 경우 접속 정보는 `DATABASE_URL` 을 **secret 으로** 주입합니다(공인 노출 없이 사설망 DB 직결).

```bash
# (Cloudflare) Hyperdrive 구성 생성 (binding 이름은 반드시 HYPERDRIVE)
wrangler hyperdrive create keystone-pg    --connection-string="postgres://user:pass@host:5432/db"
wrangler hyperdrive create keystone-mysql --connection-string="mysql://user:pass@host:3306/db"
# → 출력된 id 를 wrangler.jsonc 의 hyperdrive[].id 에 채우고 주석 해제
#   (또는 bun run setup -- --dialect postgres --hyperdrive-id <id> 로 자동 설정)
# (Hyperdrive 없이 직결하려면 DATABASE_URL 을 var/secret 으로 설정)

# 스키마 적용 + 시드 (PostgreSQL 예시 — DATABASE_URL 사용)
bun run db:generate:pg && bun run db:migrate:pg
bun run db:seed:pg
```

### 배포 타깃: Cloudflare Workers vs 순수 Node

`BUILD_TARGET`(`cloudflare`(기본) | `node`)으로 어댑터를 전환합니다. `node` 는 `@sveltejs/adapter-node` 로 빌드되어 Cloudflare 없이 순수 Node 서버로 구동됩니다. Node 에는 `platform` 바인딩이 없으므로 **PostgreSQL/MySQL/sqlite(libSQL)** 를 사용하며(D1 은 Workers 전용), 연결은 `DATABASE_URL`, 설정값은 `process.env` 로 읽습니다.

```bash
# PostgreSQL + 순수 Node 로 빌드·구동
export BUILD_TARGET=node DB_DIALECT=postgres
export DATABASE_URL="postgres://user:pass@host:5432/db"
# 필요한 설정도 환경변수로: IDP_SIGNING_KEY_SECRET, IDP_ISSUER_URL, IDP_DEFAULT_TENANT_NAME ...
bun run build
node build            # adapter-node 산출물 (기본 PORT=3000)
```

> **참고**: MySQL 은 `UPDATE ... RETURNING` 과 partial(부분) unique index 를 지원하지 않습니다. 해당 로직(인가 코드/WebAuthn challenge 소진, signing key 회전, rate limit upsert)은 방언별로 분기되어 MySQL 에서는 `affectedRows` 판정·재조회와 트랜잭션으로 동등하게 동작합니다.

### 스킨 캐시 스토리지: R2 또는 S3 호환

커스텀 로그인 스킨 캐시는 다음 우선순위로 스토리지를 선택합니다 (미설정 시 캐시 없이 매번 원본 fetch — 정상 동작).

1. **Cloudflare R2 바인딩**(`SKIN_CACHE`) 이 있으면 R2 사용.
2. 없고 **S3 호환 설정**(`S3_ENDPOINT`/`S3_BUCKET`/`S3_ACCESS_KEY_ID`/`S3_SECRET_ACCESS_KEY`)이 있으면 S3 호환 스토리지 사용.

R2 자체가 S3 호환이므로 AWS S3·MinIO·Ceph 는 물론 R2 의 S3 endpoint 도 그대로 쓸 수 있습니다. 서명은 `aws4fetch` 로 하며 Workers/Node 양쪽에서 동작합니다. path-style/virtual-host 는 `S3_FORCE_PATH_STYLE`(기본 `true`, MinIO/R2 권장)로 제어합니다. 자세한 변수는 [`.env.example`](.env.example) 참고.

## 데이터베이스 마이그레이션

스키마 변경 → 마이그레이션 생성 → 적용의 흐름은 다음과 같습니다.

```bash
# 1. 사용하는 방언의 스키마 파일 수정
#    - D1 / sqlite → src/lib/server/db/schema.sqlite.ts (공용)
#    - PostgreSQL  → src/lib/server/db/schema.pg.ts
#    - MySQL       → src/lib/server/db/schema.mysql.ts
#    (세 스키마의 구조/타입은 동일하게 유지할 것)

# 2. SQL 생성 (사용하는 방언에 맞게)
bun run db:generate          # D1         → drizzle/*.sql
bun run db:generate:sqlite   # libSQL     → drizzle/sqlite/*.sql (DDL 은 D1 과 동일)
bun run db:generate:pg       # PostgreSQL → drizzle/pg/*.sql
bun run db:generate:mysql    # MySQL      → drizzle/mysql/*.sql

# 3. 생성된 SQL 파일 검토

# 4. 원격 DB에 적용 (사용자가 직접 실행)
bun run db:migrate          # D1 프로덕션
bun run db:migrate:preview  # D1 프리뷰
# PostgreSQL/MySQL 은 DATABASE_URL 설정 후 drizzle-kit migrate 로 적용
```

> ⚠️ 원격 D1에 대한 마이그레이션 적용은 되돌리기 어려우므로, 자동화된 스크립트나 에이전트가 임의로 실행하지 않도록 운영 정책에 포함시키는 것을 권장합니다.

## 보안 참고사항

### 비밀번호 해싱

신규 비밀번호는 **scrypt** (`node:crypto` 네이티브, N=2^15·r=8·p=3 ≒ 32 MiB — OWASP 권고 조합)로 해싱됩니다. Workers·Node·Bun 모두에서 동일하게 동작합니다.

과거 **argon2id**(`@hicaru/argon2-pure.js`)와 **PBKDF2-SHA256** 으로 저장된 레거시 해시는 검증은 계속 지원되며, **로그인 성공 시 자동으로 scrypt 로 재해싱**됩니다. argon2id 에서 전환한 이유는 순수 JS 구현이 verify 1회에 약 4.4초의 CPU 를 써서 Workers 요청 지연의 주원인이었기 때문입니다(자세한 판단 근거는 `src/lib/server/auth/password.ts` 상단 주석).

### 서명 키

OIDC ID Token 및 SAML Response 서명에 사용되는 RSA 키는 `IDP_SIGNING_KEY_SECRET`으로 암호화되어 DB에 저장됩니다. 이 시크릿이 유출되면 모든 서명 키가 복호화될 수 있으므로 반드시 강한 랜덤값(`openssl rand -base64 32`)을 사용하고 정기적으로 교체하세요. 서명 키 회전은 관리자 UI(`/admin/signing-keys`)에서 수행합니다.

`IDP_SIGNING_KEY_SECRET` **자체**의 회전은 별개 절차입니다 — `IDP_SIGNING_KEY_SECRET_PREVIOUS` 병기로 무중단 전환한 뒤 재암호화 배치를 돌립니다. [docs/SECRET_ROTATION.md](docs/SECRET_ROTATION.md) 를 따르세요.

### WebAuthn challenge

WebAuthn 등록·인증 challenge는 DB에 1회용으로 저장되며, 소진 즉시 삭제됩니다. challenge는 테넌트 ID로 격리되어 다른 테넌트의 challenge를 재사용할 수 없습니다.

### LDAP 계정 연결 정책

LDAP 인증 성공 시, 동일 이메일의 기존 로컬 계정이 있는 경우 **자동 연결하지 않습니다.** LDAP 프로바이더가 이메일을 조작해 기존 관리자 계정을 탈취하는 것을 방지하기 위함입니다. 기존 로컬 계정과의 연결은 관리자가 직접 수행해야 합니다.

### 보안 헤더

`hooks.server.ts`에서 모든 응답에 다음 헤더를 적용합니다.

- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security` (HSTS)
- `Permissions-Policy` (camera/microphone/geolocation/payment 비활성)
- 해시 기반 `Content-Security-Policy`

### 부트스트랩 관리자

초기 관리자 계정은 `bun run setup` 실행 시 활성 DB(방언 무관)에 직접 삽입됩니다. 셋업 완료 후 가능한 빨리 비밀번호를 변경하고 MFA를 설정하는 것을 권장합니다. 관리자는 TOTP 미등록 시 콘솔 로그인이 차단됩니다.

### 감사 로그 무결성

`audit_events` 의 각 행에는 안정 필드에 대한 HMAC-SHA256 MAC(`hash`)이 저장되어 행 단위 위변조를 탐지할 수 있습니다. prev-hash 체인이 아니라 동시 쓰기 fork 문제가 없는 대신, **행 삭제 자체는 탐지하지 못합니다** — 필요하면 Logpush 등 외부 미러를 함께 쓰세요.

## 라이선스

[MIT](LICENSE)
