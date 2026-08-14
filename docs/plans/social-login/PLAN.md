# 외부 소셜 로그인(Naver / Kakao / GitHub / Microsoft) 도입 계획

작성일: 2026-08-14
**상태: P0~P8 구현 완료** (LDAP 은 결정에 따라 `provisioningMode` 기본값 `jit` 으로 현행 유지)

## 구현 결과 요약

| 단계 | 상태 | 비고 |
| --- | --- | --- |
| P0 스키마 | ✅ | `slug` 컬럼 4방언 마이그레이션 생성 (**적용은 사용자가 직접 실행**) |
| P1 코어 | ✅ | `oauth/{types,registry,client,http,jwt,state,provision,provider-store}.ts` |
| P2 라우트 | ✅ | `/auth/oauth/[slug]/{start,callback}` |
| P3 연합 회원가입 | ✅ | `auth/{pending-link,federated-signup,signed-token}.ts` + `/signup?federated=1` |
| P4 관리자 UI | ✅ | `/admin/social-providers` |
| P5 어댑터 | ✅ | naver / kakao / github / microsoft / google / 범용 oidc |
| P6 LDAP | ⏸️ 의도적 미적용 | 기본값 `jit` 유지 — 기존 동작 무회귀. `signup_form` 배선은 미구현 |
| P7 셀프서비스 | ✅ | `/account/connections` (연결·해제 + 마지막 수단 보호) |
| P8 마감 | ✅ | i18n(ko/en), 스킨 placeholder, ADMIN_GUIDE, lint/check/test/build 통과 |

구현 중 계획에 없던 추가 작업 2건:

1. **`amr` 정정** — MFA 라우트가 1차 요소를 `pwd` 로 하드코딩하고 있어, 연합 로그인이 MFA 를 타면
   비밀번호를 쓴 적 없는 사용자에게 `pwd` 가 붙어 downstream RP 에 거짓 정보가 나갔다.
   `MfaPendingClaims.firstFactor` 를 추가해 실제 수단을 전달하고, `amrToAcr` 이 `fed + totp` 를
   MFA 로 인정하도록 고쳤다(구버전 토큰은 `pwd` 로 폴백 — 무회귀).
2. **로그인 상태 연결 경로** — 콜백이 세션을 보지 않아 `/account/connections` 의 "연결하기" 가
   `link_required` 로 튕겼다. `linkIdentityToUser` 를 추가해 로그인 상태에서는 이메일 일치를
   따지지 않고 현재 계정에 연결한다.

테스트: 367 → **422 통과**(신규 55개).

---

## 0. 한 줄 요약

KeyStone 은 지금 **downstream IdP**(OIDC/SAML 을 남에게 제공)이면서 upstream 연합은 LDAP 하나뿐이다.
여기에 **브라우저 리다이렉트 기반 upstream OAuth2/OIDC 연합**을 추가한다.
`identity_providers` / `identities` 스키마가 이미 이 용도로 설계돼 있어 스키마 변경은 컬럼 1개(`slug`)로 끝난다.

---

## 1. 현재 구조 파악 결과

| 항목 | 현황 | 근거 |
| --- | --- | --- |
| 프로바이더 설정 테이블 | `identity_providers` 존재. `kind` enum 에 `oidc`/`oauth2` 가 **이미 포함** | `schema.sqlite.ts:163-189` |
| 외부 계정 연결 테이블 | `identities` 존재. `(tenantId, provider, subject)` unique | `schema.sqlite.ts:136-158` |
| provider 문자열 컨벤션 | `local`, `ldap:<providerId>` | `ldap/provision.ts:17`, `signup/+page.server.ts:115` |
| 연합 선례 | LDAP: admin CRUD + JIT provision + login action 인라인 호출 | `admin/ldap-providers/+page.server.ts`, `ldap/provision.ts` |
| 시크릿 저장 | DB 에 `encryptSecret(..., "idp-ldap-bind-password-v1")` 로 암호화, 키는 `IDP_SIGNING_KEY_SECRET` | `crypto/keys.ts:328`, `admin/ldap-providers/+page.server.ts:59-71` |
| 로그인 가능 판정 | `credentials` **또는** `identities` 존재 시 로그인 가능으로 계산 | `guards.ts:56-70` |
| 단기 상태 보관 선례 | (a) 서명 JWT 쿠키 = `MFA_PENDING_COOKIE`, (b) DB 테이블 = `webauthn_challenges` / `saml_authn_request_ids` | `auth/mfa.ts`, `schema.sqlite.ts:941,965` |
| CSRF | `hooks.server.ts` 에서 **비-GET 요청만** Origin/Referer 검사. `CSRF_PROTECTED` 정규식 목록 방식 | `hooks.server.ts:15-90` |
| CSP | `mode: "hash"`, `img-src: ['self','data:']` — **외부 도메인 로고 이미지는 차단됨** | `svelte.config.js:43-62` |
| 스키마 방언 | sqlite/pg/mysql 3벌 수동 미러링 + `schema-parity.test.ts` 가 CI 에서 drift 검출 | `test/unit/schema-parity.test.ts` |
| 마이그레이션 정책 | `db:generate` 까지만. 실제 적용은 **사용자가 직접 실행** | `CLAUDE.md` |

### 핵심 갭

1. OAuth2 authorization-code 왕복(리다이렉트 → 콜백)을 처리하는 라우트가 없다.
2. state / nonce / PKCE verifier 를 보관할 자리가 없다.
3. 로그인 페이지에 소셜 버튼 슬롯이 없다(커스텀 스킨 placeholder 포함).
4. 사용자가 스스로 계정을 연결/해제할 `/account/connections` 가 없다.

---

## 2. 설계 결정

### 2.1 프로바이더를 두 부류로 나눈다

| kind | 대상 | 구현 |
| --- | --- | --- |
| `oidc` | Microsoft(Entra ID), Google, Kakao(OIDC 모드) | **discovery 기반 범용 어댑터** 1개. `discoveryUrl` 만 있으면 동작 |
| `oauth2` | Naver, GitHub, Kakao(레거시 모드) | 프로바이더별 **profile 어댑터**(엔드포인트 + 응답 정규화 함수) |

`kind` enum 에 두 값 모두 이미 있으므로 **enum 변경 불필요**.

### 2.2 스키마 변경은 `slug` 컬럼 하나

콜백 URL 이 `/auth/oauth/{slug}/callback` 형태여야 네이버/카카오 콘솔에 등록하는 Redirect URI 가 안정적이다.
UUID(`id`)를 쓰면 환경마다 URI 가 달라져 운영이 괴로워진다.

```
identity_providers.slug  TEXT NULL           // 예: "naver", "kakao", "github", "entra"
  + uniqueIndex idp_tenant_slug_uidx (tenant_id, slug)
```

- nullable 로 추가 → 기존 LDAP 행 무영향, 3방언 모두 동일하게 nullable.
- 나머지 표시용 메타(`buttonLabel`, `iconKey`, `displayOrder`, `allowSignup`, `autoLinkVerifiedEmail`, `providerType`)는 전부 **`configJson` 안에** 넣는다 → 추가 마이그레이션 0.

> 마이그레이션은 `bun run db:generate:all` 까지만 수행하고 SQL 파일을 커밋한다. `db:migrate` 계열은 사용자가 직접 실행한다.

### 2.3 state / nonce / PKCE 는 서명 쿠키

`MFA_PENDING_COOKIE` 와 동일한 패턴(=`signJwt` + `IDP_SIGNING_KEY_SECRET`, httpOnly / SameSite=Lax / Secure / maxAge 600s).

- 담는 값: `state`(랜덤 32B), `nonce`, `codeVerifier`, `slug`, `redirectTo`, `skinHint`, `iat`.
- 콜백에서 쿠키의 `state` 와 쿼리 `state` 를 **상수시간 비교**하고, 검증 직후 쿠키를 즉시 삭제(단일 사용).
- 장점: 새 테이블/GC 불필요, Workers 친화적. 단점: 서버측 재사용 차단이 쿠키 삭제에 의존 → 10분 TTL + 단일 사용으로 충분.
- (대안: `webauthn_challenges` 처럼 DB 테이블 + `gc.ts` 등록. 재생 공격 방어가 더 엄밀하지만 마이그레이션·GC 비용 발생. 1차는 쿠키로 가고, 감사 요구가 생기면 전환.)

### 2.4 계정 연결 정책 — 여기가 보안의 핵심

`ldap/provision.ts:59-70` 이 이미 "동일 이메일 자동 연결 금지(계정 탈취 방지)" 원칙을 세워뒀다. **소셜에도 동일 원칙을 적용한다.**

콜백 후 분기:

1. `identities(tenant, "oauth:<slug>", subject)` 존재 → 해당 유저로 로그인. `lastLoginAt` 갱신.
2. 없고, 프로바이더 이메일이 **기존 로컬 유저와 일치** →
   - 기본: **자동 연결 거부**. "이미 계정이 있습니다. 기존 방법으로 로그인한 뒤 계정 설정에서 연결하세요" 로 안내.
   - 예외: 프로바이더가 **이메일 검증됨**을 명시하고 + admin 이 해당 프로바이더에 `autoLinkVerifiedEmail=true` 를 켰을 때만 자동 연결.
3. 없고 매칭 유저도 없음 → **§2.8 연합 회원가입 플로우**로 진행 (프로바이더별 `provisioningMode` 에 따라 무음 JIT 또는 가입 폼).
4. 대상 유저가 `disabled`/`locked` → 로그인 거부. `deletion_pending` → 기존 복구 플로우와 동일 취급.

### 2.8 매칭 계정이 없을 때 — 연합 회원가입 플로우

**결정: 무음 JIT 대신 외부 프로필로 프리필된 가입 폼을 거치게 한다.** 단, 프로바이더별 토글로 무음 JIT 도 남긴다.

```
identity_providers.configJson.provisioningMode: "signup_form" | "jit" | "deny"
```

| 프로바이더 | 기본값 | 이유 |
| --- | --- | --- |
| 소셜(`oauth2`/`oidc`) | `signup_form` | 이메일이 없거나 미검증일 수 있고, username 규칙(`^[a-z0-9_]{3,32}$`)을 외부 닉네임이 만족한다는 보장이 없다 |
| LDAP | `jit` (**현행 유지**) | 기업 디렉터리는 admin 이 관리하는 신뢰 소스이고, 엔터프라이즈 SSO 의 기대는 투명한 프로비저닝이다. 기존 배포에 회귀를 만들지 않는다 |

#### 2.8.1 신뢰 경계 — 가장 중요한 부분

프리필 값을 **폼 hidden 필드로 왕복시키면 안 된다.** 공격자가 자기 네이버 계정으로 로그인한 뒤 email 을 `admin@회사.com` 으로 바꿔 제출하면, 그 이메일을 가진 계정을 손에 넣는다.

→ 외부 프로필은 **서명된 쿠키**로만 운반한다. `MFA_PENDING_COOKIE` 와 동일한 패턴(`signJwt` / `IDP_SIGNING_KEY_SECRET`).

```ts
// src/lib/server/auth/pending-link.ts
export const PENDING_LINK_COOKIE = "idp_pending_link";   // httpOnly, SameSite=Lax, Secure, 15분

export interface PendingLinkClaims {
    tenantId: string;
    provider: string;          // "oauth:naver" | "ldap:<providerId>"  ← 폼에서 절대 못 바꿈
    subject: string;           //                                       ← 폼에서 절대 못 바꿈
    email: string | null;
    emailVerified: boolean;    // 프로바이더가 검증을 단언한 경우만 true
    displayName?: string;
    givenName?: string;
    familyName?: string;
    suggestedUsername?: string;
    redirectTo: string | null; // 이미 sanitize 된 값만 저장, 소비 시 재검증
    skinHint: string | null;
}
```

가입 액션의 규칙:

- `provider` / `subject` 는 **오직 토큰에서만** 읽는다. 폼 입력은 쳐다보지 않는다.
- `claims.tenantId !== locals.tenant.id` → 거부 (멀티테넌트 호스트 전환 방어).
- 성공/취소/만료 시 쿠키 즉시 삭제.
- DB 쓰기는 제출 시점에 한 번뿐 → 사용자가 중간에 이탈해도 **고아 레코드가 남지 않는다.**

#### 2.8.2 이메일 처리 규칙

| 프로바이더가 준 것 | 폼에서 | 계정 생성 시 |
| --- | --- | --- |
| 검증된 이메일 | **읽기 전용** (서버는 폼값 무시하고 토큰값 사용) | `emailVerifiedAt = now`, 인증 메일 미발송 |
| 미검증 이메일 | 프리필 + 수정 가능 | `emailVerifiedAt = null` + `issueEmailVerification` 발송 |
| 이메일 없음 | 빈 칸, 필수 입력 | 위와 동일 |

- 입력/토큰 이메일이 **기존 계정과 충돌**하면 검증 여부와 무관하게 생성 거부 → "기존 방법으로 로그인 후 연결" 안내. (§2.4 의 2번과 동일한 이유. 여기서 뚫리면 §2.4 방어가 무의미해진다.)

#### 2.8.3 비밀번호 — 선택 사항

- 현재 `/signup` 은 비밀번호를 필수로 요구한다(`signup/+page.server.ts:86`). 연합 가입에서는 **선택**으로 만든다.
- 미설정 시 `credentials` 행 없이 `identities` 행만 생성 → `guards.ts:56-70` 이 이미 `credentials OR identities` 로 로그인 가능 판정을 하므로 그대로 동작한다.
- 설정 시 기존 검증(길이 / `MAX_PASSWORD_LENGTH` / HIBP / confirm 일치)을 그대로 적용.
- **LDAP 모드에서는 비밀번호 필드를 아예 렌더하지 않는다.** LDAP 비밀번호를 KeyStone 에 복사 저장하면 안 되고, 인증은 매번 디렉터리가 담당한다.

#### 2.8.4 라우트 — 새로 만들지 않고 `/signup` 확장

`/signup?federated=1` 로 간다. 별도 라우트를 만들면 `client_skins.skin_type` enum(`login|signup|find_id|find_password|mfa|reset_password`, `schema.sqlite.ts:1005`)에 값을 추가해야 하고 = **3방언 마이그레이션이 하나 더 늘어난다.**

- `load`: 쿠키 검증 → `federated` 객체(프로바이더 표시명, email, emailLocked, suggestedUsername, displayName) 반환. 쿠키 없거나 만료면 `/login?error=link_expired` 로.
- **커스텀 스킨은 연합 모드에서 기본 스킨으로 폴백한다.** 스킨 HTML 은 소셜 필드를 모른다. `login/+page.svelte:93` 이 `form?.recovery` 일 때 스킨을 폴백하는 선례가 이미 있으므로 같은 패턴을 쓴다.
- 액션: `default`(기존 로컬 가입)와 `federated`(신규)를 분리해 로컬 경로에 리스크를 주지 않는다.
- 쓰기는 `runAtomic`(`db/atomic.ts`)으로 `users` + `identities` (+ 선택적 `credentials`) 를 한 단위로 묶는다.
- 동시 제출 경합은 `identities_tenant_provider_subject_uidx` 가 막는다. unique 위반을 잡으면 "이미 연결됨" → 그냥 로그인 성공으로 처리한다.
- 레이트리밋은 `signup:fed:${ipKey}` 로 별도 키를 쓴다. 외부 IdP 인증을 이미 통과한 요청이라 봇 비용이 높으므로, 로컬 가입의 5회/시간보다 여유를 둔다.
- 가입 완료 후에는 `/login?registered=1` 로 되돌리지 않고 **바로 세션을 발급**한다(방금 외부 인증을 마쳤으므로). MFA 크레덴셜이 있을 리 없는 신규 계정이지만, 경로는 §2.5 와 동일하게 탄다.
- audit: `kind:"federated_signup"`, `detail:{ provider, emailVerified }`.

#### 2.8.5 LDAP 을 `signup_form` 으로 켰을 때

`login/+page.server.ts:204-208` 의 인라인 JIT 지점을 분기시킨다. `provisionLdapUser` 가 "신규 유저" 케이스에서 생성 대신 `PendingLinkClaims` 를 반환하도록 쪼개고, login 액션은 쿠키를 심은 뒤 `/signup?federated=1` 로 redirect 한다.

- 폼은 최소화: 이메일 확인 + 표시이름 정도. username 은 LDAP 값 고정(읽기 전용), 비밀번호 필드 없음.
- 토큰에 **LDAP 비밀번호를 절대 담지 않는다.** `dn` + 정규화된 속성만.

### 2.5 MFA·세션과의 접속

콜백 성공 후 **로컬 로그인과 완전히 같은 경로**를 탄다:

- `hasTotpCredential()` → true 면 `createMfaPendingToken` + `/mfa` 리다이렉트 (신뢰 기기 체크 포함).
- 아니면 `createSessionRecord` + `setSessionCookie`.
- `amr`: `constants.ts` 에 `AMR_FEDERATED = "fed"` 추가. **소셜 단독은 `ACR_MFA` 를 만족시키지 않는다** (`amrToAcr` 는 손대지 않으면 자동으로 `ACR_PASSWORD_TRANSPORT` 반환 — 의도된 동작).
- `forceAuthn=true` 로 들어온 경우 upstream authorize 요청에 `prompt=login` 을 붙인다.
- audit: `kind:"login"`, `detail:{ via:"oauth", provider: slug }`.

### 2.6 UI

- 로그인 페이지 `load` 에서 `enabled=true` 인 `oauth2`/`oidc` 프로바이더 조회 → 버튼 렌더.
- 버튼은 `GET /auth/oauth/{slug}/start` 링크. (state 쿠키가 로그인 CSRF 를 막으므로 GET 으로 충분하고, 커스텀 스킨에서도 단순 `<a>` 로 쓸 수 있다.)
- **CSP 주의**: `img-src` 가 `self`/`data:` 뿐이라 외부 로고 URL 은 차단된다. 아이콘은 **인라인 SVG 컴포넌트**로 번들한다.
- 커스텀 스킨 대응: `replacePlaceholders` 에 `IDP_SOCIAL_BUTTONS` placeholder 추가 (`login/+page.server.ts:40-47, 71-78` 두 군데 모두).

### 2.7 SSRF

`discoveryUrl` / 커스텀 엔드포인트는 admin 입력값을 서버가 fetch 한다.
`validation.ts` 의 `isForbiddenWebhookHost` / `assertResolvedHostAllowed` 를 재사용해 `validateHttpsUrl()` 을 추가하고, admin 저장 시점 + fetch 직전 양쪽에서 검사한다.

---

## 3. 프로바이더별 함정 (구현 전 필독)

| | Naver | Kakao | GitHub | Microsoft (Entra) |
| --- | --- | --- | --- | --- |
| 프로토콜 | 순수 OAuth2 | OAuth2 + OIDC 옵션 | 순수 OAuth2 | 정식 OIDC (discovery) |
| subject | `response.id` | `id` (**숫자 → 문자열 변환 필수**) | `id` (숫자) | `sub` (앱별 pairwise) |
| userinfo | `https://openapi.naver.com/v1/nid/me` — 실제 데이터가 **`response` 아래 중첩** | `https://kapi.kakao.com/v2/user/me` — 이메일은 `kakao_account.email` | `https://api.github.com/user` | id_token 클레임 |
| 이메일 | 앱 심사에서 이메일 권한 승인 필요. **없을 수 있음** | `account_email` 스코프 = **비즈 앱 검수 필요**. `is_email_verified` 확인 필수 | `/user` 의 email 이 **null 일 수 있음** → `/user/emails` 에서 `primary && verified` 추출 | `email` 클레임 **보장 안 됨** → `preferred_username` 폴백 |
| PKCE | 미지원 | 지원 | 미지원 | 지원(필수 권장) |
| 기타 | `state` 필수 | OIDC 모드면 범용 어댑터 재사용 가능 | 토큰 교환에 `Accept: application/json` + `User-Agent` 헤더 필수 | `common` 테넌트 사용 시 `iss`/`tid` 검증 반드시 직접 확인 |

→ PKCE 지원 여부는 프로바이더 프리셋의 `supportsPkce` 플래그로 분기한다.

---

## 4. 파일 단위 작업 목록

### 신규

```
src/lib/server/oauth/types.ts              // OAuthProviderConfig, NormalizedProfile
src/lib/server/oauth/registry.ts           // naver/kakao/github/microsoft/google 프리셋
src/lib/server/oauth/providers/naver.ts
src/lib/server/oauth/providers/kakao.ts
src/lib/server/oauth/providers/github.ts
src/lib/server/oauth/providers/generic-oidc.ts   // microsoft/google/kakao-oidc 공용
src/lib/server/oauth/client.ts             // authorize URL 생성, 토큰 교환, discovery 캐시, PKCE
src/lib/server/oauth/state.ts              // state 쿠키 서명/검증/삭제
src/lib/server/oauth/provision.ts          // 연결 정책 + provisioningMode 분기
src/lib/server/auth/pending-link.ts        // PENDING_LINK_COOKIE 서명 토큰 (§2.8.1)
src/routes/auth/oauth/[slug]/start/+server.ts
src/routes/auth/oauth/[slug]/callback/+server.ts
src/routes/account/connections/+page.{server.ts,svelte}
src/routes/admin/social-providers/+page.{server.ts,svelte}
src/lib/components/SocialLoginButtons.svelte
src/lib/components/icons/{Naver,Kakao,GitHub,Microsoft}Icon.svelte
```

### 수정

```
src/lib/server/db/schema.{sqlite,pg,mysql}.ts   // slug 컬럼 + unique index (3벌 동시)
drizzle/**                                      // db:generate:all 산출물 (적용은 사용자)
src/lib/server/auth/constants.ts                // AMR_FEDERATED
src/lib/server/validation.ts                    // validateHttpsUrl
src/routes/(auth)/login/+page.server.ts         // providers 조회 + IDP_SOCIAL_BUTTONS placeholder
                                                //  + LDAP signup_form 모드 분기 (§2.8.5)
src/routes/(auth)/login/+page.svelte            // 버튼 렌더
src/routes/(auth)/signup/+page.server.ts        // federated 액션 추가 (§2.8.4)
src/routes/(auth)/signup/+page.svelte           // 연합 모드 폼 + 스킨 폴백
src/lib/server/ldap/provision.ts                // 신규 유저 케이스를 PendingLinkClaims 반환으로 분리
src/hooks.server.ts                             // SENSITIVE 에 /auth/oauth 추가 (no-cache)
src/lib/i18n/{ko,en}.json                       // social.* / admin social provider 키
src/routes/admin/+layout.svelte                 // 네비 항목
docs/ADMIN_GUIDE.md                             // 프로바이더 등록 절차
```

> `hooks.server.ts` 의 `CSRF_PROTECTED` 에는 **넣지 않는다.** 콜백은 외부 origin 에서 오는 GET 이라 Referer 검사에 걸린다. (현재 로직이 비-GET 만 검사하므로 기본값으로도 안전하지만, 명시적으로 주석을 남긴다.)

---

## 5. 단계별 진행

| 단계 | 산출물 | 검증 |
| --- | --- | --- |
| **P0. 스키마** | `slug` 컬럼 3방언 + `db:generate:all` | `bun run test -- schema-parity`, `bun run db:check` |
| **P1. 코어** | `oauth/{types,registry,client,state,provision}.ts` + GitHub 어댑터 1종 | 어댑터 정규화 유닛 테스트 |
| **P2. 라우트** | `start` / `callback` + 로그인 버튼 | `test/integration/oauth-login.test.ts` (fetch 스텁, `ldap-login.test.ts` 패턴) |
| **P3. 연합 회원가입** | `pending-link.ts` + `/signup?federated=1` (§2.8) | 변조 방어 테스트 셋(§6) |
| **P4. 관리자 UI** | `/admin/social-providers` (CRUD + 시크릿 암호화 + CSRF + audit + `provisioningMode`) | 수동 + `admin-zod` 패턴 유닛 테스트 |
| **P5. 나머지 어댑터** | Naver / Kakao / Microsoft | 어댑터별 유닛 테스트 |
| **P6. LDAP 연동** | `provisionLdapUser` 분리 + `provisioningMode` 적용 (§2.8.5) | 기존 `ldap-login.test.ts` 회귀 + 신규 모드 테스트 |
| **P7. 셀프서비스** | `/account/connections` 연결·해제 (마지막 로그인 수단 해제 차단) | 통합 테스트 |
| **P8. 마감** | i18n, 스킨 placeholder, `ADMIN_GUIDE.md`, 보안 리뷰 | `bun run lint && bun run check && bun run test` |

P3 이 P4 보다 앞서는 이유: 연합 회원가입은 P2 콜백이 "매칭 계정 없음"으로 떨어질 때 **바로 필요한 경로**다. 관리자 UI 없이도 시드/수동 INSERT 로 프로바이더 한 개를 넣어 P1~P3 을 끝까지 검증할 수 있다.
P6 이 뒤에 있는 이유: LDAP 은 현행 `jit` 이 기본이라 기능적으로 급하지 않고, 기존 동작 회귀 위험이 가장 큰 구간이라 연합 가입 폼이 소셜에서 충분히 검증된 뒤에 손대는 게 안전하다.

GitHub 을 P1 파일럿으로 삼는 이유: 무료 OAuth 앱을 즉시 만들 수 있고, "이메일이 null 일 수 있다 / 별도 엔드포인트 조회" 라는 **가장 성가신 케이스**를 초반에 밟아서 추상화가 그쪽으로 맞춰진다.

---

## 6. 반드시 테스트할 항목

- state 불일치 / state 쿠키 없음 / state 재사용 → 전부 거부
- PKCE verifier 불일치 → 거부
- OIDC `nonce` 불일치, `iss`/`aud`/`exp` 검증 실패 → 거부
- 프로바이더 이메일 == 기존 로컬 유저 이메일 → **자동 연결되지 않음** (탈취 회귀 테스트)

연합 회원가입(§2.8) 전용:

- **폼에 `provider`/`subject` hidden 필드를 위조해 제출 → 토큰 값만 쓰이고 폼값은 무시됨** (핵심 회귀 테스트)
- 검증된 이메일인데 폼 email 을 다른 값으로 변조 제출 → 토큰의 이메일로 생성됨
- 미검증 이메일로 가입 → `emailVerifiedAt` 이 `null` 이고 인증 메일이 발송됨
- 폼 email 이 기존 계정과 충돌 → 생성 거부, 병합 안 됨
- `PENDING_LINK_COOKIE` 없음 / 만료 / 서명 위조 / 다른 tenantId → 전부 거부
- 가입 폼을 이탈(미제출) → `users`/`identities` 어느 쪽에도 행이 생기지 않음
- 같은 pending 토큰으로 두 번 제출 → unique 위반이 잡혀 중복 계정이 생기지 않음
- 비밀번호 없이 가입한 계정으로 소셜 재로그인 성공 (`guards.ts` 로그인 가능 판정)
- LDAP `provisioningMode:"jit"`(기본값) → **기존 동작 그대로**, 가입 폼을 거치지 않음
- 소셜 로그인 유저에 TOTP 존재 → `/mfa` 경유 강제
- 소셜 단독 로그인 세션의 `acr` 가 `ACR_MFA` 가 **아님**
- 마지막 로그인 수단인 identity 해제 시도 → 차단
- `disabled` / `locked` 유저의 소셜 로그인 → 거부
- `redirectTo` 가 `sanitizeRedirectTarget` 를 통과해야만 사용됨

---

## 7. 사용자(운영자) 준비물

각 프로바이더 콘솔에서 앱 생성 후 Redirect URI 등록:

```
https://<idp-호스트>/auth/oauth/naver/callback
https://<idp-호스트>/auth/oauth/kakao/callback
https://<idp-호스트>/auth/oauth/github/callback
https://<idp-호스트>/auth/oauth/entra/callback
```

- 네이버/카카오는 Redirect URI **완전 일치**를 요구 → 로컬 개발용 앱을 별도로 만들어야 한다.
- 카카오 이메일 수집은 비즈 앱 검수가 필요 → 검수 전이라면 `allowSignup=false` + 수동 연결로 운영.
- `IDP_SIGNING_KEY_SECRET` 필수 (client secret 암호화에 사용).
- client secret 은 환경변수가 아니라 **admin UI 를 통해 DB 에 암호화 저장**한다(LDAP bindPassword 와 동일 모델).
