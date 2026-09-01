# Lodestar 관리자 운영 매뉴얼

Lodestar(멀티테넌트 IdP)의 관리 콘솔 운영 가이드입니다. 각 화면에서 관리자가 무엇을 클릭하고 어떤 일이 일어나는지를 실무 관점에서 정리했습니다.

> 콘솔 UI 는 한국어/영어(ko/en)를 지원합니다. 모든 관리 작업은 현재 로그인한 테넌트 범위에서만 동작하며, 주요 변경은 감사 로그(`/admin/audit`)에 기록됩니다.

---

## 1. 개요 / 접근

### 관리자 로그인

- 로그인 URL: **`/admin/login`**
- 인증 흐름(`/admin/login` → `/mfa`):
    1. 아이디/비밀번호 검증(로컬 계정).
    2. **`role === "admin"` 이 아니면 거부**(감사 로그에 `reason: not_admin`).
    3. **TOTP(MFA) 미등록 관리자는 로그인 불가**(`reason: mfa_not_configured`) — 관리자는 반드시 TOTP 를 등록해야 합니다.
    4. MFA pending 쿠키 발급 후 `/mfa` 로 이동해 TOTP 코드 확인 → 세션 생성.
- 레이트리밋: IP당 15분에 10회.
- `IDP_SIGNING_KEY_SECRET` 미설정 시 MFA 토큰 서명이 불가해 로그인이 503 으로 막힙니다.

### 접근 제어

- `/admin/**` 전 구간은 레이아웃 가드(`+layout.server.ts`)가 보호합니다.
    - 미로그인 → `/admin/login?redirectTo=...` 로 리다이렉트.
    - **`role !== "admin"` → `/` 로 강제 이동**(일반 사용자는 콘솔 접근 불가).
    - **세션이 MFA 수준(ACR `refeds/mfa`)이 아니면 콘솔에 들어올 수 없습니다.** 아래 참조.
- `/admin/login` 만 예외적으로 비인증 접근 허용.

#### MFA 세션 요구

`/admin/login` 은 원래부터 TOTP 를 강제하지만, **`/login`(일반 로그인)으로 만든 세션도 `role=admin` 이면
콘솔에 들어올 수 있었습니다.** TOTP 를 등록하지 않은 관리자가 비밀번호만으로 콘솔에 진입하는 경로였고,
지금은 막혀 있습니다.

- 판정 기준은 세션의 **ACR** 입니다. `pwd + totp`, `pwd + 백업코드`, 패스키(`hwk`), 신뢰 기기 경로는
  모두 `refeds/mfa` 를 만족하므로 **TOTP 를 등록한 관리자는 이 게이트에 걸리지 않습니다.**
- 못 미치는 세션은 **`/mfa?stepUp=mfa` 로 보내 OTP 만 추가로 받습니다**(로그인 상태 유지 — 아이디·비밀번호를
  다시 묻지 않습니다).
- **TOTP 미등록 관리자는 403** 과 함께 등록 안내를 받습니다. 리다이렉트로 보내면 비밀번호로 로그인해도
  ACR 이 올라가지 않아 무한 왕복하기 때문입니다. `/account/mfa` 는 관리자 권한을 요구하지 않으므로
  거기서 TOTP 를 등록한 뒤 콘솔로 들어오면 됩니다.
- 게이트는 **두 겹**입니다. 레이아웃 가드는 화면 이동용이고, 폼 액션(POST)은 레이아웃 load 를 거치지
  않으므로 `requireAdminContext()` 가 같은 조건을 403 으로 막습니다. 한쪽만 있으면 액션 직접 호출로
  우회됩니다.

### 대시보드

- **`/admin`**: 테넌트 요약 카운트(사용자, OIDC 클라이언트, SAML SP, 서명키, 감사 이벤트, 부서/팀/직급) 표시.

---

## 2. 조직 관리 (부서 / 팀 / 파트 / 직급)

조직은 **부서(department) → 팀(team) → 파트(part)** 3단계 계층이며, **직급(position)** 은 별도 축입니다.

| 화면 | 경로                 | 상위 참조                             | 계층          |
| ---- | -------------------- | ------------------------------------- | ------------- |
| 부서 | `/admin/departments` | 상위 부서(`parentId`, 자기 참조 트리) | 최상위        |
| 팀   | `/admin/teams`       | 부서(`departmentId`)                  | 부서 하위     |
| 파트 | `/admin/parts`       | 팀(`teamId`)                          | 팀 하위       |
| 직급 | `/admin/positions`   | 없음                                  | 독립(레벨 축) |

### 부서 (`/admin/departments`)

- 필드: 이름(필수), 코드, 상위 부서, 설명, 표시순서(`displayOrder`, 빈값 0). 수정 시 상태(active/inactive 등) 지정.
- **부서 트리 검증**(등록·수정 공통):
    - 최대 깊이 **8단계**.
    - 자기 자신을 상위로 지정 불가.
    - 상위 체인에 순환 참조가 생기면 차단(간접 순환 A→B→A 포함).
    - 상위 부서 선택지는 **활성(active) 부서**만 노출.
- 부서 트리 변경은 권한 상속에 직결되므로 **모든 변경이 감사 로그**(`department_*`)에 기록됩니다.

### 팀 (`/admin/teams`)

- 필드: 이름(필수), 코드, 소속 부서, 설명. 수정 시 상태.
- 소속 부서 선택지는 **활성 부서**만. 지정한 부서가 같은 테넌트에 존재하는지 참조 무결성 검증.

### 파트 (`/admin/parts`)

- 필드: 이름(필수), 코드, 소속 팀, 설명. 수정 시 상태.
- 소속 팀 선택지는 **활성 팀**만(부서명 병기). 참조 무결성 검증.

### 직급 (`/admin/positions`)

- 필드: 이름(필수), 코드, **레벨(`level`, 정수)**. 레벨 오름차순으로 정렬 표시.

### 사용자 소속 배정 & 주소속(primary) 의미

개별 사용자의 소속은 **`/admin/users/[id]`** 상세 화면에서 배정합니다(부서/팀/파트 각각 add/remove).

- 배정 시 각 소속에 **직책(jobTitle)** 을 지정할 수 있고, 부서 배정에는 **직급(position)** 을 함께 지정합니다.
- **주소속(primary)**: 각 축(부서/팀/파트)마다 `isPrimary` 체크박스로 지정. 소속 해제는 하드 삭제가 아니라 **`endedAt` 설정(소프트 종료)** 으로 처리됩니다(이력 보존).
- **주소속 부서**의 직급/직책이 OIDC `organization` 클레임의 최상위 `position` / `job_title` 값이 됩니다(주소속이 없으면 현재 소속 목록의 첫 부서를 사용).

---

## 3. OIDC 클라이언트 등록/관리 (`/admin/oidc-clients`)

### 생성

- **client_id**: 자동 생성(무작위 20자).
- **client_secret**: `token_endpoint_auth_method` 가 `none`(public)이 아니면 자동 생성되어 **생성 직후 화면에 1회만 노출**됩니다. DB 에는 해시만 저장되므로 이때 반드시 복사해 두어야 합니다.
- **Redirect URIs**(필수): 줄바꿈/콤마로 여러 개. `https` 또는 loopback(`http://localhost` 등) 허용, 모바일용 **커스텀 스킴 허용**. `javascript:`/`data:`/`file:`/`blob:`/`vbscript:` 및 fragment(`#`) 포함 URI 는 거부.
- **Post-Logout Redirect URIs / Front-channel / Back-channel Logout URI**: 로그아웃 관련 URL(각 세션 요구 플래그 포함). 커스텀 스킴 불허(https/loopback 만).
- **token_endpoint_auth_method**: `client_secret_basic` / `client_secret_post` / `none` 중 선택.
- **PKCE(`requirePkce`)**: 체크로 강제. **public 클라이언트(`none`)는 PKCE 가 항상 강제**되며 수정 시에도 해제 불가.
- **Wildcard Redirect URI(`allowWildcardRedirectUri`)**: 보안상 기본 비활성. 와일드카드 매칭이 꼭 필요할 때만 **명시적 opt-in**(체크).
- **MFA 인증된 세션만 허용(`requireMfa`)** / **재인증 방식(`reauthPolicy`)**: 아래 [재인증 정책](#재인증-정책-requiremfa--reauthpolicy) 참고.
- **Scopes**(공백 구분): `openid`(필수) / `profile` / `email` / `address` / `phone` / `offline_access` / `organization` / `groups`. `openid` 누락 시 거부.
    - `offline_access` 를 넣어야 refresh token(grant) 이 발급됩니다.
    - ⚠️ **`groups` 는 조직 소속(부서·팀·파트)이며 인가에 사용하지 마세요.** 서비스 권한은 `roles` 클레임을 씁니다. 자세한 구분은 아래 [발행 클레임](#발행-클레임) 참고.
    - `organization` 은 부서/직위/직책 등 조직 세부를 클레임으로 내보냅니다. 역시 표시용입니다.

### 발행 클레임

RP 가 받는 클레임은 성격이 다른 세 갈래이며, **어느 것으로 인가할지가 갈리는 지점**입니다.

| 클레임                  | 출처                                          | scope 필요                | 용도                  |
| ----------------------- | --------------------------------------------- | ------------------------- | --------------------- |
| `groups`                | 조직 소속 — `departments` · `teams` · `parts` | `groups`                  | **표시용.** 인가 금지 |
| `organization` 계열     | 조직 세부(부서/직위/직책 등)                  | `organization`            | **표시용**            |
| `roles` · `roles_label` | 서비스 역할 — 사용자별 서비스 배정            | 불필요(배정 존재 시 발행) | **인가용**            |
| `entitlements`          | 서비스 세부 권한 — 배정에 부여된 권한 키 목록 | 불필요(배정 존재 시 발행) | **인가용**            |

**`groups` 로 인가하면 안 되는 이유**: 조직도는 인사가 바꾸고 권한은 보안 담당이 줍니다. `groups` 로 인가하면 팀 이동이 보안 경계를 움직이고, 부서 개편이 권한을 재배정하며, 두 역할을 분리할 수 없게 됩니다. 이름이 인가용처럼 읽히고 값이 여러 개라 권한 집합처럼 보이지만 **인사 구조**입니다.

**`roles` 는 사용자당 서비스당 하나**입니다. 배열로 오지만 원소는 항상 1개이며, 이는 스키마 제약(`user_service_assignments` 의 유니크 인덱스)입니다. **`entitlements` 는 개수 제한이 없습니다** — 같은 배정에 여러 권한 키를 붙일 수 있어 `roles` 와 직교하는 축입니다. `roles`/`entitlements` 모두 값이 없으면 **키 자체가 페이로드에서 생략**되므로, 권한 모델을 쓰지 않는 기존 RP 의 응답은 변하지 않습니다.

역할·권한 정의는 **4장(서비스 role/entitlement 설정)**, 사용자별 배정은 **10장(사용자 운영 흐름)** 을 참고하세요.

SAML SP 에도 같은 값이 Assertion 의 **`Entitlements` 속성**으로 나갑니다. 다만 `Role`·`RoleLabel` 과 동일하게 **SP 의 허용 속성 목록에 `Entitlements` 를 넣어야** 전달됩니다(6장 참조) — 목록에 없으면 정의·배정을 해도 Assertion 에 나가지 않습니다.

### 재인증 정책 (`requireMfa` / `reauthPolicy`)

두 설정은 축이 다릅니다. **`requireMfa` 는 "무엇을 요구할지", `reauthPolicy` 는 "그 요구를 무엇으로
충족시킬지"** 를 정합니다. OIDC 클라이언트와 SAML SP 양쪽에 같은 이름으로 있습니다.

| 설정           | 기본값 | 뜻                                                                     |
| -------------- | ------ | ---------------------------------------------------------------------- |
| `requireMfa`   | 꺼짐   | 이 서비스로 SSO 하려면 세션이 MFA 수준(ACR `refeds/mfa`)이어야 한다    |
| `reauthPolicy` | `full` | 재인증이 필요할 때 `full`(아이디·비밀번호부터) 또는 `mfa_only`(OTP 만) |

#### `requireMfa` — `prompt=login` 과 다릅니다

RP 가 매번 `prompt=login` 을 보내는 방식과 결과가 다릅니다. `prompt=login` 은 세션이 **이미 MFA 여도**
무조건 재인증을 요구하므로, 같은 패밀리 앱 사이를 오갈 때마다 인증 화면이 뜹니다. `requireMfa` 는
**부족할 때만** 요구하므로 **한 번 OTP 를 통과한 뒤의 재방문은 그대로 통과**합니다.

SAML 에서는 SP 가 `RequestedAuthnContext` 로 같은 요구를 보낼 수 있지만, `requireMfa` 는 SP 가 요청에
아무것도 담지 않아도 **IdP 측에서 강제**합니다. SP-initiated 와 IdP-initiated(`?sp=<entityId>`) 양쪽에
모두 걸립니다.

#### `reauthPolicy=mfa_only` — 세션을 유지한 채 OTP 만

재인증이 필요해질 때 `/login` 으로 보내는 대신 **`/mfa` 에서 OTP 만 받아 기존 세션의 AMR/ACR 을
승격**합니다. 세션 행을 새로 만들지 않으므로 `sid` 와 세션 쿠키가 그대로 유지되고, 이미 로그인돼 있던
다른 RP 들의 세션 매핑도 끊기지 않습니다.

적용되는 트리거:

| 트리거                              | `full`               | `mfa_only`               |
| ----------------------------------- | -------------------- | ------------------------ |
| `requireMfa` 미충족                 | `/login` 전체 재인증 | `/mfa` OTP 승격          |
| OIDC `prompt=login`                 | `/login` 전체 재인증 | `/mfa` OTP 승격          |
| OIDC `max_age` 초과                 | `/login` 전체 재인증 | `/mfa` OTP 승격          |
| SAML `RequestedAuthnContext` 미충족 | `/login` 전체 재인증 | `/mfa` OTP 승격          |
| SAML `ForceAuthn`                   | `/login` 전체 재인증 | `/mfa` OTP 승격          |
| OIDC `id_token_hint` 의 sub 불일치  | `/login` 전체 로그인 | **`/login` 전체 로그인** |

**`id_token_hint` sub 불일치는 정책과 무관하게 항상 전체 로그인**입니다. RP 가 다른 사용자로
로그인시키라고 요구하는 **계정 전환**이므로 OTP 로는 해결할 수 없습니다.

TOTP 미등록 사용자는 OTP 로 승격할 수단이 없으므로 `/mfa` 가 스스로 `/login?forceAuthn=true` 로
되돌립니다. 결과적으로 기존 동작(로그인 후에도 ACR 이 부족하면 SAML SP 에 `NoAuthnContext` 반환)이
유지됩니다.

#### 켤 때 알아야 할 트레이드오프

`mfa_only` 는 **"비밀번호를 최근에 다시 제시했다"는 보증을 포기하고** 세션에 남은 1차 인증 증명을
재사용합니다. 그래서 기본값이 `full` 이고 서비스별 opt-in 입니다.

- OIDC `prompt=login` 의 재인증 의도를 완화합니다.
- SAML `ForceAuthn` 은 규격(SAML Core 3.4.1.1)이 "기존 세션에 의존하지 말고 새로 인증을 확립하라"고
  요구하는데, `mfa_only` 는 그 요구를 완화합니다. **SP 운영자가 알고 켜야 합니다.**
- 반대로 볼 면도 있습니다. 어깨 넘어로 훔쳐볼 수 있는 비밀번호와 달리 **OTP 는 기기 보유를 요구**하므로,
  공유 워크스테이션에서 키보드 앞의 공격자를 막는 데는 비밀번호 재입력보다 강할 수 있습니다.

같은 패밀리 앱 사이의 이동처럼 **서로 신뢰하는 서비스 간 전환**을 전제로 한 설정입니다.

정책 변경은 감사 로그에 기록됩니다(SAML SP 는 `saml_sp_updated` 의 `changed.reauthPolicy` ·
`newReauthPolicy`).

### 관리

- **수정**: 이름/URI/scope/로그아웃 설정/PKCE/와일드카드/활성화(enabled) 변경.
- **시크릿 재발급(`regenerateSecret`)**: 새 시크릿 생성 후 **1회 노출**. 기존 시크릿은 즉시 무효화됩니다.
- **삭제**: 클라이언트 제거.
- 생성/수정/시크릿재발급/삭제 모두 감사 로그(`oidc_client_*`) 기록. 모든 폼은 CSRF 토큰으로 보호됩니다.

---

## 4. 서비스 role / entitlement 설정 (`/admin/oidc-clients/[id]`)

클라이언트 상세 화면에서 **서비스 role** 과 **entitlement(세부 권한)** 를 정의합니다(SAML SP 도 `/admin/saml-sps/[id]` 에서 동일 구조).

### role 정의

- role 필드:
    - **key**(필수): `^[A-Za-z0-9_.-]{1,64}$` 형식. 같은 서비스 내 중복 불가(중복 시 409).
    - **label**(필수): 표시 이름.
    - **description**: 설명(선택).
    - **isDefault**: 기본 부여 role 표시.
    - **displayOrder**: 정렬 순서(정수).
- role 추가/삭제는 감사 로그(`service_role_created` / `service_role_deleted`)에 기록됩니다.
- 정의한 role 은 `/admin/users/[id]` 에서 사용자에게 **서비스 권한(assignment)** 으로 부여합니다(만료/취소 관리 포함). **사용자당 서비스당 role 은 하나**입니다.

### entitlement 정의

role 과 직교하는 권한 축입니다. role 이 "이 사람이 이 서비스에서 무엇인가"라면, entitlement 는 "구체적으로 무엇을 할 수 있는가"입니다. 하나의 배정에 **여러 개**를 붙일 수 있습니다.

- 필드는 role 과 같습니다(key / label / description / displayOrder). `site.read`, `plan.approve_own` 같은 네임스페이스 키를 권장합니다.
- **key 는 저장 시 소문자로 정규화**됩니다. 유니크 인덱스에 collation 을 지정하지 않아 방언마다 대소문자 취급이 달라지는데(MySQL 은 `Site.Read`↔`site.read` 를 충돌로 보고, PostgreSQL·SQLite 는 별개 행으로 받아 **둘 다 클레임에 실림**), 인가에 쓰이는 값이 배포 DB 에 따라 달라지면 안 되므로 입력 시점에 하나로 모읍니다.
- 추가/수정/삭제는 감사 로그(`service_entitlement_created` / `_updated` / `_deleted`)에 기록됩니다.
- **정의를 삭제하면 그 권한을 부여받은 사용자에게서도 회수**되며, 회수 건마다 `user_entitlement_revoked`(`cause: definition_deleted`)가 남습니다. 삭제 전 영향 사용자 수를 확인하세요.

### 변경 통지 (SET)

클라이언트에 `role_change_uri` 가 등록돼 있으면, 사용자의 role/entitlement 가 바뀔 때 **Security Event Token** 이 그 URI 로 POST 됩니다. RP 는 세션을 끊지 않고 권한만 갱신하므로 사용자가 재로그인할 필요가 없습니다.

- 이 통지는 **fire-and-forget 이고 재시도가 없습니다.** 전송 실패 시 RP 는 다음 변경 때까지 옛 권한을 들고 있게 되므로, 권한 회수를 즉시 강제해야 하는 상황이라면 통지에만 의존하지 말고 세션 철회(10장)를 함께 쓰세요.
- 짧은 간격의 두 변경은 도착 순서가 뒤집힐 수 있어, RP 는 payload 의 `txn`(발행 시각 ms) 을 기억하고 그보다 작거나 같은 SET 을 버려야 합니다.

---

## 5. organization 클레임 노출 설정 (`/admin/oidc-clients/[id]`)

클라이언트 상세 화면 하단 **"조직 클레임 노출 설정"** 에서, `organization` scope 로 노출되는 조직 정보를 필드별로 on/off 합니다.

### 노출되는 클레임 구조

`organization` scope 가 켜진 클라이언트의 **id_token 과 userinfo 응답에 동일하게** 아래 4개 최상위 키가 들어갑니다.

| 클레임 키    | 내용                                                                                                                        |
| ------------ | --------------------------------------------------------------------------------------------------------------------------- |
| `department` | 현재 소속 부서 배열. 각 원소: `id`, `name`, `code`, `is_primary`, `job_title`, `position`(`{id,name,code,level}` 또는 null) |
| `team`       | 현재 소속 팀 배열. 각 원소: `id`, `name`, `code`, `department`(부서명), `is_primary`, `job_title`                           |
| `position`   | 주소속 부서의 직급명(문자열) 또는 null                                                                                      |
| `job_title`  | 주소속 부서의 직책(문자열) 또는 null                                                                                        |

### 체크박스 4개와 저장 규칙

토글 필드는 **`department` / `team` / `position` / `jobTitle`** 4개입니다.

- **모든 필드를 켜면 → `null`(미설정)로 저장**됩니다. 즉 "전량 노출"이며, DB 를 깨끗하게 유지하고 **기존 동작과 하위호환**을 보장합니다.
- **하나라도 끄면 → 명시적 JSON** 으로 저장됩니다. 예:
    ```json
    { "department": true, "team": true, "position": false, "jobTitle": true }
    ```
    `false` 인 필드의 **최상위 클레임 키 자체가 응답에서 생략**됩니다.
- 저장 위치: `oidcClients.organizationClaimConfig`(JSON text).
- **id_token 과 userinfo 가 동일한 config 를 적용**하므로 두 응답의 조직 정보가 항상 일치합니다.

### 하위호환 / 무회귀

- `organizationClaimConfig` 가 없는(=null) 기존 클라이언트는 **전량 노출**로 동작합니다. 이번 기능 도입으로 인한 기존 클라이언트 회귀는 없습니다.
- 저장값 파싱이 실패하거나 알 수 없는 값이면 안전하게 null(전량 노출)로 폴백합니다.
- 변경은 감사 로그(`oidc_client_updated`, `detail.organizationClaimConfig`)에 기록됩니다.

---

## 6. SAML SP 등록/관리 (`/admin/saml-sps`)

### 생성 / 수정

- 필드: **이름**(필수), **Entity ID**(필수, 테넌트 내 중복 불가 → 중복 시 409), **ACS URL**(필수), SLO URL, SP 인증서(`cert`), NameID Format.
- **ACS/SLO URL 검증**: `validateSamlUrl` 로 형식 검사.
- **NameID Format**: emailAddress / unspecified / persistent / transient(SAML 표준 URN) 중에서만 허용.
- 서명/암호화 옵션:
    - **`signResponse` 는 항상 `true` 로 강제**됩니다(관리 UI 가 false 를 보내도 무시). XSW 계열 공격 방지를 위해 IdP 가 Response 자체를 항상 서명.
    - `signAssertion`, `wantAuthnRequestsSigned` 는 토글.
    - **`encryptAssertion` 을 켜려면 SP 공개키(cert)가 반드시 있어야** 합니다(없으면 400).
- **MFA 인증된 세션만 허용(`requireMfa`)** / **재인증 방식(`reauthPolicy`)**: OIDC 클라이언트와 같은 설정이며 3장의 [재인증 정책](#재인증-정책-requiremfa--reauthpolicy) 에 자세히 설명돼 있습니다. SAML 에서는 `RequestedAuthnContext` 미충족과 **`ForceAuthn`** 에도 적용되므로, `mfa_only` 를 켠다는 것은 SAML 규격이 요구하는 "기존 세션에 의존하지 않는 새 인증"을 완화한다는 뜻입니다.
- **AuthnInstant**: Assertion 의 `AuthnStatement/@AuthnInstant` 는 **사용자가 실제로 인증한 시각**입니다(응답 발급 시각이 아님). MFA step-up 으로 세션이 승격되면 이 값이 갱신되므로, SP 는 IdP 가 실제로 재인증을 했는지 이 값으로 판단할 수 있습니다.
- **allowedAttributes**: 콤마 구분. 허용 키 화이트리스트(`email`, `username`, `displayName`, `givenName`, `familyName`, `surName`, `phoneNumber`, `department`, `team`, `jobTitle`, `position`, `Role`, `RoleLabel`, `Entitlements`)에 없는 값은 무시됩니다. - **미설정 시 기본값은 `email`, `username`, `displayName` 뿐입니다.** 조직 정보와 서비스 권한(`Role` / `RoleLabel` / `Entitlements`)은 여기에 **명시적으로 넣어야** 나갑니다. 권한을 정의·배정했는데 SP 가 못 받는다면 이 목록부터 확인하세요.
    - `Role` / `RoleLabel` / `Entitlements` 는 인가 판정에 쓰이는 값이라, 사용자별 추가 속성(`attributesJson`)으로 **덮어쓸 수 없습니다**(위조 방지).
- 보안 설정 변경(특히 **cert / acsUrl / wantAuthnRequestsSigned**)은 ACS 하이재킹 포렌식을 위해 before/after diff 가 감사 로그(`saml_sp_updated`)에 상세 기록됩니다.

### 상세 (`/admin/saml-sps/[id]`)

- OIDC 클라이언트와 동일하게 **서비스 role · entitlement** 를 정의(key/label/description/isDefault/displayOrder). 4장 참조.
- 정의한 entitlement 가 Assertion 에 실리려면 SP 의 **allowedAttributes 에 `Entitlements` 가 있어야** 합니다(위 "생성 / 수정" 참조).

### 메타데이터

- IdP 측 SAML 메타데이터는 `/saml/metadata` 에서 제공됩니다(SP 설정 시 참조).

---

## 7. 스킨(커스텀 로그인 UI) 등록 (`/admin/skins`)

외부에 호스팅한 HTML 을 가져와 인증 화면을 클라이언트별로 커스터마이즈합니다. 사용법과 예제는 **`/admin/skins/guide`** 에 있습니다.

### 등록 필드

- **대상 클라이언트**: `clientType` + `clientRefId`.
    - `oidc` / `saml` — 해당 클라이언트에만 적용.
    - `tenant` — **테넌트 기본 스킨**. `clientRefId` 는 예약값 `*` 이며, 관리 화면에서는 클라이언트 목록의 [테넌트 기본] 항목을 고르면 됩니다.
- **스킨 타입(`skinType`)**: 총 **10종**.

    | 스킨 타입              | 화면                            |
    | ---------------------- | ------------------------------- |
    | `login`                | `/login`                        |
    | `signup`               | `/signup`                       |
    | `find_id`              | `/find-id`                      |
    | `find_password`        | `/find-password`                |
    | `mfa`                  | `/mfa`                          |
    | `reset_password`       | `/reset-password`               |
    | `verify_email`         | `/verify-email`                 |
    | `accept_invite`        | `/accept-invite`                |
    | `confirm_email_change` | `/account/confirm-email-change` |
    | `logout`               | `/logout`                       |

- **Fetch URL**: 스킨 HTML 을 가져올 URL. **https 필수**, loopback/내부주소(127.x, 10.x, 192.168.x, 172.16–31.x, link-local, 클라우드 메타데이터, 점 없는 단일 라벨, IPv6 리터럴) 금지(SSRF 방지). 실호스트를 해석한 결과가 내부 주소여도 건너뜁니다(DNS 리바인딩 완화).
- **Fetch Secret**: 스킨 서버 인증용 시크릿. IdP 가 스킨 HTML 을 가져올 때 **`X-IDP-Token`** 헤더로 전송하므로, 스킨 서버는 이 헤더를 검증해 접근을 통제할 수 있습니다(선택).
- **캐시 TTL(`cacheTtlSeconds`)**: 기본 3600초, 0 이상, **최대 86400초(1일)**.

### 해석 순서

**클라이언트 전용 스킨 → 테넌트 기본 스킨 → 기본 내장 UI** 순으로 찾습니다.

- 전용 스킨이 없는 클라이언트는 테넌트 기본 스킨으로 떨어집니다.
- `accept_invite` · `confirm_email_change` 는 링크에 클라이언트 정보가 없어(초대는 관리자가, 이메일 변경은 계정 화면에서 시작) **테넌트 기본 스킨만** 적용됩니다.
- `logout` 은 RP 가 `/logout?skinHint=oidc:<클라이언트 id>` 로 보내면 그 클라이언트의 스킨을 씁니다.
- `verify_email` 은 가입 흐름에서 발송된 인증 메일 링크가 `skinHint` 를 실어 나릅니다. 계정 화면에서 재발송한 경우에는 클라이언트 컨텍스트가 없어 테넌트 기본으로 떨어집니다.

### HTML 제약 (정화)

가져온 HTML 은 그대로 쓰이지 않고 **정화(sanitize)된 뒤** 렌더됩니다. 스킨 호스트가 침해되어도 임의 스크립트나 외부 폼 전송이 사용자 브라우저에 닿지 않게 하는 장치입니다.

| 구분                                     | 대상                                                                                             |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------ |
| 제거되는 태그(내용까지)                  | `script` `iframe` `object` `embed` `base` `meta` `link`                                          |
| 제거되는 속성                            | `on*` 전체, `action` `formaction` `srcdoc` `sandbox` `background`                                |
| 인라인 `style` 과 `<style>` 에서 제거    | `position` `top/left/right/bottom` `inset*` `z-index` `transform*` `perspective` `float` `clip*` |
| `href`/`src`/`data`/`poster` 허용 scheme | `https:` `http:` `data:image/` `data:font/` `mailto:` `tel:` `/` `#`                             |

- **`<style>` 은 허용됩니다.** 내용은 위 위치·레이어링 속성만 제거되고 색·글꼴·여백·테두리·크기는 보존되므로 미디어 쿼리와 `:hover`·`:focus` 를 쓸 수 있습니다. `@import` 는 제거됩니다(외부 CSS 로딩 차단).
- `data:image/svg+xml` 은 `<img>`·`<source>` 의 `src` 에서만 허용되고 `href` 에서는 제거됩니다.
- `form` 의 `action` 이 제거되면 현재 URL(=IdP)로 POST 되므로 정상 로그인 흐름은 유지됩니다.
- 외부 스타일시트·웹폰트·이미지는 CSP 가 차단하므로 폰트와 이미지는 `data:` URI 로 인라인해야 합니다.
- 그 밖에 **응답 5초 타임아웃 / 512KB 크기 상한 / `Content-Type: text/html` 필수 / 3xx 리다이렉트 거부**가 적용되며, 어느 하나라도 어긋나면 조용히 기본 UI 로 폴백합니다.

> 위치 속성 필터는 CSS 이스케이프(`p\osition` 등)까지 막는 완전한 필터가 아닙니다. JS 와 외부 요청이 CSP 로 이미 차단된 상태에서 주된 리드레싱 수단을 걷어내는 심층 방어로 이해하세요.

### 운영

- **수정 / 삭제 / 활성화 토글 / 캐시 무효화(`invalidateCache`)** 지원. URL·TTL 변경이나 삭제 시 캐시가 자동 무효화됩니다.
- 같은 (클라이언트, 스킨 타입) 조합 중복 등록 시 409. 테넌트 기본 스킨도 스킨 타입당 하나입니다.
- 스킨 수정은 감사 로그(`client_skin_updated`)에 남고, detail 에는 시크릿 평문이 들어가지 않습니다.

### 치환자(placeholder)

스킨 HTML 안에서 `{{...}}` 형태로 쓰며 IdP 가 값을 채웁니다. 총 **13개**이고 스킨 타입별 적용 범위가 다릅니다. 값은 HTML 이스케이프되며, `javascript:`·`data:text/html` 처럼 위험한 URL scheme 이 섞이면 빈 문자열로 대체됩니다. 서버가 채우지 않는 치환자도 빈 문자열로 지워지므로 화면에 `{{...}}` 가 남지 않습니다.

| 치환자                       | 채워지는 값                                                                                             | 적용 스킨                                                            |
| ---------------------------- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `{{IDP_FORM_ACTION}}`        | 항상 빈 문자열(비어 있으면 폼이 **현재 URL로 POST**)                                                    | 전체 공통                                                            |
| `{{IDP_REDIRECT_TO}}`        | 로그인 후 되돌아갈 경로 — hidden input 용                                                               | login / signup / reset_password 에서 채워지고 나머지는 빈 값         |
| `{{IDP_SKIN_HINT}}`          | 스킨 힌트 — hidden input 으로 되전달                                                                    | 전체 공통                                                            |
| `{{IDP_FLASH_MSG}}`          | 서버가 채우는 플래시/오류 메시지. 없으면 빈 값                                                          | 전체 공통(폼 재제출 오류 표시)                                       |
| `{{IDP_REGISTERED}}`         | 회원가입 완료 직후 `"1"`, 그 외 빈 값                                                                   | login                                                                |
| `{{IDP_PASSWORD_RESET}}`     | 비밀번호 재설정 완료 직후 `"1"`, 그 외 빈 값                                                            | login                                                                |
| `{{IDP_SOCIAL_BUTTONS}}`     | 활성 소셜 로그인 버튼 HTML(`<div class="idp-social-buttons">` 안의 `<a class="idp-social-btn …">` 목록) | login                                                                |
| `{{IDP_FIND_ID_SENT}}`       | 아이디 찾기 메일 발송 직후 `"1"`, 그 외 빈 값                                                           | find_id                                                              |
| `{{IDP_MASKED_USERNAME}}`    | 찾은 아이디의 마스킹된 형태. 계정이 없으면 빈 값                                                        | find_id                                                              |
| `{{IDP_FIND_PASSWORD_SENT}}` | 재설정 메일 발송 직후 `"1"`, 그 외 빈 값                                                                | find_password                                                        |
| `{{IDP_SUBMITTED_EMAIL}}`    | 사용자가 입력한 이메일(발송 완료 안내에 되짚어 표시)                                                    | find_password                                                        |
| `{{IDP_TOKEN}}`              | 토큰. hidden input(`name="token"`)에 넣어 그대로 돌려보내야 함                                          | reset_password / verify_email / accept_invite / confirm_email_change |
| `{{IDP_VERIFIED}}`           | 이미 인증이 끝난 상태면 `"1"`, 그 외 빈 값                                                              | verify_email                                                         |

### 폼 필드 이름

서버 액션이 읽는 `name` 과 정확히 일치해야 합니다. 하나라도 다르면 그 페이지의 제출이 실패합니다.

| 스킨 타입              | 필수 필드                                                        |
| ---------------------- | ---------------------------------------------------------------- |
| `login`                | `username`, `password`, `redirectTo`                             |
| `signup`               | `username`, `email`, `password`, `confirmPassword`               |
| `find_id`              | `email`                                                          |
| `find_password`        | `username`, `email`                                              |
| `mfa`                  | `code`                                                           |
| `reset_password`       | `token`, `password`, `confirmPassword`, `redirectTo`, `skinHint` |
| `verify_email`         | `token`                                                          |
| `accept_invite`        | `token`, `password`, `confirmPassword`                           |
| `confirm_email_change` | `token`                                                          |
| `logout`               | (없음 — 폼 제출만)                                               |

### 스크립트 훅

스킨은 자체 `<script>` 를 쓸 수 없습니다. 대신 IdP 가 공통 스크립트(`/api/skin-scripts`)와 패스키 클라이언트를 주입하며, 이 스크립트는 아래 선택자를 찾아 동작합니다. 맞추면 입력 검증·OTP 자동 이동·플래시 자동 숨김·패스키 로그인·로그아웃 자동 제출이 그대로 붙고, 맞추지 않으면 해당 기능만 조용히 빠집니다.

| 선택자                                             | 역할                                                                                                                                                         |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `.auth-shell[data-skin-type]`                      | 최상위 컨테이너. `data-skin-type` 값으로 어떤 초기화를 돌릴지 결정                                                                                           |
| `#flash` · `#flash-msg`                            | 플래시 영역과 메시지 노드. 내용이 있으면 표시하고 4초 후 자동 숨김                                                                                           |
| `#skin-meta[data-*]`                               | 서버 상태 전달용 빈 노드(`data-registered`, `data-pw-reset`, `data-find-id-sent`, `data-masked-username`, `data-find-password-sent`, `data-submitted-email`) |
| `#username` · `#password` · `#confirm` · `#submit` | 입력란과 제출 버튼. 오류 문구는 각 필드 래퍼 안의 `[data-err]`, 힌트는 `[data-hint]`                                                                         |
| `#passkey`                                         | 패스키 로그인 버튼(login 전용)                                                                                                                               |
| `.otp input` · `#otp-value`                        | OTP 입력 6칸과 hidden input(mfa 전용)                                                                                                                        |
| `#r-len` · `#r-mix` · `#r-special` · `#strength`   | 비밀번호 규칙 표시와 강도 미터(reset_password 전용)                                                                                                          |

### 캐시 동작

- 정화된 결과가 캐시(R2 바인딩 또는 S3 호환 스토리지)에 저장되고 TTL 동안 재사용됩니다. 캐시 스토리지가 설정되지 않았으면 매 요청마다 원본을 가져옵니다.
- 캐시 키는 **실제로 매칭된 행** 기준이라, 테넌트 기본 스킨으로 폴백한 여러 클라이언트가 캐시를 공유합니다.
- 스킨을 갱신했는데 즉시 반영이 필요하면 콘솔의 **캐시 무효화** 버튼을 쓰세요.

---

## 7-1. 소셜 로그인 제공자 (`/admin/social-providers`)

네이버 · 카카오 · GitHub · Microsoft · Google 등 외부 계정으로 로그인할 수 있게 합니다.
LDAP 과 같은 `identity_providers` 테이블을 쓰지만 `kind` 가 `oauth2` / `oidc` 인 행입니다.

### 등록 절차

1. 제공자 콘솔에서 앱을 만들고 **Redirect URI** 를 등록합니다. 화면 하단에 표시되는 값을 **그대로** 복사하세요.

    ```
    https://<IdP 호스트>/auth/oauth/<slug>/callback
    ```

    네이버·카카오는 **완전 일치**를 요구하므로 로컬 개발용 앱을 따로 만들어야 합니다.

2. `/admin/social-providers` → **제공자 추가** → 종류 선택 후 Client ID / Secret 입력.
3. 저장 직후에는 **비활성** 상태입니다. 설정을 확인한 뒤 편집 화면에서 **활성화**를 체크하세요.

> Client Secret 은 `IDP_SIGNING_KEY_SECRET` 으로 암호화되어 DB 에 저장되며 화면에 다시 표시되지 않습니다.
> 이 환경 변수가 없으면 저장이 거부됩니다(평문 저장 폴백 없음).

### "계정이 없을 때" 옵션

| 값                            | 동작                                                                  | 권장 대상              |
| ----------------------------- | --------------------------------------------------------------------- | ---------------------- |
| **가입 폼으로 보내기** (기본) | 외부 프로필을 채운 `/signup?federated=1` 로 보내 사용자가 가입을 완료 | 일반 소셜 로그인       |
| **자동으로 계정 생성**        | 폼 없이 즉시 생성. 신뢰할 수 있는 이메일이 있을 때만 동작             | 사내 SSO 성격의 제공자 |
| **가입 차단**                 | 사전에 만들어 둔 계정만 로그인 허용                                   | 사전 프로비저닝 조직   |

### 기존 계정 자동 연결

기본적으로 **이메일이 같다는 이유만으로 기존 계정에 연결하지 않습니다.** 제공자가 이메일을 조작하면
관리자 계정까지 탈취될 수 있기 때문입니다. 이 경우 사용자는 기존 방법으로 로그인한 뒤
`/account/connections` 에서 직접 연결합니다.

**"검증된 이메일이면 자동 연결"** 을 켜면 제공자가 이메일 검증을 단언한 경우에 한해 자동 연결됩니다.
이메일 검증을 신뢰할 수 있는 제공자에만 사용하세요. 참고로 Lodestar 이 판단하는 검증 여부는:

| 제공자                | 검증으로 인정하는 조건                                   |
| --------------------- | -------------------------------------------------------- |
| GitHub                | `/user/emails` 의 `verified: true`                       |
| 카카오                | `is_email_valid` **와** `is_email_verified` 가 모두 true |
| Microsoft/Google/OIDC | id_token 의 `email_verified` 가 `true`                   |
| 네이버                | **항상 미검증** — 네이버는 검증 단언을 제공하지 않습니다 |

### 제공자별 주의사항

- **카카오**: 이메일 스코프 `account_email` 은 **비즈 앱 검수**를 통과해야 씁니다. 미승인 상태로 스코프에 넣으면 로그인 자체가 실패합니다. 기본 스코프는 `profile_nickname` 뿐입니다.
- **네이버**: 제공 항목(이메일·닉네임)은 개발자센터에서 별도 승인이 필요하고, 사용자가 동의를 거부하면 값이 아예 오지 않습니다. PKCE 미지원.
- **GitHub**: 이메일을 비공개로 둔 사용자는 `/user` 에 이메일이 없어 `user:email` 스코프가 필요합니다.
- **Microsoft**: 디렉터리 테넌트 기본값은 `common`(모든 Microsoft 계정)입니다. 사내 계정만 허용하려면 디렉터리 GUID 를 입력하세요.

### 사용자 화면

- 로그인 페이지에 활성 제공자 버튼이 자동으로 나타납니다. 커스텀 스킨은 `{{IDP_SOCIAL_BUTTONS}}` 치환자를 넣어야 표시됩니다.
- 사용자는 `/account/connections` 에서 연결/해제할 수 있습니다. **마지막 로그인 수단은 해제할 수 없습니다.**

---

## 7-2. 정보 제공 동의 (consent)

사용자가 어떤 서비스를 **처음 이용할 때** "이 서비스에 아래 정보를 제공할까요" 를 묻습니다. OIDC 와 SAML 둘 다 대상입니다.

### 동작

게이트 체인의 마지막에 놓입니다. 로그인 → 재인증 → 이메일 인증 → 서비스 배정 → **약관** → **동의** 순으로 통과해야 인증 코드(또는 SAML Assertion)가 발급됩니다.

못 미치면 `/consent` 로 보내고, 승인하면 원래 요청으로 되돌아가 체인을 처음부터 다시 통과합니다. 서버에 대기 상태를 쌓지 않으므로 재시도·뒤로가기·탭 중복에 강합니다.

| 프로토콜 | 동의 대상                                                                  |
| -------- | -------------------------------------------------------------------------- |
| OIDC     | 요청 scope ∩ 클라이언트 등록 scope                                         |
| SAML     | SP 의 `allowedAttributes` (미지정 시 `email` · `username` · `displayName`) |

### 필수 / 선택 스코프

OIDC 클라이언트의 **거부 가능 스코프**(`/admin/oidc-clients` 의 optionalScopes)에 적은 항목만 사용자가 체크를 해제할 수 있습니다.

- **비워 두면 요청 scope 전부가 필수** 입니다 — 즉 전체 승인/거부와 같게 동작합니다(기본값).
- `openid` 는 거부 가능으로 지정할 수 없습니다. 등록하지 않은 scope 도 지정할 수 없습니다.
- SAML 에는 선택 항목이 없습니다. SP 가 요구하는 속성을 골라 빼면 SP 쪽이 깨지기 때문입니다.

> **거부된 항목은 발급되지 않습니다.** 인증 코드에 실리는 scope 는 `요청 ∩ 동의` 이므로, 사용자가 체크를 해제한 scope 는 토큰과 UserInfo 에 나가지 않습니다. 화면이 아니라 이 계산이 실제 강제 지점입니다.

### 재동의가 걸리는 때

- **필수 항목이 늘어났을 때.** 새로 늘어난 항목만 강조하고 이미 승인한 것은 접어 보여줍니다.
- RP 가 `prompt=consent` 를 보냈을 때 (강제 재동의).
- 사용자가 계정 화면에서 철회한 뒤 다시 접속했을 때.

**선택 항목이 빠져 있다는 이유만으로는 다시 묻지 않습니다.** 그러지 않으면 `phone` 을 한 번 거부한 사용자에게 매 로그인마다 같은 화면이 뜹니다. 선택 항목을 다시 제안하려면 `prompt=consent` 를 쓰거나 사용자가 철회하면 됩니다.

### prompt 처리

| 요청             | 동의 필요 없음     | 동의 필요                                     |
| ---------------- | ------------------ | --------------------------------------------- |
| (없음)           | 그대로 발급        | `/consent` 로 이동                            |
| `prompt=consent` | `/consent` 로 이동 | `/consent` 로 이동                            |
| `prompt=none`    | 그대로 발급        | `interaction_required` 오류를 redirect_uri 로 |

사용자가 **거부** 하면 OIDC 는 `access_denied`, SAML 은 `RequestDenied` 상태의 서명된 오류 Response 를 돌려줍니다.

### 사용자의 철회

`/account/connections` 의 **동의한 서비스** 목록에서 사용자가 스스로 철회합니다.

- 동의 행은 지우지 않고 철회 표시만 합니다 — "그때 무엇에 동의했는가" 를 나중에 답할 수 있어야 합니다.
- 그 클라이언트의 **refresh token 을 폐기** 해 갱신 경로를 끊습니다. 이미 발급된 access token 은 만료까지 유효합니다(즉시 무효화가 필요하면 RP 가 introspection 을 써야 합니다).
- 세션은 끊지 않습니다 — 다른 RP 로 이미 로그인한 세션을 함께 날리는 것은 과합니다.

### 감사 로그

`consent_granted` · `consent_denied` · `consent_revoked` 로 남습니다. `consent_granted` 의 detail 에는 승인 목록과 **거부한 선택 항목**이 함께 들어갑니다.

### 화면 커스터마이즈

`consent` 스킨 타입으로 교체할 수 있습니다. 치환자는 `{{IDP_CLIENT_NAME}}` · `{{IDP_REQUIRED_SCOPES}}` · `{{IDP_OPTIONAL_SCOPES}}` 이고, 선택 항목 체크박스는 `name="optionalScope"` 로 항목마다 반복 전송합니다.

---

## 7-3. 약관 관리 (`/admin/terms`)

약관 문서를 작성·발행하고, 어떤 앱에서 노출할지 지정합니다.

### 문서

| 필드             | 설명                                                                                               |
| ---------------- | -------------------------------------------------------------------------------------------------- |
| `key`            | 개정을 가로지르는 안정 식별자 (`service`, `privacy`, `marketing`). 영문·숫자·점·밑줄·하이픈 1~64자 |
| `version`        | 정수. **올리면 기존 동의자에게 재동의가 걸립니다**                                                 |
| `locale`         | `ko` / `en`. 요청 로케일이 없으면 `ko` 로 폴백합니다                                               |
| `title` · `body` | 본문은 마크다운 부분집합                                                                           |
| `required`       | 필수 약관은 거부하면 진행할 수 없습니다. 선택은 거부해도 통과합니다                                |
| `displayOrder`   | 화면 표시 순서                                                                                     |

`(tenant, key, version, locale)` 이 유니크입니다. `key` 와 `version` 은 만든 뒤 **바꿀 수 없습니다** — 동의 기록이 그 둘을 가리키므로, 나중에 바꾸면 이미 받은 동의가 어떤 문서에 대한 것인지 알 수 없게 됩니다. 개정은 version 을 올린 **새 문서**를 만드는 것입니다.

### 본문 서식

지원 범위는 다음과 같고, 그 밖의 HTML 은 제거됩니다(이스케이프를 먼저 하고 서식을 얹으므로 원본 태그가 살아남지 않습니다).

```
## 제목            → 소제목
**굵게**
- 목록
[문구](https://…)  → 링크 (http/https 만)
빈 줄              → 단락 구분
```

### 발행

새로 만든 문서는 **초안**이고 사용자에게 노출되지 않습니다. 본문을 다 쓴 뒤 **발행** 을 눌러야 대상이 됩니다.

> 발행하는 순간 대상 사용자에게 동의 요구가 걸립니다. 필수 약관이면 동의 전까지 서비스 이용이 막히므로, 문안이 확정된 뒤에 누르세요. `terms_document_published` 로 감사에 남습니다.

### 앱별 노출 (전역 vs 앱)

| 매핑 상태   | 언제 요구되는가                             |
| ----------- | ------------------------------------------- |
| 매핑 없음   | **전역 약관** — 로그인 직후 모든 사용자에게 |
| 앱에 매핑됨 | 그 앱으로 SSO 할 때만                       |

매핑은 문서 id 가 아니라 `key` 로 걸리므로 개정할 때 다시 걸 필요가 없습니다. 하나의 key 를 여러 앱에 매핑할 수 있고, 한 앱에 여러 약관을 걸 수도 있습니다.

전역 약관은 **모든 진입 경로**(비밀번호·MFA·소셜·패스키·초대)에서 걸립니다. 로그인 완료 지점마다 검사를 심는 대신 모든 페이지 이동이 지나가는 자리에서 한 번 보기 때문에, 새 약관을 발행하면 이미 로그인해 있던 세션도 다음 이동에서 걸립니다.

### 동의 기록

`(user, key, version)` 단위로 남고, **거부도 기록** 합니다 — 그래야 "물어봤지만 거부했다" 와 "아직 안 물어봤다" 를 구분해 선택 약관을 매번 다시 묻지 않습니다. 어떤 로케일의 본문을 보고 동의했는지도 함께 남습니다.

이전 version 기록은 지우지 않습니다. `terms_agreed` 감사 이벤트에 승인·거부 목록이 `key@version` 형태로 들어갑니다.

### 화면 커스터마이즈

`terms` 스킨 타입으로 교체할 수 있습니다. 항목 체크박스는 `name="termsKey"` 로 반복 전송합니다.

---

## 8. 서명키 회전 (`/admin/signing-keys`)

OIDC/SAML 토큰 서명에 쓰이는 **RSA 서명키**를 생성·회전합니다.

- 목록: `kid`, alg(RS256), 용도(use), **활성 여부(active)**, 인증서 보유 여부, 생성/회전/만료 시각.
- **회전(rotate)** 액션 한 번으로:
    1. 새 RSA 키 + 자체서명 인증서 생성(CN = issuer 호스트명, 없으면 `idp.local`).
    2. 기존 활성 키를 비활성화하고 새 키를 활성으로 **원자적(atomic)** 전환.
    3. partial unique index 로 **"동시에 활성 키는 항상 1개"** 불변식을 DB 레벨에서 보장(동시 회전 충돌 시 409 `rotate_conflict`).
    4. 로컬 캐시/JWKS 캐시 무효화(다른 isolate 는 캐시 TTL 만료로 수렴).
- 새 키의 private JWK 는 **`IDP_SIGNING_KEY_SECRET`** 로 래핑(AES-256-GCM)되어 저장됩니다. 따라서 이 시크릿이 없으면 회전이 503 으로 실패합니다.
- 공개키는 `/oidc/jwks` 로 노출됩니다.

> **중요(혼동 주의)**: 이 화면의 "서명키 rotate" 는 **현재 `IDP_SIGNING_KEY_SECRET` 을 그대로 사용해 새 RSA 서명키를 만드는 것**입니다. 마스터 시크릿(`IDP_SIGNING_KEY_SECRET`) 자체의 회전과는 별개입니다. 마스터 시크릿 회전(무중단 절차, `IDP_SIGNING_KEY_SECRET_PREVIOUS` 병기, 재암호화 배치)은 **[docs/SECRET_ROTATION.md](./SECRET_ROTATION.md)** 를 따르세요.

---

## 8-1. 서비스 API 토큰 (`/admin/service-tokens`)

service-to-service 호출(`/api/totp/*`, `/api/users/lookup`)에 쓰는 Bearer 토큰을 **호출자별로**
발급합니다.

- **발급**: 이름(호출자 식별용) + 스코프 체크박스 + 만료(선택). 생성 직후 **평문이 한 번만**
  표시됩니다 — DB 에는 해시만 저장되므로 잃어버리면 재발급밖에 없습니다.
- **스코프**: `totp.verify` / `totp.status` / `totp.enroll` / `users.lookup`. 정확히 일치하는
  스코프를 가진 토큰만 해당 엔드포인트를 호출할 수 있습니다. **필요한 것만 주세요** — 예를 들어
  OTP 검증만 위탁하는 콘솔에는 `totp.verify` 하나면 충분하고, 그러면 그 토큰이 유출돼도
  2단계를 새로 등록하거나 사용자 목록을 조회할 수 없습니다.
- **폐기**: 행을 삭제합니다. 그 토큰을 쓰던 호출자는 즉시 401 을 받습니다. 이력은 감사 로그
  (`service_api_token_created` / `_revoked`)에 남습니다.
- **마지막 사용**: 5분 간격으로 갱신됩니다(승인 경로에 매 호출 쓰기를 얹지 않기 위함). "쓰이지
  않는 토큰" 을 찾아 정리하는 용도로 보세요.

> `DISPATCHER_SERVICE_TOKEN` 환경변수는 이 목록에 나오지 않으며 **모든 스코프**를 가집니다.
> 기존 호출자 무중단을 위한 레거시 경로이므로, 전부 옮긴 뒤 제거하는 것이 좋습니다.

---

## 9. 감사 로그 조회 (`/admin/audit`)

- 컬럼: 시각, **kind**(이벤트 종류), **outcome**(success/failure), IP, 사용자 이메일(연결된 경우), 상세(JSON).
- 필터:
    - **kind**: 실제 존재하는 kind 목록에서 선택.
    - **outcome**: `success` / `failure`.
- 페이징: 최신순 **50건**씩, 커서(마지막 행의 생성시각 기준) 기반 "더 보기".
- 감사 이벤트 행에는 무결성 MAC(`hash`)이 포함됩니다(위변조 탐지용, `IDP_SIGNING_KEY_SECRET` 기반).

주요 kind 예: `login`, `user_created` / `user_invited` / `user_deleted`, `user_status_changed` / `user_role_changed`, `password_reset`, `oidc_client_*`, `saml_sp_*`, `service_role_*`, `service_entitlement_*`, `user_entitlement_revoked`, `service_api_token_created` / `_revoked`, `service_token_rejected`, `signing_key_rotated`, `ldap_provider_*`, `user_deletion_requested` / `user_deletion_cancelled`.

---

## 10. 사용자 운영 흐름 (`/admin/users`)

목록은 최신순 50건 페이징 + 검색(이메일/아이디/표시이름 부분일치, 대소문자 무시). 유효한 미사용 초대 토큰을 가진 계정에는 **"초대중"** 배지가 붙습니다.

### 관리자 작업

| 작업                               | 동작                                                                                                                                     |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **생성(create)**                   | 이메일+비밀번호(8자 이상) 즉시 계정 생성. 이메일/아이디 중복 시 409.                                                                     |
| **초대(invite)**                   | 비밀번호 없이 계정 선생성(status=active, 이메일 미인증) 후 **초대 메일** 발송. 수락 시 최초 비밀번호 설정.                               |
| **상태 변경(updateStatus)**        | active/disabled/locked. 비활성/잠금 전환 시 **기존 세션 즉시 파기** + 보안 알림 메일. 자기 자신 비활성화 및 **마지막 관리자 보호** 차단. |
| **역할 변경(updateRole)**          | admin ↔ user. **자기 역할 변경 불가**, admin→user 강등 시 마지막 관리자 보호. 변경 시 세션 파기.                                         |
| **비밀번호 초기화(resetPassword)** | 관리자가 새 비밀번호(8자 이상) 설정. 대상 사용자 **전 세션 파기** + 알림 메일.                                                           |
| **삭제(delete)**                   | 계정 하드 삭제. 자기 삭제 불가, 마지막 관리자 보호.                                                                                      |

- 개별 사용자 상세(`/admin/users/[id]`)에서 프로필/조직 소속/서비스 권한/강제 로그아웃까지 관리합니다(2·4장 참조).

### 이메일 인증 (self-service)

- 가입/재발송 시 인증 토큰 발급 + 메일 발송(`/verify-email?token=...`). 토큰 유효기간 **24시간**.
- `IDP_ISSUER_URL` 미설정이면 host header injection 방지를 위해 메일 발송을 스킵합니다.

### 초대 수락 (self-service)

- 초대 링크(`/accept-invite?token=...`) 유효기간 **72시간**. 수락 시 사용자가 최초 비밀번호를 설정하며 토큰이 소비(used)됩니다.

### 계정 삭제 유예 (self-service, `/account/danger-zone`)

- 사용자 본인이 탈퇴를 요청하면:
    1. **step-up 재인증**(비밀번호 또는 TOTP) 필수 — 세션 탈취자에 의한 삭제 방지.
    2. **마지막 관리자 자기삭제 차단**.
    3. 계정을 **`status=deletion_pending` + `deletionScheduledAt`(now+30일)** 로 소프트 삭제. 전 세션·refresh token 즉시 폐기 후 로그아웃. 접수 알림 메일 발송.
- **복구(유예 내)**: 유예 30일 안에 다시 로그인하면 복구 확인 프롬프트가 뜨고, 비밀번호 재입력으로 확정하면 계정이 `active` 로 환원됩니다(`user_deletion_cancelled`).
- **유예 경과**: `deletionScheduledAt` 이 지난 계정은 로그인 거부되고, **GC 가 하드 삭제**합니다(감사 로그·복구 불가).

---

### 참고 문서

- 마스터 시크릿 회전 절차: [docs/SECRET_ROTATION.md](./SECRET_ROTATION.md)
