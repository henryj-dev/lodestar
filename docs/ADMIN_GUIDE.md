# KeyStone 관리자 운영 매뉴얼

KeyStone(멀티테넌트 IdP)의 관리 콘솔 운영 가이드입니다. 각 화면에서 관리자가 무엇을 클릭하고 어떤 일이 일어나는지를 실무 관점에서 정리했습니다.

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
- `/admin/login` 만 예외적으로 비인증 접근 허용.

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
- **allowedAttributes**: 콤마 구분. 허용 키 화이트리스트(`email`, `username`, `displayName`, `givenName`, `familyName`, `surName`, `phoneNumber`, `department`, `team`, `jobTitle`, `position`, `Role`, `RoleLabel`, `Entitlements`)에 없는 값은 무시됩니다.
    - **미설정 시 기본값은 `email`, `username`, `displayName` 뿐입니다.** 조직 정보와 서비스 권한(`Role` / `RoleLabel` / `Entitlements`)은 여기에 **명시적으로 넣어야** 나갑니다. 권한을 정의·배정했는데 SP 가 못 받는다면 이 목록부터 확인하세요.
    - `Role` / `RoleLabel` / `Entitlements` 는 인가 판정에 쓰이는 값이라, 사용자별 추가 속성(`attributesJson`)으로 **덮어쓸 수 없습니다**(위조 방지).
- 보안 설정 변경(특히 **cert / acsUrl / wantAuthnRequestsSigned**)은 ACS 하이재킹 포렌식을 위해 before/after diff 가 감사 로그(`saml_sp_updated`)에 상세 기록됩니다.

### 상세 (`/admin/saml-sps/[id]`)

- OIDC 클라이언트와 동일하게 **서비스 role · entitlement** 를 정의(key/label/description/isDefault/displayOrder). 4장 참조.
- 정의한 entitlement 가 Assertion 에 실리려면 SP 의 **allowedAttributes 에 `Entitlements` 가 있어야** 합니다(위 "생성 / 수정" 참조).

### 메타데이터

- IdP 측 SAML 메타데이터는 `/saml/metadata` 에서 제공됩니다(SP 설정 시 참조).

---

## 7. 스킨(커스텀 로그인 UI) 등록 (`/admin/skins`)

외부에 호스팅한 HTML 을 가져와 로그인/가입 등 인증 화면을 클라이언트별로 커스터마이즈합니다. 사용법 안내는 **`/admin/skins/guide`** 에서 확인할 수 있습니다.

### 등록 필드

- **대상 클라이언트**: `clientType`(oidc/saml) + `clientRefId`.
- **스킨 타입(`skinType`)**: `login` / `signup` / `find_id` / `find_password` / `mfa` / `reset_password`.
- **Fetch URL**: 스킨 HTML 을 가져올 URL. **https 필수**, loopback/내부주소(127.x, link-local) 금지(SSRF 방지).
- **Fetch Secret**: 스킨 서버 인증용 시크릿. IdP 가 스킨 HTML 을 가져올 때 **`X-IDP-Token`** 헤더로 이 값을 전송하므로, 스킨 서버는 이 헤더를 검증해 접근을 통제할 수 있습니다(선택).
- **캐시 TTL(`cacheTtlSeconds`)**: 기본 3600초, 0 이상, **최대 86400초(1일)**.

### 운영

- **수정 / 삭제 / 활성화 토글 / 캐시 무효화(`invalidateCache`)** 지원. URL·TTL 변경이나 삭제 시 캐시가 자동 무효화됩니다.
- 같은 (클라이언트, 스킨타입) 조합 중복 등록 시 409.

### 치환자(placeholder)

스킨 HTML 안에서 `{{...}}` 형태로 사용하며, IdP 가 렌더링 시 값을 채웁니다. **총 6개**이고, 스킨 타입별 적용 범위가 다릅니다.

| 치환자                   | 채워지는 값                                                                                    | 적용 스킨                                                                          |
| ------------------------ | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `{{IDP_FORM_ACTION}}`    | 항상 빈 문자열 `""`(비어 있으면 폼이 **현재 URL로 POST**)                                      | 모든 스킨 공통                                                                     |
| `{{IDP_REDIRECT_TO}}`    | `escapeHtml(redirectTo ?? "")` — hidden input 용                                               | **login / signup / reset_password** 에서 채워짐. find_id·find_password·mfa 는 `""` |
| `{{IDP_SKIN_HINT}}`      | `escapeHtml(skinHint)` — hidden input 용(어떤 스킨을 쓸지 서버에 되전달)                       | 모든 스킨 공통                                                                     |
| `{{IDP_REGISTERED}}`     | 회원가입 완료 직후 `"1"`, 그 외 `""`(가입 완료 안내 노출용)                                    | **login 전용**                                                                     |
| `{{IDP_PASSWORD_RESET}}` | 비밀번호 재설정 완료 직후 `"1"`, 그 외 `""`(재설정 완료 안내 노출용)                           | **login 전용**                                                                     |
| `{{IDP_FLASH_MSG}}`      | `escapeHtml(flashMsg)` — 서버가 채우는 플래시/오류 메시지(이미 HTML 이스케이프됨). 없으면 `""` | 모든 스킨 공통(폼 재제출 오류 표시)                                                |

> **필수 hidden input**: `login` 스킨의 `<form>` 에는 최소한 `redirectTo`(값 `{{IDP_REDIRECT_TO}}`)와 `skinHint`(값 `{{IDP_SKIN_HINT}}`) hidden input 및 `username`/`password` 입력이 있어야 정상 동작합니다. 폼 `action` 은 `{{IDP_FORM_ACTION}}`(빈 값=현재 URL POST)으로 둡니다.

### 캐시 동작

- 가져온 스킨 HTML 은 TTL 동안 캐시됩니다. 스킨을 갱신했는데 즉시 반영이 필요하면 콘솔의 **캐시 무효화** 버튼을 사용하세요.

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
