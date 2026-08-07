# `IDP_SIGNING_KEY_SECRET` 회전 절차

> 작성: 2026-07-06 / 갱신: 2026-08-07 (access-token HMAC 이 HKDF 파생 서브키로 전환된 것을 반영).
> 코드 기준: `src/lib/server/crypto/keys.ts`, `auth/runtime.ts`, `auth/totp.ts`, `auth/mfa.ts`, `auth/webauthn.ts`, `audit/index.ts`.
>
> **무중단(zero-downtime) 회전이 지원된다.** `IDP_SIGNING_KEY_SECRET_PREVIOUS` 에 old
> 시크릿을 병기하면, 모든 복호/검증 경로가 current→previous 순차로 시도(`tryWithSecrets`)
> 하므로 재암호화 창 동안에도 요청이 실패하지 않는다. **발급/암호화(토큰 서명, private key
> 래핑, 시크릿·TOTP 암호화, 쿠키·audit 서명)는 항상 current(`IDP_SIGNING_KEY_SECRET`)만
> 사용**하므로, 회전 후 새로 쓰이는 데이터는 곧바로 new 시크릿으로 저장된다.

## 1. 이 시크릿이 쓰이는 곳 (7용도)

| #   | 용도                                  | 방식                                                                  | 저장 데이터                                                  | 근거                     |
| --- | ------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------ | ------------------------ |
| 1   | OIDC/SAML 서명용 RSA private JWK 래핑 | HKDF(`idp-signing-key-wrap-v1`) → AES-256-GCM                         | `signing_keys.private_jwk_encrypted` (활성 행만 런타임 사용) | `crypto/keys.ts:37-69`   |
| 2   | Opaque access token 서명/검증         | HKDF(`idp-access-token-hmac-v1`) → HMAC-SHA256 서브키                 | 저장 없음 (TTL 300초)                                        | `crypto/keys.ts:255-288` |
| 3   | LDAP admin bind password 암호화       | HKDF(`idp-ldap-bind-password-v1`) → AES-256-GCM                       | `identity_providers.config_json` 내 `bindPasswordEnc`        | `crypto/keys.ts:258-280` |
| 4   | TOTP seed 암호화                      | HKDF(v2: `idp-totp-secret-wrap-v2:<userId>`, v1 레거시) → AES-256-GCM | `credentials.secret` (type='totp')                           | `auth/totp.ts:99-175`    |
| 5   | MFA pending 쿠키 서명                 | 원문 HMAC                                                             | 저장 없음 (쿠키, TTL 5분)                                    | `auth/mfa.ts:44-92`      |
| 6   | WebAuthn challenge 쿠키 서명          | 원문 HMAC                                                             | 저장 없음 (쿠키, TTL 5분)                                    | `auth/webauthn.ts:28-58` |
| 7   | 감사 로그 행 무결성 MAC               | 원문 HMAC                                                             | `audit_events.hash` (평문 필드에 대한 MAC — 암호화 아님)     | `audit/index.ts:93-124`  |

## 2. 회전 시 영향 분류

**A. 자연 해소(조치 불필요)** — 발급된 access token(최대 5분 내 만료), MFA pending·WebAuthn challenge 쿠키(5분, 재시도로 해소). `oidc_refresh_tokens`는 이 시크릿과 무관(랜덤 토큰 + SHA-256 해시)이라 영향 없음.

> access token 은 `IDP_SIGNING_KEY_SECRET_PREVIOUS` 병기 여부와 무관하게, HKDF 서브키 검증 실패 시 **레거시 raw-key 폴백 검증**도 시도한다(R10 전환기 하위호환, `deriveLegacyHmacKey`). 신규 서명은 항상 HKDF 서브키만 쓴다.

**B. 재암호화 필수(누락 시 장애)** — 아래 3종은 old secret으로 복호해 new secret으로 재암호화하지 않으면 **영구 복호 불가**:

| 데이터                                                                                 | 미조치 시 증상                                                                   |
| -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `signing_keys` 활성 행(`active=true AND rotated_at IS NULL`)의 `private_jwk_encrypted` | unwrap 예외(try/catch 없음) → OIDC 토큰 발급·SAML SSO 전면 500                   |
| `credentials.secret` (TOTP 전량)                                                       | `api/totp/verify` 500 → TOTP 사용자 전원 MFA 로그인 불가                         |
| `identity_providers.config_json.bindPasswordEnc` (LDAP)                                | 복호 실패는 try/catch로 흡수되나 bind 자격증명 부재 → 해당 LDAP 로그인 전부 실패 |

**C. 선택 후처리** — `audit_events.hash`: 원본 평문이 DB에 있으므로 new secret으로 전량 재계산 가능(전용 스크립트는 현재 없음). 재계산하지 않으면 향후 무결성 검증 시 old-secret 시절 행이 전부 오탐된다.

## 3. 무중단 회전 절차 (순서 엄수)

핵심: **new 를 current 로 먼저 배포하고 old 를 PREVIOUS 로 병기** → 이 상태에서는 old·new 로
암호화된 데이터가 모두 복호되고(fallback), 새 데이터는 new 로만 저장된다. 재암호화 후 PREVIOUS
를 제거한다. 어느 시점에도 요청 실패 창이 없다.

1. **준비**: 새 secret 생성(고엔트로피 256bit 이상).
2. **PREVIOUS 병기 + new 배포** (fallback 활성화):
    - `IDP_SIGNING_KEY_SECRET` = **new**, `IDP_SIGNING_KEY_SECRET_PREVIOUS` = **old** 로 설정 후 재배포.
    - Workers: `wrangler secret put IDP_SIGNING_KEY_SECRET` / `... IDP_SIGNING_KEY_SECRET_PREVIOUS`.
    - Node: 두 환경변수를 설정 후 재시작.
    - 이 시점부터 발급/암호화는 new 로, 복호/검증은 new→old 순차로 처리된다(무중단).
3. **재암호화 배치 실행** (`scripts/reencrypt-secrets.ts`): old(PREVIOUS)로 복호 → new 로 재암호화.
    - 대상: `signing_keys` 활성 행 `private_jwk_encrypted`, `credentials` type='totp' `secret`,
      `identity_providers` kind='ldap' `config_json.bindPasswordEnc`.
    - 먼저 **dry-run**(기본): `IDP_SIGNING_KEY_SECRET_PREVIOUS=<old> IDP_SIGNING_KEY_SECRET=<new> DB_DIALECT=... DATABASE_URL=... bun scripts/reencrypt-secrets.ts`
      → 대상 건수만 보고, DB 미변경.
    - 확인 후 **적용**: 동일 명령에 `--apply` 추가 → DB 쓰기.
    - 멱등: 이미 new 로 재암호화된 행은 "already"로 건너뛴다(반복 실행 안전). old/new 둘 다 복호 실패
      행은 error 로 집계(종료코드 2)하되 배치는 계속 진행한다.
    - (프로젝트 규칙상 이 스크립트는 원격 DB 를 변경하므로 자동 실행하지 않는다 — 운영자가 직접 실행.)
4. **스모크 테스트**: `/oidc/token` 발급, `/saml/sso` 서명, TOTP 로그인, LDAP 로그인, JWKS(`/oidc/jwks`) kid 노출 확인.
5. **PREVIOUS 제거로 회전 마무리**: `IDP_SIGNING_KEY_SECRET_PREVIOUS` 삭제 후 재배포. old 로만 복호되던
   데이터는 3단계에서 모두 new 로 재암호화되었으므로 이제 old 는 불필요하다.
6. **old secret 파기**.

> **`audit_events.hash` 재계산은 이번 범위 밖(수동 절차)**이다. audit hash 는 발급(생성) 전용이라
> fallback 이 없고, current(new)로 계산된다. 회전 후 무결성 검증 시 old 시절 행이 오탐되지 않게 하려면
> 원본 평문(모두 DB 에 존재)으로 new 시크릿으로 전량 재계산하는 별도 배치가 필요하다 — 필요 시 수동으로 수행한다.

## 4. 알려진 한계 / 개선 여지 (별도 트랙)

- 쿠키·audit 서명(#5,#6,#7)이 아직 파생 없이 마스터 시크릿 원문을 HMAC 키로 공유한다. access-token HMAC(#2)은 HKDF 도메인 분리로 전환됐으므로, 같은 방식으로 통일하면 용도별 노출 반경이 더 줄어든다.
- `audit_events.hash` 재계산 전용 배치가 아직 없다(위 3절 주석 참조).
- admin 콘솔의 "서명키 rotate" 액션은 **현재 secret으로 새 서명키를 만드는 것**이지 이 마스터 시크릿 회전과 무관하다 — 혼동 주의.
