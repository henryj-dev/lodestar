# KeyStone 외부 접근 취약점 전수 검사 레포트

> **이 문서는 2026-07-20 감사 시점의 기록입니다.** 조치 내역(F1~F14)은 그대로 유효하지만,
> 그 이후 코드가 더 움직였으므로 아래 "이후 변경" 을 함께 읽으세요. (최종 확인: 2026-08-07)
>
> **이후 변경 (2026-07-20 이후)**
>
> - **비밀번호 해시가 argon2id → scrypt 로 전환**되었습니다(`node:crypto`, N=2^15·r=8·p=3).
>   §5 의 "열거 방어(균일 응답+scrypt 균등화)" 서술은 현행과 맞고, 순수 JS argon2 의 ~4.4초
>   verify 비용이 사라졌습니다. 레거시 argon2id/PBKDF2 해시는 로그인 시 자동 업그레이드됩니다.
> - **서비스 권한 모델(`entitlements`)이 추가**되었습니다. `roles` 와 직교하는 인가 축이며
>   id_token·userinfo 로 발행되고, 변경 시 `role_change_uri` 로 SET 을 POST 합니다 —
>   **이 감사에는 포함되지 않은 신규 표면**이므로 다음 감사 대상입니다.
> - **서비스 API 토큰이 DB 발급형으로 전환**되었습니다(`/admin/service-tokens`, 스코프 제한).
>   §1 인벤토리의 "Bearer 서비스 토큰" 은 이제 `DISPATCHER_SERVICE_TOKEN`(전 스코프 레거시)과
>   발급 토큰 두 갈래입니다. F1 의 실패 throttle·감사 이벤트는 양쪽에 그대로 적용됩니다.
> - **테스트 규모**: 본문의 245·247·251·257개 표기는 당시 수치입니다. 현재는 **36 파일 340 테스트**.
> - §6 "운영 후속" 의 마이그레이션 적용 상태는 그 시점 기준입니다. 현재 적용 여부는 배포 환경에서
>   직접 확인하세요.
>
> 미채택으로 남은 R1(회원가입 계정 열거)·R9(admin Zod `.strict()`) 결론은 **그대로 유효**합니다.

- **일자**: 2026-07-20
- **대상**: KeyStone (SvelteKit 기반 OIDC / SAML Identity Provider)
- **방식**: 6개 도메인 병렬 심층 코드 감사 + 메타 레벨(CSRF 커버리지, CSP, 시크릿 노출, IP 신뢰) 직접 점검
- **총평 위험도**: **LOW** — 이미 여러 라운드의 보안 하드닝(`ctrls H-AUTH-1`, `H-ADMIN-3`, `C6` 등 주석)을 거친 코드베이스. **Critical / High 0건.**

---

## 1. 공격 표면 (엔드포인트 인벤토리)

| 그룹    | 엔드포인트                                                                                                          | 인증 방식                                     | CSRF                                                     |
| ------- | ------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | -------------------------------------------------------- |
| OIDC    | `authorize`, `token`, `userinfo`, `introspect`, `revoke`, `jwks`, `end-session`, `.well-known/openid-configuration` | client_secret / PKCE / Bearer / id_token_hint | 프로토콜 자체 인증(skip), end-session만 origin+Sec-Fetch |
| SAML    | `sso`, `slo`, `metadata`                                                                                            | 서명 XML / SP cert                            | 프로토콜 자체 인증(skip)                                 |
| 인증    | `login`, `signup`, `find-id`, `find-password`, `reset-password`, `verify-email`, `accept-invite`, `mfa`, `logout`   | 세션 쿠키 / 토큰                              | hook origin 검사                                         |
| API     | `health`, `skin-scripts`, `users/lookup`, `totp/*`, `webauthn/*`                                                    | Bearer 서비스 토큰 / 세션                     | totp·users=Bearer(skip), webauthn=origin                 |
| Admin   | `admin/*` (users, oidc-clients, saml-sps, ldap-providers, signing-keys, audit 등)                                   | 세션 + `role==="admin"` + 강제 TOTP           | hook origin 검사                                         |
| Account | `account/*` (profile, sessions, mfa, passkeys, danger-zone, confirm-email-change)                                   | 세션 (본인 소유 scoped)                       | hook origin 검사                                         |

---

## 2. SQL 인젝션 및 기타 인젝션 — 전수 확인 결과

- **SQL 인젝션**: DB 계층은 Drizzle ORM 파라미터라이즈드 쿼리만 사용. `sql.raw` / 문자열 결합으로 사용자 입력을 SQL 에 넣는 지점 **없음**. 4개 방언(d1/sqlite/postgres/mysql) 드라이버 모두 확인. → **표면 없음.**
- **LDAP 인젝션**: username RFC 4515 filter / RFC 4514 DN 이스케이프 후 치환(`ldap/auth.ts`). → 방어됨.
- **XML 인젝션 / XXE / XSW (SAML)**: DOCTYPE·ENTITY 거부, 크기 캡, 서명은 소비되는 엘리먼트에 대해서만 검증, KeyInfo 신뢰 배제, ACS 핀 고정. → 방어됨.
- **XSS**: hash 기반 CSP(`unsafe-inline` 스크립트 없음) + skin HTML은 HTMLRewriter 서버 sanitize + `{@html}` 이전 escape 이중 방어. → 스크립트 XSS 차단.
- **오픈 리다이렉트**: `sanitizeRedirectTarget`(double-decode, `//`·`\`·제어문자 거부, same-origin 검증) 전 리다이렉트 sink 적용. → 방어됨.
- **이메일 헤더 인젝션**: 모든 사용자 값 escape, URL 스킴 검증. → 방어됨.

---

## 3. 보완 조치 완료 (이번 커밋에 적용)

모두 `svelte-check`(0 errors) · `eslint`(0) · `prettier` · 전체 테스트 257개 통과로 검증됨.

| #   | 심각도             | 항목                                                                                                        | 파일                                                                                                                                               | 조치                                                                                                                                                                                                                                                                                                               |
| --- | ------------------ | ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| F1  | Medium             | 서비스 토큰 인증 실패가 레이트리밋·감사로그 없이 무한 추측 가능                                             | `src/lib/server/auth/service-token.ts` (+호출부 5)                                                                                                 | 실패 경로에 IP 단위 실패 throttle(5분/20회, 정상 트래픽 무영향)과 `service_token_rejected` audit 이벤트 추가                                                                                                                                                                                                       |
| F2  | Low                | `/api/totp/enroll/init` 레이트리밋 부재 + 존재/등록상태 oracle                                              | `src/routes/api/totp/enroll/init/+server.ts`                                                                                                       | `confirm` 과 동일한 사용자당 레이트리밋(5분/10회) 추가                                                                                                                                                                                                                                                             |
| F3  | Low                | CSRF origin 검사가 `/verify-email`·`/accept-invite` 에 미적용                                               | `src/hooks.server.ts`                                                                                                                              | `CSRF_PROTECTED` 에 두 라우트 추가                                                                                                                                                                                                                                                                                 |
| F4  | Medium             | 세션·MFA·신뢰기기 쿠키 `Secure` 가 관측 protocol 에만 의존(adapter-node+TLS 종단 프록시에서 평문 전송 위험) | `session.ts`, `trusted-device.ts`, `(auth)/login/+page.server.ts`                                                                                  | 프로덕션 빌드(`!dev`)에서는 protocol 무관하게 `Secure` 강제                                                                                                                                                                                                                                                        |
| F5  | Low                | SAML `metadata.ts` `xmlEscape` 가 apostrophe·제어문자 미처리(다른 SAML 모듈과 불일치)                       | `src/lib/server/saml/metadata.ts`                                                                                                                  | `response.ts`/`slo.ts` 와 동일 정책(5 entity + 제어문자 제거)으로 통일                                                                                                                                                                                                                                             |
| F6  | Low                | account 프로필 자유 텍스트 필드 길이 무제한(저장소 팽창/claim 전파)                                         | `account/profile/+page.server.ts`, `i18n/{ko,en}.json`                                                                                             | 필드별 길이 상한 검증 + `profile.err_field_too_long` 메시지 추가                                                                                                                                                                                                                                                   |
| F7  | Medium(런타임 Low) | dev/build 의존성 CVE 5건(esbuild/postcss/brace-expansion/cookie)                                            | `package.json`, `bun.lock`                                                                                                                         | `bun update` + `overrides`(cookie≥0.7 / esbuild≥0.25 / brace-expansion≥5.0.6) 로 **`bun audit` 0건** 달성. 빌드·타입체크·245 테스트 전부 통과 검증                                                                                                                                                                 |
| F8  | Medium             | SAML SP 인증서 유효기간(notBefore/notAfter) 미검증                                                          | `saml/cert-validity.ts`(신규), `verify-xml-signature.ts`, `parse-authn-request.ts`, `encrypt.ts`, `.env.example`                                   | 서명검증·암호화 3지점에 유효기간 검증 추가. **기본 on 강제**, `IDP_ENFORCE_SP_CERT_VALIDITY=false` 로만 완화. 만료/미유효 거부 테스트 2건 추가(전체 247개 통과)                                                                                                                                                    |
| F9  | Low(설계 개선)     | R6 이메일 미인증 로그인 — 전역 대신 **서비스(RP)별** 강제 옵션 신설                                         | `db/schema.{sqlite,pg,mysql}.ts`, `drizzle/*`, `oidc/authorize`, `saml/sso`, admin `oidc-clients`/`saml-sps`(server+svelte), `i18n`, harness+tests | oidcClients·samlSps 에 `requireVerifiedEmail`(기본 false) 컬럼 추가. authorize=미인증 시 `access_denied(email_verification_required)`, sso=403 으로 거부. admin 토글 + 마이그레이션(4방언) 생성. 거부/허용 테스트 4건 추가(전체 251개 통과). `email_verified` 클레임 전파는 이미 정상이라 RP 자체 판단과 병행 가능 |
| F10 | Low(R8)            | SAML 미서명 AuthnRequest 허용 → forced-SSO(login-CSRF)                                                      | `db/schema.{sqlite,pg,mysql}.ts`, `drizzle/*`, admin `saml-sps/+page.svelte`                                                                       | 신규 SP 는 서명된 AuthnRequest 요구를 기본값으로(secure-by-default): 스키마 default true(3방언) + admin 생성폼 체크박스 기본 체크. 마이그레이션 생성(pg/mysql=ALTER, sqlite/d1=테이블 재생성). 현재 SP 가 없어 무손실                                                                                              |
| F11 | Low(R4)            | public 클라이언트가 introspect 무인증 호출 → 토큰 메타데이터 노출                                           | `oidc/introspect/+server.ts`                                                                                                                       | `auth_method="none"` client 는 introspect 를 항상 `{active:false}` 로 응답(존재 oracle 차단). revoke(RFC 7009)는 public client 도 자기 토큰 폐기가 정상이라 그대로 둠                                                                                                                                              |
| F12 | Low(R7)            | SSRF 리터럴-호스트 검사만 — DNS 리바인딩 잔여                                                               | `validation.ts`(신규 `assertResolvedHostAllowed`), `oidc/logout.ts`, `oidc/role-change.ts`, `skin/resolver.ts`                                     | webhook·skin fetch 직전 `node:dns` resolve4/resolve6 로 실호스트 해석 후 내부 IP 면 차단(완화). 해석 실패는 fail-open. TOCTOU 로 원천 차단은 아님(완화)                                                                                                                                                            |
| F13 | Low(R10)           | access-token HMAC 이 마스터 시크릿을 raw 키로 직접 사용(키 분리 부재)                                       | `crypto/keys.ts`, `crypto-keys.test.ts`                                                                                                            | HMAC 키를 HKDF(salt/info 도메인분리) 파생 서브키로 전환. **전환기 하위호환**: legacy raw-key 로 서명된 미만료 토큰도 폴백 검증 → 무중단. 하위호환·키분리 테스트 추가                                                                                                                                               |
| F14 | Low(R5)            | 유출 비밀번호 스크리닝 없음                                                                                 | `auth/breach-check.ts`(신규), signup·reset-password·accept-invite, `i18n`, `.env.example`, `breach-check.test.ts`                                  | HIBP k-anonymity 조회 헬퍼 신설(원문 미전송, `Add-Padding`). `PASSWORD_BREACH_CHECK=true` **opt-in**(외부 의존을 핫패스에 강제하지 않음), API 오류는 fail-open. 로직 단위 테스트 5건                                                                                                                               |

---

## 4. 잔여 권고 사항 (운영/제품 판단이 필요해 자동 변경하지 않음)

이 항목들은 **깨질 위험(interop/UX)** 또는 **정책 판단**이 있어 임의로 적용하지 않았습니다.

| #       | 심각도     | 항목                                                                                                               | 판단 포인트                                                                                                                                                               |
| ------- | ---------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1      | Medium     | **회원가입 계정 열거** — `409 username_taken` / `email_taken` 이 존재 여부를 노출(`signup/+page.server.ts:97,104`) | email 존재를 숨기면 UX 저하. "이미 등록됨→로그인 안내 메일" 패턴으로 바꿀지 제품 결정 필요                                                                                |
| ~~R2~~  | ~~Medium~~ | ~~SAML SP 인증서 유효기간 미검증~~                                                                                 | **완료 → F8 참조.** 기본 on(강제), `IDP_ENFORCE_SP_CERT_VALIDITY=false` 완화 플래그                                                                                       |
| ~~R3~~  | ~~Medium~~ | ~~dev/build 의존성 CVE 5건~~                                                                                       | **완료 → F7 참조.** `bun audit` 0건                                                                                                                                       |
| ~~R4~~  | ~~Low~~    | ~~public 클라이언트 introspect/revoke 무인증~~                                                                     | **완료 → F11 참조.** introspect 만 거부(revoke 는 RFC 7009 상 정상)                                                                                                       |
| ~~R5~~  | ~~Low~~    | ~~유출 비밀번호 스크리닝 없음~~                                                                                    | **완료 → F14 참조.** HIBP k-anonymity, `PASSWORD_BREACH_CHECK` opt-in                                                                                                     |
| ~~R6~~  | ~~Low~~    | ~~이메일 미인증 상태로 로그인 가능~~                                                                               | **완료 → F9 참조.** 서비스(RP)별 `requireVerifiedEmail` 옵션으로 구현. 전역 로그인 차단은 순수 UX 결정이라 채택하지 않음                                                  |
| ~~R7~~  | ~~Low~~    | ~~SSRF DNS 리바인딩 잔여~~                                                                                         | **완료 → F12 참조(완화).** `node:dns` resolve4/6 로 fetch 직전 실호스트 해석·차단. TOCTOU 로 원천 차단은 아님                                                             |
| ~~R8~~  | ~~Low~~    | ~~SAML 미서명 AuthnRequest 허용 → forced-SSO~~                                                                     | **완료 → F10 참조.** 신규 SP 기본 signed=true                                                                                                                             |
| R9      | Low        | admin CRUD Zod 스키마 `.strict()` 미사용                                                                           | **주의**: 폼이 submit 버튼명/csrf 필드 등 추가 필드를 POST 하면 `.strict()` 가 오히려 정상 요청을 깨뜨림. 현재는 Zod 기본 strip 으로 안전. 적용 시 폼 필드 전수 확인 필요 |
| ~~R10~~ | ~~Low~~    | ~~마스터 시크릿 키 분리(access-token HMAC)~~                                                                       | **완료 → F13 참조.** HKDF 파생 서브키 + 전환기 하위호환으로 무중단                                                                                                        |

---

## 5. 검증된 강력한 방어 (조치 불필요, 유지 권장)

- **OIDC**: redirect_uri 정확 매칭(wildcard opt-in), PKCE S256 강제·plain 다운그레이드 불가, 인가코드 원자적 단일 사용, RS256 고정(alg:none/HS-RS confusion 불가), cross-client introspection 차단, client_secret constant-time 비교, prod Host-header iss 주입 fail-close.
- **SAML**: XXE(DOCTYPE 거부+파서 미해석), XSW(단일 Signature/Reference·enveloped 강제), 서명 미검증 assertion 거부, ACS 핀 고정, 재전송 방지(1회성 requestId + skew), SLO CSRF(SP 서명·Sec-Fetch).
- **인증/세션**: 로그인 IP+계정 이중 레이트리밋(락아웃 DoS-safe), 열거 방어(균일 응답+scrypt 균등화), 리셋/초대 토큰 32B CSPRNG·SHA-256 저장·단일 사용, 세션 fixation 방지(로그인마다 재발급), 서버측 로그아웃 무효화, MFA 사전상태 HMAC+IP 바인딩, TOTP 재전송 방지, 신뢰기기 쿠키 탈취 단독 무력(비밀번호 필수).
- **API**: 서비스 토큰 constant-time 비교, WebAuthn 등록의 세션 바인딩(피해자 계정 패스키 등록 불가), 챌린지 단일 사용, TOTP secret AES-256-GCM+userId AAD.
- **Admin/Account**: 모든 action 이 layout 이 아닌 자체 `requireAdminContext` 재검증, 전 쿼리 tenant+owner scoped(IDOR 없음), 자기 역할 상승 차단, 마지막 admin 자가 삭제 방지, signing key private 미노출.
- **횡단**: CSPRNG 전용(보안 경로 `Math.random` 없음), hash 기반 CSP, 보안 헤더 전역(XFO/nosniff/HSTS/COOP/CORP/Permissions-Policy), `cf-connecting-ip` Workers 한정 신뢰(XFF 스푸핑 불가), 커밋된 시크릿 없음, audit 행 단위 HMAC 무결성.

---

## 6. 우선순위 권고

- **완료**: R2·R3·R4·R5·R6·R7·R8·R10 → F7~~F14 (+ 초기 F1~~F6). 총 **F1~F14**.
- **미반영(의도적)**:
    - **R1**(회원가입 계정 열거) — 사용자 판단으로 제외(UX 저하).
    - **R9**(admin Zod `.strict()`) — 정상 폼이 추가 필드를 POST 하면 오히려 파손되어 **권장하지 않음**.
- **운영 후속**: 아래 마이그레이션을 사용하는 환경에 적용 필요(postgres 는 R6 컬럼까지 적용 완료, R8 default 는 미적용).
