# 후속 3차 개선 기획서 — KeyStone (마감 라운드)

> **상태: 완료 (병합됨). 이 문서는 실행 이력이며 현행 사양서가 아닙니다.**
> 미체크로 남은 항목은 당시 커밋/검증 게이트 절차이고, 작업 자체는 병합되었습니다.
> **마이그레이션의 실제 DB 적용 여부는 배포 환경에서 직접 확인하세요.**
> 현행 사양은 [README](../../../README.md) · [관리자 매뉴얼](../../ADMIN_GUIDE.md) 참조. (최종 확인: 2026-08-07)

> 요청: 남은 항목 전부 진행 (C 기능·UX 마감 + A rate-limit 추상화 + B 테스트 심화 + 새 전수 재조사).
> 조사: 2026-07-06, 4개 병렬 Explore(전수 재조사=Opus, A/B/C=Sonnet). 코드 근거 확인.
> 규칙: 스키마 변경은 `db:generate:all`까지만(적용은 사용자). 커밋은 검증 통과 + 승인 후.

---

## 배경 / 목표

두 라운드로 핵심 결함·기능 공백은 해소됨. 이번은 **마감 라운드**: 전수 재조사로 드러난 신규 갭 + 미룬 A/B/C를 처리한다. 조사 종합 결과 6개 페이즈:

- **P12 잔여 버그·보안·운영 마감** — 전수 재조사 발견(저비용 고가치).
- **P13 메일 i18n + 세션 철회 알림 + 프로필 이메일 변경** — 기능 공백.
- **P14 UX a11y/loading + 스킨 복구 패널** — 접근성·사용성.
- **P15 rate-limit 저장소 추상화(A)** — 인터페이스 + Node in-memory.
- **P16 테스트 심화(B)** — SAML SSO·로그인+MFA·LDAP 통합 테스트.
- **P17 문서·잔여 마감** — admin 매뉴얼, organization 세분화, 관측성.

---

## 범위 (In / Out)

### Phase 12 — 잔여 버그·보안·운영 마감 (스키마 소폭)

- **In**:
    - **B1 invite_tokens GC 누락**(Medium): `gc.ts`가 users 하드삭제는 넣으면서 invite_tokens(만료/소진) purge를 누락 — 무한 성장. 다른 토큰 테이블과 동일 시맨틱으로 추가.
    - **B2 organization scope id_token 불일치**(표준 위배): `oidc/token/+server.ts`가 `scopes.has("organization")`을 안 봐서 organization만 요청 시 id_token에 조직정보 누락(userinfo만 실림). userinfo와 동일 로직 공유로 수정.
    - **B3 accept-invite status 검증 + 초대계정 상태**(Low보안): accept-invite `lookupToken`에 `status="active"` 필터 추가(disabled/deletion_pending 계정에 credential 심기 방지). 초대 미수락 계정이 즉시 `active`라 admin 카운트 오염 — credential 존재 기준으로 admin 판정하거나 상태 구분.
    - **B4 헬스체크 readiness**(Low운영): `api/health`가 DB 다운에도 200 → DB unavailable 시 503.
    - **B5 users 하드삭제 인덱스+배치**(Low): `deletionScheduledAt`/`status` 부분 인덱스 + GC 배치 LIMIT(대량 cascade 락 방지). `db:generate:all`.
    - **B6 잔여 하드코딩 한국어**(Low): `account/profile/+page.server.ts:52`(생년월일), `accept-invite:77`(credential label) translate 전환.
- **Out**: DCR/PAR/JAR/Device Flow(로드맵 — 정책 판단, 열린 질문 ⑤), 계정 병합.

### Phase 13 — 메일 i18n + 세션 철회 알림 + 프로필 이메일 변경

- **In**:
    - **F1 메일 전량 locale 인지**: 재설정/인증/초대 메일이 수신자 locale 무시(ko 고정) — `email.ts` 템플릿을 locale 인자 받도록(보안 알림 메일 패턴 확장). `baseHtml` 푸터·제목 i18n.
    - **F2 세션 철회 보안 알림**: `account/sessions` revoke/revokeOthers에 `dispatchSecurityAlert` 추가(`session_revoked`/`sessions_revoked_all` kind + i18n). 본인 직접 철회에도 보낼지는 열린 질문 ④(기본: 보냄 — 탈취 방어).
    - **F3 프로필 이메일 변경**(중간~높음): `users.pendingEmail`+`pendingEmailRequestedAt` 컬럼, `account/profile` changeEmail 액션(현 비밀번호 재인증 → pendingEmail 저장 → 새 주소 인증 메일), confirm 라우트(토큰 검증 → email 교체). 기존 이메일에 "변경 시도" 알림(탈취 방어). `email_change_tokens` 또는 email_verification_tokens 파라미터화. `db:generate:all`.
- **Out**: 이메일 변경 시 기존 세션 유지 정책(변경만, 세션 무효화는 안 함 — 표준).

### Phase 14 — UX a11y/loading + 스킨 복구 패널

- **In**:
    - **U1 a11y 에러 배너**: 8개 auth 라우트 에러 배너에 `role="alert"`/`aria-live="assertive"` 추가. 실패 후 포커스 이동.
    - **U2 loading 상태**: 메인 제출 폼(login/signup/mfa/reset/find-\*/accept-invite)에 `use:enhance` + 제출 중 버튼 disabled/스피너. 공용 패턴/컴포넌트로 추출.
    - **U3 스킨 로그인 복구 패널**(옵션 B, 저비용): `login/+page.svelte`의 스킨 조건을 `{#if skinHtmlEffective && !form?.recovery}`로 바꿔 복구 케이스는 기본 UI 강제 노출(스킨 작성자 개입 불필요). 또는 recovery 반환에 skinHtml 채우기.
- **Out**: 전면 스킨 슬롯 시스템(옵션 A — 등록 스킨 소급 수정 부담 큼).

### Phase 15 — rate-limit 저장소 추상화 (A)

- **In**:
    - **A1 인터페이스**: `RateLimitStore { increment(key,windowMs), peek(key,windowMs) }` 추출. `checkRateLimit(store, key, opts)`로 슬라이딩 윈도우 알고리즘 유지·저장소만 위임. `login`의 중복 `accountLockStatus` 구현을 `store.peek()`로 대체.
    - **A2 Node in-memory**: `Map` 기반 store(기존 globalThis 전역 패턴). 단일 인스턴스 가정 한계 문서화(다중 인스턴스는 Redis 필요 — 이번 미도입).
    - **A3 Workers 저장소**: **DO는 adapter-cloudflare 제약(fetch 단일 export)으로 wrapper 엔트리 필요 = 과침습**(GC scheduled 포기와 동일). 열린 질문 ①에 따라 (a) Workers는 현행 DB 저장소 유지(인터페이스만 추상화, 나중에 DO 삽입 가능), (b) wrapper 엔트리 도입해 DO. **기본안: (a)** — 추상화로 정리 효과(DB 4방언 분기·중복 제거)만 취하고 DO는 별도 결정.
    - 21곳 호출부 시그니처 교체(기계적), `locals.rateLimitStore` 요청당 1회 해석(db.ts 패턴).
- **Out**: Redis(다중 인스턴스 시에만), KV(원자 increment 없어 보안 rate-limit 부적합).

### Phase 16 — 테스트 심화 (B, Playwright 제외)

- **In**:
    - **T1 하네스 확장**: `seedSamlSp`, `seedIdentityProvider`, cookies 체이닝 헬퍼, SAML 서명 fixture 헬퍼(기존 유닛 테스트 `makeKeyCert`/`signAuthnRequest` 승격).
    - **T2 SAML SSO 통합**: SP-initiated POST 바인딩(authorize→Response 검증, 권한 게이트, replay 가드). saml 커버리지 15%→상승.
    - **T3 로그인+MFA 체이닝 통합**: 같은 cookies 인스턴스 재사용으로 idp_session/idp_mfa_pending 왕복. auth 34%→상승.
    - **T4 LDAP 로그인 통합**: `seedIdentityProvider`로 login LDAP 분기. ldap 0%→상승.
- **Out**: admin CRUD 전체 통합(라우트 다수 — 시간 크나 선택적, 열린 질문 없이 여력 되면), SAML Redirect 바인딩 서명(반나절 추가), Playwright e2e(ROI 최하 — 통합으로 대부분 커버).

### Phase 17 — 문서·잔여 마감

- **In**:
    - **D1 admin 운영 매뉴얼**: `docs/ADMIN_GUIDE.md`(조직/클라이언트/스킨/서명키/감사로그). skins/guide placeholder 6개 실제값 문서화(가이드 페이지도 갱신).
    - **D2 organization 노출 세분화 UI**(중간, 열린 질문 ③): oidc-clients 상세에 organization 클레임 토글(department/team/position 개별). `oidcClients.organizationClaimConfig` JSON 컬럼 + userinfo/token 참조. `db:generate:all`.
    - **D3 관측성 훅**(Low): 헬스체크 개선(B4와 통합), GC 결과 구조화 로깅. 구조화 로거·request-id·메트릭 export는 기반만(전면 도입은 별도).
    - **D4 백업코드 저잔량 경고**(Low): 로그인 시 backup_code 소비 후 잔량 경고, 소진 시 알림 메일.
- **Out**: Sentry/OTel 전면 배선, 감사뷰어 필터 대폭 확장(날짜/actor/CSV — 별도), scope 자유텍스트→체크박스 전면 개편.

---

## 코드베이스 사실관계 (조사 근거)

- **invite_tokens GC 누락**: `gc.ts:26,157-188` — users 하드삭제는 추가됐으나 invite_tokens purge 없음(다른 토큰과 동일 시맨틱).
- **organization 버그**: `oidc/token/+server.ts:148-153`이 `groups`만 체크, userinfo(`userinfo:120-154`)는 department/team/position 매핑 → organization scope만 요청 시 id_token 누락.
- **accept-invite**: `accept-invite:15-27` status 필터 없음. 초대 계정 `admin/users:227`이 즉시 `status:"active"`.
- **헬스체크**: `api/health:11-21` DB 상태 무관 200.
- **rate-limit**: `ratelimit/index.ts`(86줄) 2버킷 슬라이딩 윈도우, DB 4방언 분기. 호출부 21곳 `rl.allowed`만 사용(`remaining` 미참조). `login`이 `accountLockStatus`로 peek 중복 구현(20-46). DO는 adapter 제약(`_worker.js` fetch 단일 export)으로 wrapper 엔트리 필요.
- **테스트 하네스**: `harness.ts`가 makeEvent/makeCookies/seed 유틸 제공. cookies 인스턴스 재사용으로 라우트 체이닝 가능(신규 패턴). SAML fixture는 `test/unit/saml-verify-xml-signature.test.ts`의 makeKeyCert/signAuthnRequest 재사용. 커버리지: saml 15%·ldap 0%·org 0%·access 0%·admin/user-actions 0%. adapter-node는 이미 설정됨(svelte.config.js BUILD_TARGET 분기). Playwright 미설치.
- **a11y**: 8개 auth 폼 에러 배너 role/aria 전무, logout만 use:enhance.
- **프로필 이메일 변경**: `account/profile:35-71` email 필드 없음, pendingEmail 컬럼 없음.
- **메일 i18n**: 보안 알림만 locale 인자, reset/verify/invite 메일은 ko 고정.
- **스킨 복구**: `login/+page.server.ts:271-274` recovery 반환에 skinHtml 없음 → 스킨 로그인에서 복구 패널 미표시(무한 로그인 폼).

---

## 접근법 / 리스크 / 순서

| Phase         | 접근                                                          | 리스크 & 완화                                                  |
| ------------- | ------------------------------------------------------------- | -------------------------------------------------------------- |
| 12 마감       | 기존 패턴 소폭 수정, 저비용                                   | organization 버그는 표준 정합 회귀 주의 → 통합 테스트로 커버   |
| 13 기능       | email.ts locale화 + pendingEmail 플로우(email 인증 패턴 복제) | 이메일 변경은 탈취 벡터 → 재인증+기존주소 알림 필수            |
| 14 UX         | role=alert/use:enhance 일관 적용(공용화)                      | 스킨 복구는 옵션 B(코드만)로 스킨 작성자 무개입                |
| 15 rate-limit | 인터페이스 추상화 + Node in-memory, Workers는 기본 DB 유지    | DO는 과침습이라 열린 질문 ①. 추상화만으로 4방언 분기 제거 효과 |
| 16 테스트     | 하네스 확장(기존 fixture 재사용)                              | Playwright 제외(ROI). 커버리지 0% 구간 집중                    |
| 17 문서       | 문서 + organization UI(스키마 소폭) + 관측성 기반             | organization UI는 열린 질문 ③(버그만 vs UI까지)                |

**순서**: 12(마감·기반) → 13/14 병렬(기능·UX, 파일 대체로 분리) → 15(rate-limit, 21곳 광범위) → 16(테스트 — 12~15 신규 로직 포함) → 17(문서·마감). 스키마 건드리는 12(B5)·13(F3)·17(D2)는 마이그레이션 순서 조율(직렬).

---

## 열린 질문 (승인 시 확정)

1. **rate-limit Workers 저장소(P15)** — (a) 인터페이스만 추상화하고 Workers는 현행 DB 유지(Node만 in-memory 개선, 권장 — 저리스크), (b) wrapper 엔트리 도입해 Durable Object(성능 최적이나 과침습·빌드구조 변경). 어느 쪽?
2. **프로필 이메일 변경(P13 F3)** — 포함할지(중간~높음, 스키마+confirm 라우트). 표준 IdP 기능이라 권장하나 규모 있음.
3. **organization 노출 세분화 UI(P17 D2)** — id_token 불일치 버그 수정(P12 B2)만 할지, 클라이언트별 세분화 토글 UI(스키마 컬럼)까지 할지.
4. **세션 철회 알림(P13 F2)** — 본인이 직접 자기 세션 철회할 때도 알림 메일 보낼지(탈취 방어 vs 정상 로그아웃 스팸). 기본: 보냄.
5. **DCR/PAR/Device Flow(P12 Out)** — 표준 확장. 이번 로드맵 제외가 기본. 원하면 별도 트랙.

---

## 산출물

- `docs/plans/followup-round3/PLAN.md` (본 문서) → 승인 후 `TODO.md`
- 스키마 변경분은 `db:generate:all`까지만 — 적용은 사용자.
