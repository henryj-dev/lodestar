# 실행 투두 — service entitlements (6 페이즈)

> 설계: `docs/plans/service-entitlements/PLAN.md` · 발단: `docs/keystone-핸드오프.md` §5
> heliopause 답신(2026-08-06) 반영: 클레임명 `entitlements` · refresh 정책 **C** · SET 은 `{ roles, entitlements }`.
> **잔여 미정 1건** — SAML attribute 명(PLAN §8-3). P2-2(발행)와 P4-3(정의 UI)이 여기 묶여 있다.
> 규칙: 스키마 변경은 `db:generate:all` 까지만(적용 금지, `CLAUDE.md`). 스텁/TODO/skip 은 블로커.
> 순서: P1 → P2 → **P3(RP 계약 확정)** → P4 → P5 → P6. 각 페이즈가 독립 배포 가능하며, 중단해도 기존 동작이 깨지지 않는다.
> **P3 을 UI 앞으로 당긴 이유**: heliopause 가 SET 을 구현하겠다고 확정했다. payload 모양을 먼저 고정해야 그쪽 파서 재작업이 없다.
>
> **진행 상황 (2026-08-06)** — **P1~P6 전부 완료**, 브랜치 `feat/service-entitlements`.
> OIDC 경로는 정의 → 배정 → 클레임 발행 → SET 통지까지 닫혔다.
> 남은 것은 **SAML 한 갈래뿐**이고 attribute 명 미정에 묶여 있다 — P2-2(발행)와 P4-3(정의 UI).
> 그 둘은 같이 붙여야 한다(정의만 먼저 넣으면 조용한 무동작).
> **마이그레이션은 pg 에 적용 완료**(사용자 실행). FK 이름 길이 문제로 한 번 재생성·재적용했다.
> **heliopause 에 P3 완료를 알렸다** — `docs/plans/service-api-tokens/회신-heliopause.md` §6.

---

## Phase 1 — 스키마

**목적**: 테이블 2개를 3방언에 추가. 아직 아무도 읽지 않는다.

### [x] 1-1. `service_entitlements` × 3방언

- 파일: `src/lib/server/db/schema.pg.ts` · `schema.mysql.ts` · `schema.sqlite.ts`
- 작업: PLAN §2-1 의 컬럼/인덱스. 각 방언의 `serviceRoles` 정의 바로 아래에 배치
  (pg `:459-479` · mysql `:503-526` · sqlite `:501-524`). 방언별 타입 매핑은 PLAN §2-3 표.
  `is_default` 는 **넣지 않는다**(PLAN §2-1).
- 수용 기준: 3방언 정의가 컬럼명·인덱스명까지 동일. `bun run check` 통과.

### [x] 1-2. `user_service_entitlements` × 3방언

- 파일: 위와 동일
- 작업: PLAN §2-2. `assignment_id` → `user_service_assignments.id` **ON DELETE CASCADE**,
  `service_entitlement_id` → `service_entitlements.id` **ON DELETE CASCADE**.
  `revoked_at` 은 **넣지 않는다**(PLAN §1-1 — 기존 테이블에서 죽은 컬럼임을 실측).
- 수용 기준: 위와 동일. cascade 가 3방언 모두에 걸림.

### [x] 1-3. 타입 export + 마이그레이션 생성

- 파일: 각 schema 파일 말미(`schema.pg.ts:971` `ServiceRole` 인근) **3방언 전부**
- 작업: `ServiceEntitlement` / `UserServiceEntitlement` 타입을 세 파일에 각각 export.
  `src/lib/server/db/schema.ts` 는 `export * from "$db-active-schema"` 배럴이라 **수정 불필요**.
  이후 `bun run db:generate:all` 실행.
- 수용 기준: 출력 4곳에 마이그레이션 생성 — `drizzle/`(D1) · `drizzle/pg` · `drizzle/mysql` ·
  `drizzle/sqlite`(`drizzle.config.ts:14,25,38,58`). **적용하지 않고 사용자에게 보고.**

---

## Phase 2 — 클레임 발행

**목적**: 권한을 토큰에 싣는다. 권한 0개인 기존 RP 는 토큰이 완전히 동일해야 한다.

### [x] 2-1. `listActiveEntitlements()`

- 파일: `src/lib/server/access/service-permissions.ts`
- 작업: `(db, assignmentId) => Promise<string[]>`. `user_service_entitlements` ⋈ `service_entitlements`,
  `expiresAt` 미래/null 필터(`getActiveAssignment` 의 `:50` 과 동일 시맨틱),
  `display_order` → `key` 정렬. 키 배열만 반환.
- 수용 기준: 단위 테스트 — 만료 권한 제외, 정렬 안정, 없으면 `[]`.

### [x] 2-2. 발행 3곳

- 파일: `src/routes/oidc/token/+server.ts:136-147` · `src/routes/oidc/userinfo/+server.ts:101-118` ·
  `src/routes/saml/sso/+server.ts:110`
- 작업: 각 위치가 이미 들고 있는 `assignment.id` 로 2-1 호출. 클레임명 **`entitlements`**(확정).
  **결과가 빈 배열이면 클레임을 넣지 않는다**(PLAN §3-1 — 빈 배열도 넣지 않음).
- ⚠️ **SAML 부분은 attribute 명 미정으로 보류했다**(PLAN §8-3). OIDC 2곳(token·userinfo)만 발행한다.
  SAML SP 를 붙이는 시점에 이름을 정해 `saml/sso` 에 추가한다. **이 항목만 P2 에서 미완이다.**
- 수용 기준: 권한 0개 사용자의 id_token/userinfo 페이로드가 변경 전과 **키 단위로 동일**.
  권한 보유 시 발행 지점 간 값 일치.

### [x] 2-3. 예약 클레임 등록

- 파일: `src/routes/oidc/token/+server.ts:22` · `src/routes/oidc/userinfo/+server.ts`
- 작업: `RESERVED_ID_TOKEN_CLAIMS` / `RESERVED_USERINFO_CLAIMS` 에 클레임명 추가.
  `roles` 는 이번에 **건드리지 않는다**(PLAN §7).
- 수용 기준: `attributesJson` 에 같은 키를 넣어도 실제 권한이 덮이지 않음(테스트).

---

## Phase 3 — SET payload 계약 확정 ← **UI 앞으로 당김**

**목적**: heliopause 가 파서를 만들 대상을 최종형으로 고정한다. 이 시점에 `entitlements` 는 항상
`[]` 지만(정의 UI 가 아직 없으므로) **계약은 이미 최종형이다.** 스텁이 아니라 2-1 의 실제 함수가
실제로 빈 결과를 반환하는 것이다.

### [x] 3-1. SET payload 에 `entitlements`

- 파일: `src/lib/server/oidc/role-change.ts:63-74`
- 작업: `sendRoleChangeSet()` 에 `entitlements: string[]` 파라미터 추가,
  `events[ROLE_CHANGE_EVENT]` 를 `{ roles, entitlements }` 로. 헤더 주석(`:11-12`) 갱신.
  호출부(`user-actions/service.ts:29` `emitRoleChangeSet()`)에서 `roles` 를 다시 읽는 자리(`:40-41`)에
  2-1 을 같이 호출해 전달.
- 수용 기준: 기존 RP 가 읽는 `roles` 키 위치·형태 무변경(하위 호환). 서명/`typ` 무변경.
  권한 미정의 상태에서 `entitlements: []` 가 실제로 실림.
- **완료 후 heliopause 에 알린다** — 그쪽이 이 모양에 맞춰 구현할 수 있게 된다.

---

## Phase 4 — 권한 정의 UI

**목적**: 서비스별 권한 키 CRUD. `serviceRoles` UI 복제.

### [x] 4-1. OIDC 클라이언트 상세

- 파일: `src/routes/admin/oidc-clients/[id]/+page.server.ts` · `+page.svelte`
- 작업: role CRUD(`:54-82` 생성 · `:98-109` 수정 · `:160-175` 삭제) 를 본떠 entitlement 액션 3종.
  키 검증은 **기존 `ROLE_KEY_RE`(`:11`) 재사용** — `/^[A-Za-z0-9_.-]{1,64}$/` 로 점·밑줄을 허용하므로
  `site.read`·`plan.approve_own` 형태가 그대로 통과한다(PLAN §3-1). 새 정규식을 만들지 않는다.
  409 중복 처리, 감사 이벤트(`service_entitlement_created`/`_deleted`) 동일 패턴.
  `+page.svelte` 에 role 섹션 아래 entitlement 섹션. **`displayOrder` 편집 가능해야 한다**(PLAN §2-1 —
  권한 간 의존을 관리자에게 안내하는 유일한 수단).
- 수용 기준: 생성/수정/삭제 동작, 중복 key 409, 점 포함 키 통과, 감사 이벤트 기록.
  기존 role 섹션 무회귀.

### [x] 4-2. `ROLE_KEY_RE` 중복 정리

- 파일: `admin/oidc-clients/[id]/+page.server.ts:11` · `admin/saml-sps/[id]/+page.server.ts:10`
- 작업: 같은 상수가 두 파일에 중복돼 있다. entitlement 액션이 이걸 또 복제하지 않도록 공용 위치로
  뽑는다(`$lib/server/admin/` 하위). 기존 role 검증도 같은 상수를 쓰게 한다.
- 수용 기준: 정의 1곳. role/entitlement 양쪽 검증 동작 무회귀.

### [~] 4-3. SAML SP 상세 — **보류**

- 파일: `src/routes/admin/saml-sps/[id]/+page.server.ts` · `+page.svelte`
- **P2-2 의 SAML 발행 보류에 딸려 보류한다.** SAML SSO 가 entitlement 를 발행하지 않는 상태에서
  정의 UI 만 있으면, 관리자가 권한을 만들고 배정했는데 SP 에는 아무것도 가지 않는 **조용한
  무동작**이 된다. attribute 명이 정해져 발행이 붙는 시점에 4-1 과 동일하게 추가한다.
  (해당 파일에 이유를 주석으로 남겨 뒀다.)
- 수용 기준: 발행과 함께 붙일 것 — 정의 UI 만 먼저 넣지 말 것.

### [x] 4-4. i18n

- 작업: 4-1/4-3 에서 추가한 라벨·에러 키를 기존 locale 파일 전체에 추가.
- 수용 기준: 누락 키 없음(기존 i18n 검증 경로 통과).

---

## Phase 5 — 사용자별 배정 UI

**목적**: 이 작업에서 유일한 신규 UI. 여기서부터 실사용 가능.

### [x] 5-1. 배정 화면에 권한 체크박스

- 파일: `src/routes/admin/users/[id]/+page.svelte`(role `<select>` 는 `:425`, 배정 목록 `:357-390`) ·
  `+page.server.ts`
- 작업: 선택된 서비스의 `service_entitlements` 를 **`displayOrder` 순** 체크박스 그룹으로.
  배정 행마다 현재 권한 표시. 재부여 시 이전 권한이 복구되지 않음을 UI 에 명시(PLAN §2-2).
- 수용 기준: 체크박스 상태가 DB 와 일치, 순서가 `displayOrder` 를 따름. 서비스 변경 시 목록 갱신.

### [x] 5-2. 부여/회수 액션 + 감사

- 파일: `src/lib/server/admin/user-actions/service.ts`
- 작업: 권한 부여/회수 액션. `addAssignment()`(`:92`) 의 검증 패턴 준수 —
  `assertUserInTenant` cross-tenant IDOR 가드(`:101-103`), entitlement 가 해당 service 소속인지 검증
  (role 검증 `:136-144` 와 동형). 감사 이벤트 `user_entitlement_granted`/`_revoked`.
  **권한 간 의존은 강제하지 않는다**(PLAN §2-1 — RP 의 의미론이므로 IdP 가 알지 않는다).
- 수용 기준: 타 테넌트/타 서비스 entitlement 부여 차단. 감사 이벤트에 `entitlementKey` 포함.
  배정 삭제 시 권한이 cascade 로 사라짐(통합 테스트).

---

## Phase 6 — SET 발행 지점 확장 + refresh 정책

**목적**: 권한 회수가 RP 세션에 즉시 반영되게 한다. **이게 없으면 회수가 조용히 샌다**(PLAN §1-2).
payload 모양은 P3 에서 이미 고정됐고, 여기서는 **언제 쏘는가**를 채운다.

> heliopause 는 refresh token 을 받지 않는다 — 인가 상태가 자체 세션 쿠키에 있다(답신 Q1).
> 그런 RP 에게 **6-2 의 refresh 폐기는 아무것도 닫아 주지 못하고, 6-1 의 SET 이 유일한 수단이다.**
> 6-1 을 "부수 작업" 으로 취급하지 말 것.

### [x] 6-1. 발행 지점 확장

- 파일: `src/lib/server/admin/user-actions/service.ts:29-89` `emitRoleChangeSet()`
- 작업: **권한만 변경된 경우(5-2 액션)에도 호출**한다 — 현재는 배정 부여/회수에서만 나간다.
  (payload 조립 자체는 P3 에서 완료.)
- 수용 기준: 권한 체크박스만 바꿔도 SET 발행. `role_change_uri` 미설정 클라이언트는 조용히 skip
  (기존 동작 유지).

### [x] 6-2. refresh token 정책 C 구현

- 파일: `src/lib/server/admin/user-actions/service.ts`
- 작업: **정책 C 확정**(heliopause 답신 Q1) — 권한 **제거** 시에만 `revokeRefreshTokenFamily()`,
  추가는 SET 만. 기존 회수 경로(`:234`)와 같은 함수를 쓴다.
- 수용 기준: 권한 제거 후 기존 refresh token 으로 재발급되는 토큰에 해당 권한이 없음(통합 테스트).
  권한 **추가** 시에는 refresh family 가 폐기되지 않음(재로그인 강요 없음).

---

## 완료 게이트

- [x] `bun run check`(0/1446) · `bun run lint`(0) · `bun run test`(287/287) 전부 통과
- [x] 권한 미정의 기존 RP 의 토큰 페이로드 무회귀(2-2 수용 기준 — 키 부재 테스트)
- [x] SET 의 `roles` 키가 기존 형태 그대로(3-1 수용 기준 — 기존 계약 테스트 유지)
- [x] 마이그레이션은 생성만, 적용은 사용자 실행(pg 적용 완료)
- [x] **작성자와 분리된 독립 리뷰 통과** — 코드 리뷰 + 보안 리뷰를 각각 독립으로 받고 지적을 반영했다.
- [ ] **배포 전 사람 확인 3건** — `DEPLOY-CHECKLIST.md`(컬럼 비어있음·attributesJson 충돌·D1 cascade)

---

## 이 작업 밖 — 별건으로 뺀 것

heliopause 답신에서 나온 것과, 설계 중 보인 것. **entitlement 와 독립이므로 여기서 하지 않는다.**

- ~~**`isNull(revokedAt)` 죽은 필터**~~ → **해결.** 필터 3곳·load·UI 분기·컬럼까지 제거하고
  마이그레이션(②)을 만들었다. 적용 전 컬럼이 비어 있는지 확인할 것 — `DEPLOY-CHECKLIST.md` §1.
- ~~**관리자 강제 로그아웃이 RP 에 도달하지 않음**~~ → **해결.** 주체 단위 타깃 탐색
  (`getOidcBackchannelTargetsForUser`)을 만들어 배선했다. 배선만으로는 부족했다 — 아래 항목 참조.
- ~~**back-channel logout 타깃 탐색이 단명 행에 묶임**~~ → **해결(양쪽 다).**
  주체 단위 경로는 배정/allowAllUsers 기준 탐색으로, 세션 단위 경로(`end-session` ·
  `(auth)/logout` · `saml/slo`)는 `oidc_client_sessions` 기록(토큰 발급 시 1회, 세션에 cascade)으로
  바꿨다. 기존 grant/refresh 탐색과 **합집합**이라 이 테이블 이전 세션도 회귀 없이 찾힌다.
- ~~**`roles`/`roles_label` 이 예약 클레임 목록에 없음**~~ → **해결.** `groups` 까지 함께 예약했다.
  기존에 그 경로로 클레임을 넣어 쓰던 배정이 있으면 사라지므로 배포 전 확인 필요 —
  `DEPLOY-CHECKLIST.md` §2.
- **핸드오프 §3 — `groups` 문서화.** `ADMIN_GUIDE.md:91` scope 표 + `README.md`.
- **핸드오프 §8 — `sub` 계약 주석.** `token/+server.ts:98` 옆 한 줄.
