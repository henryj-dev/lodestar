# service entitlements — 설계안

작성 2026-08-06 · 개정 2026-08-06(heliopause 답신 반영) · 근거: `feat/workers-vpc-db` @ e45b80d 실측
발단: `docs/keystone-핸드오프.md` §5 (heliopause 팀 제안)
왕복: 회신 `회신-heliopause.md` → 답신 `heliopause/docs/keystone-답신.md`(Q1~Q5 회답)

---

## 0. 요약

`groups`(조직 소속) · `roles`(단일 역할) 와 **직교하는 세 번째 축**으로 권한을 모델링한다.
테이블 2개 × 3방언, 클레임 1개, 관리 UI 2화면.

핸드오프 §4 의 결론(multi-role 반대)을 그대로 채택한다. `user_service_assignments_user_service_uidx`
는 건드리지 않는다. 역할은 계속 하나다.

**핸드오프에 없던 것 둘을 이 설계에서 추가로 다룬다.** 아래 §1 과 §5 — 둘 다 안 하면 권한 회수가
조용히 새는 자리다.

---

## 1. 실측하며 정정한 두 가지

핸드오프 §5 의 논거 중 하나가 현재 코드와 맞지 않는다. 설계에 영향이 있어 먼저 적는다.

### 1-1. "부여 이력이 공짜로 따라온다" — 지금은 아니다

핸드오프는 `userServiceAssignments` 가 `grantedBy`·`grantedAt`·`expiresAt`·`revokedAt` 을 이미
들고 있으니 같은 패턴이면 이력이 따라온다고 봤다. 컬럼은 실제로 있다(`schema.pg.ts:502-505`).

그런데 **`revokedAt` 은 읽히기만 하고 아무도 쓰지 않는다:**

- `src/lib/server/access/service-permissions.ts:49` — `isNull(userServiceAssignments.revokedAt)` 로 **읽는다**
- 쓰는 곳: **없음.** `revokeAssignment()` 는 `db.delete(...)` 로 **행을 지운다** (`user-actions/service.ts:218`)

`grep -rn "revokedAt" src/` 기준으로 `sessions`·`oidcRefreshTokens`·`trustedDevices` 는 `.set({ revokedAt })`
을 하지만 `userServiceAssignments` 만 하지 않는다. 즉 회수 이력은 행에 남지 않고 **감사 로그에만**
남는다(`kind: "service_assignment_revoked"`).

**설계 반영:** 새 테이블에 `revokedAt` 을 넣지 않는다. 죽은 컬럼을 하나 더 만들지 않기 위해서다.
이력은 기존과 같은 자리 — 감사 이벤트 — 에 남긴다(§4-3). 부여 시점 정보(`grantedBy`/`grantedAt`)는
행에 남기므로 "지금 이 권한을 누가 줬는가" 에는 답할 수 있다.

### 1-2. Role Change SET 이 `roles` 만 싣는다

핸드오프 §8 이 "흥미롭게 보고 있다" 고 한 Role Change push 는 **이미 구현돼 있다:**

- `src/lib/server/oidc/role-change.ts:12` — `events = { "https://idp.hyochan.site/event/role-change": { roles: string[] } }`
- `src/lib/server/admin/user-actions/service.ts:29` `emitRoleChangeSet()` — 부여/회수 직후 fire-and-forget

**이 payload 에 entitlement 를 싣지 않으면, 권한을 회수해도 RP 세션이 만료될 때까지 남는다.**
`roles` 에 대해 이미 닫아 둔 구멍이 `entitlements` 에 대해서만 다시 열린다. §5 에서 다룬다.

---

## 2. 데이터 모델

`serviceRoles` (`schema.pg.ts:459`) 를 본뜨되 두 군데를 뺀다.

### 2-1. `service_entitlements` — 서비스가 정의하는 권한 키

| 컬럼 | 타입(pg) | 비고 |
|---|---|---|
| `id` | `text` PK | `crypto.randomUUID()` |
| `tenant_id` | `text` NOT NULL | → `tenants.id` ON DELETE CASCADE |
| `service_type` | `text` enum `oidc`\|`saml` | |
| `service_ref_id` | `text` NOT NULL | FK 없음 — `serviceRoles` 와 동일한 이유(2개 테이블 중 하나) |
| `key` | `text` NOT NULL | 클레임에 실리는 값 |
| `label` | `text` NOT NULL | 관리 UI 표시용 |
| `description` | `text` | |
| `display_order` | `integer` NOT NULL DEFAULT 0 | |
| `created_at` / `updated_at` | `timestamp` | |

인덱스 — `serviceRoles` 와 동형:
```
uniqueIndex service_entitlements_service_key_uidx  (service_type, service_ref_id, key)
index        service_entitlements_tenant_service_idx (tenant_id, service_type, service_ref_id)
```

**`is_default` 를 넣지 않는다.** `serviceRoles.isDefault`(`schema.pg.ts:473`) 는 "새 배정의 기본 역할"
이라 무해하지만, 권한에서 기본 부여는 "누가 줬는가" 에 답이 없는 권한을 만든다. 권한은 전부 명시
부여로 둔다.

**`display_order` 는 장식이 아니다 — 권한 간 의존을 표현하는 유일한 자리다.**
heliopause 실측(답신 Q5)에 따르면 권한 키는 완전히 평평하지 않다: `plan.approve_own` 은
`plan.approve` 없이는 의미가 없고, `plan.approve` 는 `site.read` 를 함의한다.

**그럼에도 함의를 모델에 넣지 않는다.** "A 가 B 를 요구한다" 는 것은 **RP 의 의미론**이고, 다른 RP
에서는 같은 모양의 두 키가 무관할 수 있다. 함의를 스키마에 넣으면 IdP 가 RP 의 의미를 알아야 하고,
그것은 **entitlement 가 피하려던 결합 그 자체**다 — `groups` 를 인가에 쓰면 안 되는 이유와 같은
종류의 문제다. 의존 강제는 RP 가 한다.

대신 관리 UI 가 `display_order` 순으로 체크박스를 세워, 관리자가 "아래를 켜려면 위도 켜야 한다" 를
읽을 수 있게 한다. **강제하지 않고 안내만 하는 자리다.**

### 2-2. `user_service_entitlements` — 사용자 ↔ 권한 (다대다)

| 컬럼 | 타입(pg) | 비고 |
|---|---|---|
| `id` | `text` PK | |
| `tenant_id` | `text` NOT NULL | → `tenants.id` CASCADE |
| `assignment_id` | `text` NOT NULL | → `user_service_assignments.id` **ON DELETE CASCADE** |
| `service_entitlement_id` | `text` NOT NULL | → `service_entitlements.id` **ON DELETE CASCADE** |
| `granted_by` | `text` | |
| `granted_at` | `timestamp` NOT NULL DEFAULT now | |
| `expires_at` | `timestamp` | |
| `created_at` | `timestamp` NOT NULL | |

```
uniqueIndex user_service_entitlements_assignment_ent_uidx (assignment_id, service_entitlement_id)
index        user_service_entitlements_tenant_ent_idx      (tenant_id, service_entitlement_id)
```

**`userId`/`serviceType`/`serviceRefId` 대신 `assignment_id` 를 참조하는 이유 셋:**

1. **기본 deny 가 구조로 강제된다.** 접근 배정 없이 권한만 가진 상태가 표현 불가능해진다.
   현재 SSO 게이트가 배정 유무(`hasServiceAccess`)라, 권한이 배정과 따로 놀면 의미가 없다.
2. **회수가 공짜로 cascade 된다.** `revokeAssignment()` 의 `db.delete(userServiceAssignments)`
   (`service.ts:218`) 가 그대로 권한까지 지운다. 회수 경로에 코드를 추가할 필요가 없다.
3. **만료가 이미 한 곳에 있다.** `getActiveAssignment()` 가 `expiresAt`/`revokedAt` 을 이미 필터하므로
   (`service-permissions.ts:49-50`), 배정이 만료되면 권한 조회가 애초에 시작되지 않는다.

**트레이드오프 (수용):** 접근을 회수했다가 다시 부여하면 권한은 복구되지 않는다. 재부여 시
`user_service_assignments` 행이 새로 생기므로(하드 삭제 후 INSERT) `assignment_id` 가 달라진다.
**이것이 옳은 동작이라고 본다** — 접근을 다시 준 것이 이전 권한까지 조용히 되살리는 편이 위험하다.
관리 UI 에서 재부여 시 "이전 권한은 복구되지 않습니다" 를 명시한다.

**"publish 권한 가진 사람 전부" 쿼리** — 핸드오프 §5 가 감사에서 먼저 나온다고 한 질문:
```sql
user_service_entitlements → user_service_assignments (assignment_id) → users
  WHERE service_entitlement_id = ?
```
조인 하나. `user_service_entitlements_tenant_ent_idx` 가 커버한다.

### 2-3. 3방언

`serviceRoles` 의 방언 차이를 그대로 따른다. 기계적 치환이고 새로운 판단은 없다:

| | pg | mysql | sqlite |
|---|---|---|---|
| id/ref | `text` | `varchar(64)` | `text` |
| key/label | `text` | `varchar(255)` | `text` |
| 타임스탬프 | `timestamp({mode:"date",withTimezone:true,precision:3})` `.defaultNow()` | `datetime({mode:"date",fsp:3})` `.default(sql`(CURRENT_TIMESTAMP(3))`)` | `integer({mode:"timestamp_ms"})` `.default(sql`(unixepoch() * 1000)`)` |
| 정수 | `integer` | `int` | `integer` |

대조: `schema.pg.ts:459-479` · `schema.mysql.ts:503-526` · `schema.sqlite.ts:501-524`.

**컬럼명·테이블명·인덱스명·추론 타입이 세 방언에서 동일해야 한다.** 선택이 아니라 제약이다 —
`src/lib/server/db/schema.ts` 는 `export * from "$db-active-schema"` 배럴이고, 그 헤더 주석이
"세 스키마는 컬럼명·테이블명·인덱스명·JS 추론 타입이 동일하도록 유지되므로, 어떤 방언이 활성이든
쿼리 코드는 그대로 컴파일·동작한다" 를 계약으로 명시한다. 하나라도 어긋나면 다른 방언 빌드에서만
깨진다.

---

## 3. 클레임 발행

### 3-1. 클레임 이름과 형태

```
entitlements: string[]     // service_entitlements.key 의 배열, 정렬은 display_order → key
```

**이름 `entitlements` 확정** (heliopause 답신 Q2). `permissions` 는 프레임워크·미들웨어가 같은 이름으로
자기 것을 주입하는 일이 흔해 토큰 디버깅 시 출처가 모호해지고, `perms` 는 사람이 눈으로 읽는 자리
(토큰 디코드 화면·로그)에 나오기엔 정보가 적다는 것이 소비자 측 의견이다.

**키 형식은 `ROLE_KEY_RE` 를 그대로 쓴다** — `/^[A-Za-z0-9_.-]{1,64}$/`
(`admin/oidc-clients/[id]/+page.server.ts:11` · `admin/saml-sps/[id]/+page.server.ts:10`).
점과 밑줄을 허용하므로 heliopause 가 스케치한 `site.read`·`plan.approve_own` 형태의 네임스페이스 키가
그대로 통과한다. 별도 정규식을 만들지 않는다. (이 상수가 두 파일에 중복돼 있다 — entitlement 액션을
추가할 때 같은 중복을 늘리지 말고 공용 위치로 뽑는다.)

**scope 게이트를 두지 않는다.** `groups` 는 scope 로 게이트되지만(`token/+server.ts:152`),
`roles` 는 배정 존재만으로 발행된다(`token/+server.ts:137-140`). `entitlements` 는 인가 데이터이므로
`roles` 와 같은 규칙을 따르는 편이 일관적이다.

**권한이 0개면 클레임을 아예 넣지 않는다.** 빈 배열도 넣지 않는다. 이러면 entitlement 를 정의하지
않은 기존 RP 의 토큰은 **바이트 단위로 동일하다** — 회귀 위험이 0 이다.

### 3-2. 발행 지점 3곳

`membershipToGroups()` 가 놓인 자리와 같다. 공용 함수 하나를 만들어 세 곳이 공유한다
(`membershipToGroups` 가 token/userinfo 를 공용화한 것과 같은 패턴 — `org/membership.ts:47` 주석 참조).

```
src/lib/server/access/service-permissions.ts
  + listActiveEntitlements(db, assignmentId): Promise<string[]>
```

| 파일 | 위치 | 변경 |
|---|---|---|
| `src/routes/oidc/token/+server.ts` | `:136-147` assignment 블록 | `assignment.id` 로 조회 → `idTokenPayload.entitlements` |
| `src/routes/oidc/userinfo/+server.ts` | `:101-118` assignment 블록 | 동일 → `response.entitlements` |
| `src/routes/saml/sso/+server.ts` | `:110` `spAssignment` 이후 | SAML attribute 로 방출 |

세 곳 모두 이미 `getActiveAssignment()` 결과를 손에 들고 있다. `assignment.id` 는 이미 `ActiveAssignment`
에 포함돼 있어(`service-permissions.ts:31,58`) **인터페이스 변경이 없다.**

### 3-3. 예약 클레임 충돌

`attributesJson` 머지가 `entitlements` 키를 덮어쓸 수 있다. 두 곳의 예약 목록에 추가한다:

- `src/routes/oidc/token/+server.ts:22` `RESERVED_ID_TOKEN_CLAIMS`
- `src/routes/oidc/userinfo/+server.ts` `RESERVED_USERINFO_CLAIMS`

`roles`/`roles_label` 이 지금 이 목록에 **없다**는 점은 별개 이슈다(§7 에 남긴다).

---

## 4. 관리 UI

핸드오프가 "작업의 절반 이상" 이라고 한 부분. 실측해 보니 **본뜰 대상이 이미 다 있어** 추정보다
가볍다.

### 4-1. 권한 정의 (서비스별)

`serviceRoles` CRUD 와 동형. `src/routes/admin/oidc-clients/[id]/+page.server.ts` 의
`:54-82`(생성) · `:98-109`(수정) · `:160-175`(삭제) 를 그대로 본뜬다. `ROLE_KEY_RE` 검증,
409 중복 처리, 감사 이벤트까지 패턴이 동일하다.

- `src/routes/admin/oidc-clients/[id]/` — 기존 role 섹션 아래에 entitlement 섹션 추가
- `src/routes/admin/saml-sps/[id]/` — 동일

### 4-2. 사용자별 권한 배정

`src/routes/admin/users/[id]/+page.svelte` — 현재 배정 UI 는 역할 단일 `<select>`(`:425`).
그 아래에 **권한 체크박스 그룹**을 추가한다. 배정 행 목록은 `:357-390`.

이 화면이 이 작업에서 유일하게 새로운 UI 다 — 나머지는 복제.

### 4-3. 감사 이벤트

`revokedAt` 을 두지 않으므로(§1-1) 이력은 전적으로 여기 남는다. 기존 `service_assignment_granted`
/`service_assignment_revoked` 와 나란히:

```
service_entitlement_created / service_entitlement_deleted     (정의 변경)
user_entitlement_granted    / user_entitlement_revoked        (배정 변경)
```

`detail` 에 `{ serviceType, serviceRefId, entitlementKey }` 를 담는다.

---

## 5. Role Change SET 확장 — 빠뜨리면 안 되는 것

§1-2 에서 짚은 것. `emitRoleChangeSet()`(`user-actions/service.ts:29`) 이 `roles` 만 싣는다.

**변경:**

```
role-change.ts:70
  events: { [ROLE_CHANGE_EVENT]: { roles } }
→ events: { [ROLE_CHANGE_EVENT]: { roles, entitlements } }
```

`sendRoleChangeSet()` 시그니처에 `entitlements: string[]` 를 추가하고, `emitRoleChangeSet()` 이
`roles` 를 다시 읽는 자리(`service.ts:40-41`)에서 권한도 같이 읽는다. **기존 RP 는 `roles` 만 읽으므로
하위 호환이다** — 같은 event 객체에 키가 하나 늘 뿐이다.

**호출 지점 추가:** 지금은 배정 부여/회수에서만 SET 이 나간다. 권한만 바뀌는 경우
(배정은 그대로, 체크박스만 변경)에도 SET 이 나가야 한다. §4-2 의 배정 액션에서 `emitRoleChangeSet()`
을 호출한다.

**refresh token 폐기(M-3) — C 로 확정.** (heliopause 답신 Q1, 2026-08-06)
`revokeAssignment()` 는 회수 시 `revokeRefreshTokenFamily()` 를 호출한다(`service.ts:234`).
주석(`:222-227`)이 설명하듯, 이게 없으면 탈권한 사용자가 refresh token 으로 최대 30일간 토큰을
재발급받는다. 권한 **축소**도 같은 성질이지만 세션을 끊는 비용이 크다(권한 하나 뺐다고 로그아웃).

| | 동작 | 대가 |
|---|---|---|
| A | 권한 축소 시 refresh family 폐기 | 안전. 권한 조정마다 재로그인 |
| B | SET 만 발행, refresh 는 유지 | 재로그인 없음. RP 가 SET 을 처리해야만 안전 |
| **C** | 권한 **제거** 시에만 폐기, 추가는 SET 만 | **채택** |

권한 추가는 확대라 급하지 않고, 제거는 축소라 즉시 반영돼야 한다. `roles` 회수가 이미 폐기하는 것과
일관된다.

**단, refresh 폐기가 모든 RP 를 지켜 주지는 않는다.** heliopause 는 refresh token 을 **의도적으로
받지 않는다** — 로그인 시 ID 토큰을 한 번 검증하고 이후는 자체 세션 쿠키로 간다. 이런 RP 에게
refresh 폐기는 아무것도 닫아 주지 못하고, **인가 상태를 되돌리는 수단이 SET 하나뿐이다.**

C 를 채택하되, C 가 안전망이라고 착각하지 않는 것이 중요하다. **실질 보안 통제는 §5 의 SET 이고
refresh 폐기는 보조다.** 이것이 아래 §6 에서 SET payload 를 앞으로 당기는 이유다.

---

## 6. 단계와 규모

각 단계가 독립적으로 배포 가능하다. 중단해도 깨지지 않는다.

| 단계 | 내용 | 규모 | 배포 가능 |
|---|---|---|---|
| 1 | 스키마 2테이블 × 3방언 + `db:generate:all` | 소 | ✅ 미사용 테이블 |
| 2 | `listActiveEntitlements()` + 클레임 3곳 + 예약목록 | 소 | ✅ 권한 0개 → 클레임 없음 |
| **3** | **SET payload 를 `{ roles, entitlements }` 로 (§5 payload)** | 소 | ✅ **RP 계약 확정점** |
| 4 | 권한 정의 UI (§4-1) | 중 | ✅ |
| 5 | 사용자별 배정 UI (§4-2) + 감사 이벤트 | **중~대** | ✅ 여기서부터 실사용 |
| 6 | SET 발행 지점 확장 + refresh 정책 C (§5) | 소 | ✅ |

**단계 3 을 UI 앞으로 당겼다.** 원래 마지막에 뒀는데, heliopause 가 SET 을 구현하겠다고 확정했기
때문이다(답신 Q3). 그쪽이 `{ roles }` 만 보고 파서를 만든 뒤 우리가 키를 추가하면 그쪽 코드를 다시
건드려야 한다. **payload 모양을 먼저 고정하면 그 재작업이 통째로 없어진다.**

단계 3 시점에 `entitlements` 는 항상 `[]` 다 — 권한을 정의할 UI 가 아직 없기 때문이다. 스텁이
아니라 단계 2 에서 만든 실제 함수가 실제로 빈 결과를 반환하는 것이고, 단계 5 부터 값이 찬다.
그 사이에도 계약은 이미 최종형이다.

> **마이그레이션 주의** — 프로젝트 규칙(`CLAUDE.md`)상 `bun run db:generate:all` 까지만 수행하고
> `drizzle-kit migrate`/`push` 는 **실행하지 않는다.** 생성된 `drizzle/*.sql` 을 사용자에게 보고하고
> 적용을 요청한다. (`db:generate` 는 sqlite 전용이므로 3방언 변경에는 `:all` 을 쓴다 —
> `package.json:20-24`.)

**기존 데이터 마이그레이션은 없다.** 직교 추가이므로 기존 배정은 손대지 않는다.

핸드오프의 "UI 가 절반 이상" 은 대체로 맞다 — 단계 4·5 가 전체의 절반 남짓이다. 다만 단계 4 는
`serviceRoles` UI 복제라 실질 신규 작업은 단계 5 하나다.

---

## 7. 이 설계 밖으로 미룬 것

- **`isNull(revokedAt)` 필터가 지금 아무 일도 하지 않는다.** (heliopause 답신에서 발견)
  `service-permissions.ts:49` 의 이 조건은 §1-1 대로 값이 절대 채워지지 않으므로 **항상 참**이다.
  즉 **안전 검사처럼 보이는 죽은 코드**이고, 다음 사람이 "회수된 배정은 걸러진다" 고 읽을 여지가
  크다 — 실제로 걸러 주는 것은 하드 삭제 쪽인데 이 줄만 봐서는 알 수 없다.
  고치는 방향이 둘로 갈린다: **필터를 지워** 하드 삭제가 유일한 회수 경로임을 코드가 말하게 하거나,
  **소프트 회수로 바꿔** 다른 테이블(`sessions`·`oidcRefreshTokens`·`trustedDevices`)과 맞추거나.
  후자는 `revokeAssignment()` 의 동작 변경이라 범위가 넓다. **이 설계와 독립이므로 별건으로 다룬다.**
- **관리자 강제 로그아웃이 RP 에 도달하지 않는다.** (회신2 작성 중 발견)
  `admin/user-actions/security.ts` 의 `sessions_revoked` 액션은 `revokeAllUserSessions()` +
  `revokeAllUserRefreshTokens()` 만 하고 **back-channel logout 을 보내지 않는다.** back-channel logout
  발화점은 사용자 로그아웃 경로 3곳뿐이다(`oidc/end-session/+server.ts:185` ·
  `(auth)/logout/+page.server.ts:48` · `saml/slo/+server.ts:58`) — 관리자 경로에서 부르는 곳이 없다.
  관리자가 "강제 로그아웃" 을 눌러도 RP 세션은 살아 있다. 자체 세션 쿠키를 쓰는 RP(heliopause 등)
  에서는 특히 그렇다.
  **결과: 관리자 측에서 그런 RP 세션에 도달하는 수단이 현재 SET 하나뿐이다.** 이것이 §5 에서
  "실질 통제는 SET" 이라고 적은 이유의 나머지 절반이다.
  heliopause 는 **필요하다고 답했다**(답신2) — 다만 순서는 당기지 말 것.
- **back-channel logout 의 타깃 탐색이 단명 행에 묶여 있다.** ⚠️ **위 항목보다 큰 문제다.**
  (답신2 회신 준비 중 발견 — "메꾸는 작업 자체는 크지 않다" 던 위 문장이 틀렸다.)
  `getOidcBackchannelTargets()`(`oidc/logout.ts:54`)는 대상 클라이언트를 **`oidcGrants` 또는
  미폐기 `oidcRefreshTokens` 행**으로만 찾는다(`:55-64`). 그런데,
    - `oidcGrants` 는 authorization code(수 분 TTL)이고 만료되면 GC 가 **삭제**한다
      (`db/gc.ts:198` — "미사용·소진 무관"). Workers 에서는 요청당 확률 샘플링으로 돌아
      삭제 시점이 비결정적이다(`gc.ts:276`).
    - `oidcRefreshTokens` 는 `offline_access` scope + 클라이언트의 `refresh_token` grant 허용이
      있어야만 발급된다(`oidc/token/+server.ts:514`).
  **따라서 `offline_access` 를 안 쓰고 자체 세션을 오래 유지하는 RP 는 grant 가 GC 된 뒤
  back-channel logout 으로 도달할 수 없다** — 타깃으로 탐색되지 않기 때문이다. 관리자 강제
  로그아웃에 배선하더라도 마찬가지다. heliopause 가 정확히 이 형태다(scope 에 `offline_access`
  없음, 자체 세션 8시간).
  **즉 위 항목은 "발화점 추가" 가 아니라 "내구성 있는 타깃 탐색 추가" 다.** 후보:
  (a) 토큰 발급 시 (sessionId, clientId) 를 별도 테이블에 기록, (b) **주체 단위 —
  `userServiceAssignments` 기반으로 해당 사용자가 접근 권한을 가진 클라이언트에 발송**.
  (b)가 heliopause 가 선호한 주체 단위 의미론과 일치하고 이미 있는 테이블을 쓰지만,
  `allowAllUsers` 클라이언트는 배정 행이 없어 누락된다 — 별건으로 다룰 때 확정한다.
- **`roles`/`roles_label` 이 예약 클레임 목록에 없다.** `attributesJson` 에 `{"roles": [...]}` 를 넣으면
  실제 역할을 덮어쓴다(`token/+server.ts:22` 목록에 부재, `:143-145` 에서 머지). `entitlements` 는
  이번에 목록에 넣지만 `roles` 는 별도 판단이 필요해 손대지 않는다 — 기존 RP 가 이 동작에 의존 중일
  수 있다.
  **우선순위가 올라갔다:** heliopause 가 인가를 entitlement 로 옮긴 뒤에도 `roles`/`roles_label` 을
  표시용으로 계속 쓰겠다고 확정했다(답신 Q5). 수명이 짧은 레거시가 아니라 **오래 남는 클레임**이다.
- **`groups` 문서화(핸드오프 §3).** 이 설계와 독립이고 훨씬 값싸다. 별도로 처리한다.
- **`sub = users.id` 계약 명시(핸드오프 §8).** 동일. `token/+server.ts:98` 옆 주석 한 줄이면 된다.
  heliopause 의 OTP 검증은 **아직 구현 전**이지만 설계가 이 성질에 의존한다(답신 §8).
- **multi-role.** 핸드오프 §4 대로 하지 않는다.
- **`groups` 의 의미 변경.** 핸드오프 §6 대로 하지 않는다.

---

## 8. 착수 전 확정할 것

heliopause 답신(2026-08-06)으로 **1·2 확정, 3 만 남았다.**

1. ~~refresh token 정책 A/B/C~~ → **C 확정** (§5). 단, heliopause 는 refresh token 을 받지 않으므로
   그쪽에는 무영향이고 실질 통제는 SET 이다.
2. ~~클레임 이름~~ → **`entitlements` 확정** (§3-1).
3. **SAML attribute 이름** (§3-2) — **미정.** heliopause 는 OIDC 만 쓰므로 소비자 의견이 없다.
   SAML SP 를 붙이는 시점에 정해도 늦지 않다. 그때까지 단계 2 의 SAML 발행은 보류해도 무방하다.

**단계 1~3 은 지금 착수 가능하다.** 3번은 단계 2 의 SAML 부분에만 걸린다.
