# heliopause 팀에 — entitlement 설계 회신 및 문의

회신 2026-08-06 · 원문: `docs/keystone-핸드오프.md`(2026-08-06)
근거: KeyStone `feat/workers-vpc-db` @ e45b80d 실측

---

## 상태부터

**설계만 했습니다. 코드는 0줄입니다.** 스키마도, 마이그레이션도 아직 없습니다.
설계안은 `docs/plans/service-entitlements/PLAN.md`, 실행 항목은 같은 폴더 `TODO.md` 에 있습니다.

§7 을 그대로 받았습니다 — **기다리지 마세요.** 누적 등급 사다리로 진행하시면 됩니다.
아래 질문들은 착수 시점을 정하기 위한 것이 아니라, 착수한다면 어떤 모양이어야 하는지에 대한
것입니다.

---

## 1. 채택한 것과 채택하지 않은 것

| 제안 | 결정 |
|---|---|
| §5 entitlement 를 세 번째 축으로 모델링 | **채택.** 설계 완료 |
| §4 multi-role 하지 말 것 | **채택.** `user_service_assignments_user_service_uidx` 안 건드립니다 |
| §6 `groups` 의미 변경하지 말 것 | **채택.** 이름 안 뺏고 옆에 세웁니다 |
| §3 문서 한 줄 | **아직 안 했습니다.** §5 와 독립이고 훨씬 값싼데 이번 범위에 안 넣었습니다 |
| §8 `sub = users.id` 계약 명시 | **아직 안 했습니다.** 아래 5절 |

§2 의 지적은 실측으로 확인했습니다. `groups` 의 의미를 설명하는 문장이 코드베이스에 **한 줄도
없습니다** — `docs/ADMIN_GUIDE.md:91` 은 scope 목록에 이름만 나열하고, `README.md` 는 `groups`·`roles`
를 아예 언급하지 않습니다. "읽지 않았으면 그대로 갔을 것" 은 과장이 아니었습니다.

---

## 2. 실측하며 정정한 것 둘

§5 의 논거 하나가 현재 코드와 맞지 않았고, §8 에 적으신 것 하나는 설계에 영향이 있었습니다.
두 건 다 그쪽 판단이 틀렸다는 뜻이 아니라, **바깥에서 읽으면 그렇게 보이는 게 자연스러운**
자리입니다.

### 2-1. "부여 이력이 공짜로 따라온다" — 지금은 아닙니다

`userServiceAssignments` 가 `grantedBy`·`grantedAt`·`expiresAt`·`revokedAt` 을 들고 있다는 건
맞습니다(`schema.pg.ts:502-505`). 그런데 **`revokedAt` 은 읽히기만 하고 아무도 쓰지 않습니다.**

- 읽기: `src/lib/server/access/service-permissions.ts:49` `isNull(userServiceAssignments.revokedAt)`
- 쓰기: **없음.** `revokeAssignment()` 는 `db.delete(...)` 로 행을 지웁니다
  (`src/lib/server/admin/user-actions/service.ts:218`)

같은 저장소에서 `sessions`·`oidcRefreshTokens`·`trustedDevices` 는 `.set({ revokedAt })` 를 하는데
assignment 만 하지 않습니다. 즉 회수 이력은 행이 아니라 **감사 로그에만** 남습니다
(`kind: "service_assignment_revoked"`).

그래서 새 테이블에 `revokedAt` 을 **넣지 않기로** 했습니다. 죽은 컬럼을 하나 더 만드는 대신,
이력은 지금 실제로 이력이 남는 자리 — 감사 이벤트 — 에 남깁니다. 부여 시점(`grantedBy`/`grantedAt`)은
행에 남으므로 "지금 이 권한을 누가 줬는가" 에는 답할 수 있습니다.

### 2-2. Role Change SET 의 payload 가 지금 `roles` 만 싣습니다

§8 에서 "아직 안 쓰는 것" 으로 Role Change URI 를 꼽으셨는데, **RP 쪽에서 안 쓰신다는 뜻으로
읽었습니다.** IdP 쪽 발행은 이미 동작합니다:

- `src/lib/server/oidc/role-change.ts:70` — `events: { [ROLE_CHANGE_EVENT]: { roles } }`
- `src/lib/server/admin/user-actions/service.ts:29` `emitRoleChangeSet()` — 부여/회수 직후 fire-and-forget

**여기가 설계에 영향이 있습니다.** entitlement 를 추가하면서 이 payload 를 그대로 두면,
`roles` 에 대해 이미 닫아 둔 구멍이 `entitlements` 에 대해서만 다시 열립니다 — 권한을 회수해도
세션 만료까지 남는, §8 에서 정확히 지적하신 그 문제입니다.

그래서 같은 event 객체에 키를 하나 더하는 것으로 설계했습니다:

```
{ roles }  →  { roles, entitlements }
```

기존 RP 는 `roles` 만 읽으므로 하위 호환입니다. **다만 이게 4절 질문 3번의 배경입니다.**

---

## 3. 설계 요약

상세는 `PLAN.md` 에 있고, 여기서는 그쪽 결정에 영향이 있는 것만 적습니다.

**테이블 2개** — `service_entitlements`(서비스가 정의하는 권한 키) + `user_service_entitlements`(다대다).
`serviceRoles` 를 본떴고 3방언(`pg`/`mysql`/`sqlite`)에 동형으로 넣습니다.

**클레임** — 권한 키 배열. **권한이 0개면 클레임을 아예 넣지 않습니다**(빈 배열도 안 넣음).
entitlement 를 정의하지 않은 기존 RP 의 토큰은 키 단위로 완전히 동일합니다.

**scope 게이트 없음** — `groups` 는 scope 로 게이트되지만 `roles` 는 배정 존재만으로 발행됩니다
(`token/+server.ts:137-140`). entitlement 는 인가 데이터이므로 `roles` 쪽 규칙을 따릅니다.

**배정 행을 참조합니다** — `user_service_entitlements` 가 `userId`+`serviceType`+`serviceRefId` 대신
`user_service_assignments.id` 를 FK 로 겁니다(ON DELETE CASCADE). 접근 배정 없이 권한만 가진 상태가
구조적으로 표현 불가능해지고, 기존 회수 경로가 그대로 cascade 됩니다.

**대가가 하나 있습니다** — 접근을 회수했다가 다시 부여하면 이전 권한은 복구되지 않습니다.
재부여 시 배정 행이 새로 생기기 때문입니다(하드 삭제 후 INSERT). 저희는 이게 더 안전한 기본값이라고
봤는데, 질문 4번으로 확인받고 싶습니다.

---

## 4. 묻고 싶은 것

답이 설계를 바꾸는 것만 추렸습니다. **모두 "모르겠다/상관없다" 도 유효한 답입니다** — 그 경우
저희 기본값으로 갑니다.

### Q1. 권한 축소 시 refresh token 을 폐기해야 할까요? ← 가장 중요

지금 배정 회수는 refresh token family 를 폐기합니다(`service.ts:234`). 주석(`:222-227`)이 설명하듯,
이게 없으면 탈권한 사용자가 refresh token 으로 **최대 30일간** 토큰을 계속 재발급받습니다.

권한 축소도 같은 성질인데, 배정 회수와 달리 세션을 끊는 비용이 큽니다 — 권한 하나 뺐다고 재로그인.

| | 동작 | 대가 |
|---|---|---|
| A | 축소 시 항상 refresh family 폐기 | 안전. 권한 조정마다 재로그인 |
| B | SET 만 발행, refresh 유지 | 재로그인 없음. **RP 가 SET 을 처리해야만 안전** |
| C | 권한 **제거** 시에만 폐기, 추가는 SET 만 | 절충 (저희 기본값) |

**그쪽 판단이 필요한 이유:** B 의 안전성이 heliopause 가 SET 을 구현하는지에 달려 있고,
A 의 비용을 실제로 무는 것도 그쪽 오퍼레이터입니다. §첫머리에서 "승인 = 방화벽 규칙을 실제로 바꾸는
행위" 라고 하셨으니, 재로그인 비용보다 즉시성이 중요할 수도 있다고 봅니다.

### Q2. 클레임 이름을 무엇으로 할까요?

`entitlements` / `permissions` / `perms`. 핸드오프에서 `entitlements` 를 예로 드셨고 저희도 그걸
기본값으로 뒀는데, **옮겨올 때 코드에서 읽는 건 그쪽입니다.** 짧은 걸 선호하시면 지금 바꾸는 게
쌉니다.

### Q3. Role Change SET 을 구현할 계획이 있나요? 있다면 대략 언제쯤인가요?

2-2 의 payload 변경 때문에 묻습니다.

- **구현 계획이 없다** → 저희는 Phase 5 를 마지막에 둡니다. 급할 것 없습니다.
- **구현할 생각이다** → 순서가 중요해집니다. `{ roles }` 만 보고 만드신 뒤 저희가 키를 추가하면
  그쪽 파서를 다시 건드려야 합니다. **처음부터 `{ roles, entitlements }` 를 가정하고 만드시는 편이
  낫습니다** — `entitlements` 가 없으면 `[]` 로 취급하시면 됩니다.

### Q4. 재부여 시 권한이 복구되지 않는 게 그쪽 운영에 문제가 되나요?

3절의 대가입니다. "접근을 잠깐 껐다 켜는" 운영 패턴이 있다면 매번 권한을 다시 체크해야 합니다.
저희는 접근 재부여가 이전 권한을 조용히 되살리는 게 더 위험하다고 봤는데, 실제 운영을 하시는
쪽 의견을 듣고 싶습니다.

### Q5. 누적 등급 사다리를 entitlement 로 분해하면 어떤 모양이 되나요?

§7 의 `viewer → proposer → approver → publisher → admin` 을 권한 키로 옮긴다면
`{ site.view, plan.propose, plan.approve, vpc.publish, plan.self_approve }` 같은 모양일 것 같은데,
맞나요?

**이걸 묻는 이유:** 실제 소비자가 정의할 키를 하나라도 손에 쥐고 설계를 검증하고 싶습니다.
지금은 모델이 추상적이라, 그쪽 사다리가 깔끔하게 분해되지 않는다면 그건 설계 결함의 신호입니다.
대충 스케치만 주셔도 충분하고, **확정 아니어도 됩니다.**

부수적으로 — 사다리를 entitlement 로 옮기신 뒤 `roles` 는 어떻게 하실 생각인지도 궁금합니다.
계속 두고 표시용으로 쓰실지, 아니면 entitlement 만 보실지에 따라 `roles_label` 의 수명이 달라집니다.

---

## 5. §3 과 §8 은 아직 안 했습니다

**§3 (문서 한 줄)** — "우리가 필요했던 것은 이 한 줄이었다" 고 하신 것, 맞다고 봅니다. 이번 범위에
안 넣었을 뿐이고 §5 를 기다릴 이유가 없는 항목입니다. `ADMIN_GUIDE.md:91` scope 표와 `README.md`
클레임 설명이 들어갈 자리입니다.

**§8 (`sub` 계약)** — `sub: user.id` 는 지금도 그대로입니다(`token/+server.ts:98`). OTP 검증이 여기
의존한다는 것을 알았으니, 바꾸게 되면 알리겠습니다. 다만 **지금은 저희 쪽 코드 어디에도 "이건 계약이라
바꾸면 안 된다" 는 표시가 없습니다** — 즉 다음 사람이 모르고 바꿀 수 있는 상태입니다. 이건 §3 과
같은 종류의 값싼 개선이라 같이 처리하는 게 맞다고 봅니다.

---

## 6. 마지막으로

핸드오프 문서가 유용했습니다. 특히 **"기능이 없다는 이야기가 아니라, 있는 것이 오해되기 쉽다는
이야기"** 라는 구분이 그랬습니다 — 저희가 §3 을 §5 보다 값싸다고 보게 된 이유이기도 합니다.

급한 답 필요 없습니다. Q1 과 Q3 만 언제든 주시면 나머지는 저희 기본값으로 진행해도 무방합니다.
