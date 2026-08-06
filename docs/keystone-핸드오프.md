# KeyStone 핸드오프 — 인가 클레임 모델에 대한 제안

작성 2026-08-06 · 근거: KeyStone `main` 실측(파일·행 인용은 그 시점 기준)

---

## 이 문서를 받는 사람에게

heliopause 는 호스트 방화벽 관리 도구다. 오퍼레이터 콘솔에 OIDC 로그인을 붙이면서 KeyStone 을
IdP 로 붙였고, **인가를 어느 클레임으로 할 것인가**에서 한 번 잘못 갔다가 되돌렸다. 그 과정에서
KeyStone 쪽에 남길 가치가 있다고 판단한 것을 정리한다.

heliopause 쪽 요구는 이 문서에 없다. **이미 지금 KeyStone 으로 해결했고**, 아래 제안은 그것과
독립적으로 KeyStone 자체의 품질에 대한 것이다. 급한 것이 아니며, 안 해도 우리는 막히지 않는다.

**전제 하나만 공유한다.** heliopause 에서 "승인" 은 방화벽 규칙을 실제로 바꾸는 행위다. 그래서
"누가 무엇을 할 수 있는가" 가 JSON 텍스트가 아니라 모델링된 사실이어야 한다는 관점에서 아래를
썼다. 그 관점이 과한 서비스도 많다는 것을 안다.

---

## 1. 지금 KeyStone 에는 그룹 개념이 셋이다

실측한 것을 그대로 적는다.

|             | 출처                                      | 개수      | 발행 클레임              |
| ----------- | ----------------------------------------- | --------- | ------------------------ |
| 조직 소속   | `departments` · `teams` · `parts`         | 여럿      | `groups`                 |
| 서비스 역할 | `serviceRoles` + `userServiceAssignments` | **하나**  | `roles` · `roles_label`  |
| 배정 속성   | `userServiceAssignments.attributesJson`   | 자유 형식 | 임의 키를 ID 토큰에 머지 |

근거:

- `src/lib/server/org/membership.ts:47` `membershipToGroups()` — `departments`·`teams`·`parts` 를
  순회해 코드(없으면 이름)를 모은다.
- `src/routes/oidc/token/+server.ts:155` — `groups` scope 가 있으면 그 결과를 `groups` 클레임으로.
- `src/routes/oidc/token/+server.ts:136-139` — `getActiveAssignment()` 로 배정 하나를 가져와
  `roles = [assignment.role.key]`. 배열이지만 원소는 항상 하나다.
- `src/lib/server/db/schema.pg.ts:509` —
  `uniqueIndex("user_service_assignments_user_service_uidx").on(tenantId, userId, serviceType, serviceRefId)`.
  **"역할 하나" 는 쿼리 선택이 아니라 스키마 제약이다.**

---

## 2. 우리가 밟은 함정

heliopause 는 처음에 **`groups` 로 인가하려고 했다.** 이름이 그렇게 읽힌다 — OIDC 에서 `groups` 는
인가에 쓰라고 있는 것처럼 보이고, 여러 개가 오므로 권한 집합처럼 보인다.

그런데 `groups` 는 **인사 구조**다. 이걸 인가에 쓰면:

- 팀 이동이 보안 경계를 움직인다
- 부서 개편이 방화벽 변경 권한을 재배정한다
- 조직도를 고치는 사람과 권한을 주는 사람이 분리되지 않는다

우리는 코드를 읽다가 `membershipToGroups` 를 보고 되돌렸다. **읽지 않았으면 그대로 갔을 것이다.**
그리고 다음에 KeyStone 을 붙이는 사람도 같은 길로 갈 가능성이 높다고 본다.

이것이 이 문서를 쓰는 이유다. 기능이 없다는 이야기가 아니라, **있는 것이 오해되기 쉽다**는 이야기다.

---

## 3. 가장 값싼 개선 — 문서 한 줄

스키마를 건드리지 않고 대부분의 효과를 낼 수 있다.

> `groups` 클레임은 **조직 소속**이다. 인가에 사용하지 말 것. 서비스 권한은 `roles` 를 쓴다.

README 의 엔드포인트 표나 클레임 설명 옆, 그리고 가능하면 클라이언트 등록 화면의 scope 설명에
같이 두면 좋겠다. **우리가 필요했던 것은 이 한 줄이었다.**

---

## 4. multi-role 은 권하지 않는다

`user_service_assignments_user_service_uidx` 를 풀어 역할을 여러 개 허용하는 방향은 두 가지를
놓친다고 본다.

**역할과 권한은 다른 것이다.** 역할이 여럿이면 "이 사람의 역할은?" 에 답이 여러 개가 되고,
감사 로그·관리 UI·`roles_label` 이 즉시 애매해진다. 역할은 하나로 두고 권한을 따로 두는 쪽이
대부분의 IdP 가 택한 모양이고, 그럴 만한 이유가 있다고 생각한다.

**비용도 좁지 않다.** 단수를 전제하는 호출자가 5개 파일 11곳이다:

```
src/lib/server/access/service-permissions.ts   2
src/lib/server/admin/user-actions/service.ts   3
src/routes/oidc/token/+server.ts               2
src/routes/oidc/userinfo/+server.ts            2
src/routes/saml/sso/+server.ts                 2
```

거기에 스키마가 **3개 방언**(`schema.pg.ts` · `schema.mysql.ts` · `schema.sqlite.ts`)에 중복돼 있고,
관리 UI 도 단일 선택 전제다.

---

## 5. 제안 — `groups`·`roles` 와 직교하는 entitlement

권한을 세 번째 축으로 **모델링**하는 방향을 제안한다.

```
serviceEntitlements       서비스가 정의하는 권한 키 (serviceRoles 와 같은 모양)
userServiceEntitlements   사용자 ↔ 권한, 다대다
    → 새 클레임으로 발행 (예: entitlements)
```

`attributesJson` 에 `perms: [...]` 를 넣는 것으로도 **오늘 당장** 같은 효과가 나온다. 그럼에도
모델링을 제안하는 이유는 넷이다.

- **참조 무결성** — 오타가 조용히 통과하지 않는다. 자유 텍스트 권한은 `pubish` 가 아무 일도 안
  하면서 아무도 알려주지 않는다.
- **열거 가능** — "publish 권한을 가진 사람 전부" 에 답할 수 있다. 감사에서 이 질문이 먼저 나온다.
- **부여 이력** — `userServiceAssignments` 가 이미 `grantedBy`·`grantedAt`·`expiresAt`·`revokedAt`
  을 들고 있다. 같은 패턴을 권한에도 주면 "언제 누가 줬는가" 가 공짜로 따라온다.
- **UI 에서 보인다** — 체크박스로 보이는 권한과 JSON 필드에 적힌 권한은 운영 난이도가 다르다.

### 규모 추정

| 항목                   | 비용   | 비고                                                                  |
| ---------------------- | ------ | --------------------------------------------------------------------- |
| 스키마 2테이블 × 3방언 | 중     | `serviceRoles` 를 그대로 본뜨면 된다                                  |
| 클레임 발행            | 소     | `token` · `userinfo` · `saml/sso` — `membershipToGroups` 와 같은 자리 |
| 관리 UI                | **대** | 권한 정의 + 사용자별 배정. 이 작업의 절반 이상                        |
| 기존 배정 호환         | 소     | 직교 추가라 데이터 마이그레이션이 필요 없다                           |

**UI 가 절반 이상이고, UI 없는 권한 모델은 `attributesJson` 과 실질적으로 같다.** 착수한다면 UI 를
범위에 넣고 시작하는 편이 낫다고 본다.

---

## 6. 하지 않는 편이 낫다고 보는 것

**`groups` 의 의미를 바꾸는 것.** 이미 그 클레임을 조직 정보로 쓰는 RP 가 있을 수 있고, 조직 소속을
내보내는 것 자체는 유효한 기능이다. 이름을 뺏지 말고 **옆에 세우는** 편이 낫다.

**heliopause 를 기다리게 하는 것.** 아래 7절을 참조.

---

## 7. heliopause 는 이것을 기다리지 않는다

우리는 **누적 등급 역할**로 진행한다. 역할 하나로 아래를 전부 포함하는 사다리다.

```
viewer     사이트 뷰 조회
proposer   viewer + 플랜 제안
approver   proposer + 남의 플랜 승인
publisher  approver + VPC 에 push
admin      publisher + 자기 플랜 단독 승인
```

이 모양은 **KeyStone 변경 0** 으로 지금 동작한다. "승인은 하는데 push 는 안 하는 사람" 같은 직교
조합을 표현할 수 없지만, 우리 쪽 오퍼레이터가 한 명인 동안 그 조합에 실익이 없다.

entitlement 가 생기면 옮기는 비용도 작다 — 역할 키를 읽던 자리를 권한 키로 바꾸는 것뿐이다.

**묶으면 방화벽 콘솔 배포가 IdP 스키마 마이그레이션을 기다리게 된다.** 3개 방언 마이그레이션과 UI
작업이 끼면 그 대기가 짧지 않고, 그 사이 브라우저 접근은 계속 막혀 있다. 그래서 분리한다.

---

## 8. 우리가 실제로 쓰고 있는 것 (참고)

KeyStone 쪽에서 "누가 무엇을 쓰는지" 를 알아야 할 때를 위해 적어 둔다.

| 무엇        | 어떻게                                                                              |
| ----------- | ----------------------------------------------------------------------------------- |
| 로그인      | Authorization Code + PKCE(S256), confidential client                                |
| scope       | `openid profile email groups` — `groups` 는 표시용으로만 쓴다                       |
| 인가        | `roles` 클레임 (위 사다리)                                                          |
| 승인 시 OTP | `POST /api/totp/verify` — 서비스 토큰 + `{userId, code}`. `userId` 는 OIDC `sub` 다 |
| 로그아웃    | RP-initiated (`end_session`)                                                        |

`sub` 가 `users.id` 와 같다는 점(`token/+server.ts:98` `sub: user.id`)에 의존한다. 이 성질이 바뀌면
우리 OTP 검증이 조용히 깨지므로, 바꾸게 되면 알려주면 좋겠다.

**아직 안 쓰는 것 둘** — Back-channel Logout 과 Role Change URI. 후자는 특히 흥미롭게 보고 있다:
그룹·역할 클레임은 로그인 시점에 캡처되어 세션 수명 동안 캐시되므로, 권한을 회수해도 세션이
만료될 때까지 남는다. Role Change push 가 그것을 닫는다.
