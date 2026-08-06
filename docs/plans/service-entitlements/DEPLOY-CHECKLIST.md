# 배포 전 점검 — service entitlements 브랜치

작성 2026-08-06 · 대상 브랜치 `feat/service-entitlements`

여기 있는 것은 **코드로 끝낼 수 없어 사람이 확인해야 하는 것들**이다. 독립 리뷰 두 건에서
나온 항목 중 실제 환경 접근이 필요한 것을 모았다. 나머지 지적은 전부 코드에 반영했다.

---

## 1. 마이그레이션 적용

브랜치에 마이그레이션이 **두 벌** 있다. 순서대로 적용한다.

| 순서 | D1 | PostgreSQL | MySQL | libSQL |
|---|---|---|---|---|
| ① entitlement 테이블 2개 | `0033_colossal_bloodaxe` | `pg/0016_talented_lockheed` | `mysql/0016_cooing_giant_girl` | `sqlite/0016_jazzy_starfox` |
| ② `revoked_at` 컬럼 제거 | `0034_jazzy_spitfire` | `pg/0017_loud_catseye` | `mysql/0017_same_silverclaw` | `sqlite/0017_needy_madelyne_pryor` |
| ③ `oidc_client_sessions` 추가 | `0035_square_speed_demon` | `pg/0018_smiling_nuke` | `mysql/0018_living_colonel_america` | `sqlite/0018_tricky_goblin_queen` |

> pg 는 ①이 이미 적용돼 있다(FK 이름 길이 문제로 한 번 재생성·재적용함). ②만 남았다.

### ② 적용 전 — 컬럼이 정말 비어 있는지 확인

`user_service_assignments.revoked_at` 을 **삭제**한다. 이 컬럼을 쓰는 코드는 처음부터 없었으므로
전부 NULL 이어야 하지만, 손으로 넣은 값이 있으면 사라진다.

```sql
SELECT COUNT(*) AS not_null_count
  FROM user_service_assignments
 WHERE revoked_at IS NOT NULL;
```

**0 이 아니면 적용하지 말고 알려 달라.** 그 경우 컬럼을 살리고 소프트 회수를 제대로 구현하는
쪽이 맞다.

---

## 2. `attributesJson` 에 `entitlements` 키를 쓰던 배정이 있는지

**이것만 유일하게 기존 RP 의 토큰을 바꿀 수 있다.**

`entitlements` 를 예약 클레임에 넣었으므로, 그전까지 `attributesJson` 에 그 이름의 키를 넣어
쓰던 배정이 있었다면 **그 클레임이 토큰에서 사라진다.** 권한 기능을 쓰지 않던 RP 에게는
예고 없는 클레임 회귀다.

```sql
SELECT id, tenant_id, user_id, service_type, service_ref_id
  FROM user_service_assignments
 WHERE attributes_json LIKE '%"entitlements"%';
```

같은 이유로 `roles` / `roles_label` / `groups` 도 이번에 예약했다. 이쪽은 **원래 위조 경로**였으므로
막는 것이 맞지만, 그 경로로 클레임을 넣어 쓰던 곳이 있으면 역시 사라진다.

```sql
SELECT id, tenant_id, user_id, attributes_json
  FROM user_service_assignments
 WHERE attributes_json LIKE '%"roles"%'
    OR attributes_json LIKE '%"roles_label"%'
    OR attributes_json LIKE '%"groups"%';
```

**행이 나오면 해당 RP 와 조율한 뒤 배포한다.** 0 행이면 무영향이다.

---

## 3. D1 에서 FK cascade 가 실제로 도는지

**이번 브랜치에서 cascade 는 "정리 편의" 가 아니라 권한을 회수하는 메커니즘이다.**
`user_service_entitlements` 는 배정과 정의에 `ON DELETE CASCADE` 로 매달려 있고, 배정 회수와
정의 삭제가 그것에 의존한다.

테스트는 libSQL 에 `PRAGMA foreign_keys = ON` 을 걸고 돌지만(`test/integration/harness.ts`),
**D1 이 프로덕션에서 FK 를 강제하는지는 코드로 확인할 수 없다.** 프리뷰 D1 에서 한 번 확인한다.

```sql
-- 프리뷰 D1 에서
INSERT INTO service_entitlements (id, tenant_id, service_type, service_ref_id, key, label)
VALUES ('t-ent', '<tenant>', 'oidc', '<client-uuid>', 'probe.key', 'probe');

-- 아무 배정 id 로
INSERT INTO user_service_entitlements (id, tenant_id, assignment_id, service_entitlement_id)
VALUES ('t-use', '<tenant>', '<assignment-uuid>', 't-ent');

DELETE FROM service_entitlements WHERE id = 't-ent';

-- 0 이어야 한다. 1 이면 cascade 가 안 도는 것 → 애플리케이션 레벨 삭제가 필요하다.
SELECT COUNT(*) FROM user_service_entitlements WHERE id = 't-use';
```

**1 이 나오면 알려 달라.** 회수 경로에 명시적 DELETE 를 넣어야 한다.

---

## 4. heliopause 통지

SET payload 에 `exp` / `txn` 을 추가했다(회수가 역순 도착으로 되돌아가는 것을 RP 가 막을 수 있게).
`회신4-heliopause.md` 에 정리해 뒀다 — 그쪽이 파서를 만들기 전에 전달돼야 한다.

---

## 코드로 처리한 것 (참고, 확인 불필요)

리뷰 지적 중 아래는 전부 반영했고 테스트로 고정했다.

- 정의 삭제 시 보유자별 감사(key 포함) + refresh 폐기 + SET
- `roles`/`roles_label`/`groups` 예약 — attributesJson 위조 차단
- 만료 변경의 감사·SET·refresh(활성↔비활성 전이)
- 죽은 배정에 권한 사전 적재 차단
- 동시 제출 409(원자적 적용)
- 읽기 경로의 테넌트·서비스 재확인
- 교차 테넌트 테스트(뮤테이션으로 실효성 확인)
- entitlement key 소문자 정규화
- 관리자 강제 로그아웃의 RP 통지(주체 단위 탐색)
- 세션 단위 로그아웃 통지의 내구성(`oidc_client_sessions`) — grant GC 후에도 도달
- 서비스 TOTP API 성공/실패 감사
- 클라이언트 삭제 시 role/entitlement 정의 정리

## 미뤄 둔 것 — 없음

리뷰 지적과 별건을 모두 처리했다. 마지막까지 남아 있던 둘도 닫았다:

- **SAML 갈래** — 속성명 `Entitlements` 로 확정하고 발행 + SP 정의 UI 를 같은 커밋에 넣었다.
- **CSRF 이중 제출 토큰** — 처음에는 "entitlement 에만 붙이면 나머지가 다른 방식으로 보호되는
  것처럼 보인다" 는 이유로 넣지 않았는데, 그 판단의 결론은 하지 말자가 아니라 **화면 전체를
  한 번에 맞추자**였다. 상세 화면 3곳의 액션 25개와 폼 25개에 적용했다(수가 맞는 것을 확인).
