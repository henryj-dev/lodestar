# 보류 3건 처리 기획서 — TOTP TOCTOU / i18n(en) / CRUD 팩토리+zod

> **상태: 완료 (병합됨). 이 문서는 실행 이력이며 현행 사양서가 아닙니다.**
> 미체크로 남은 항목은 당시 커밋/검증 게이트 절차이고, 작업 자체는 병합되었습니다.
> **마이그레이션의 실제 DB 적용 여부는 배포 환경에서 직접 확인하세요.**
> 현행 사양은 [README](../../../README.md) · [관리자 매뉴얼](../../ADMIN_GUIDE.md) 참조. (최종 확인: 2026-08-07)

> 대상: `improvement-report-2026-07-02.md` 에서 "의도적 보류"로 남긴 3건(argon2 제외).
> 조사(2026-07-04, 3개 Explore 에이전트) 결과를 종합한 실행 기획. 스키마 변경은 CLAUDE.md 규칙대로 `db:generate` 까지만.

---

## 배경 / 목표

앞서 이 3건은 (검증 그물 부재 / mysql partial-index drift 재생산 / 품질 담보 불가) 사유로 보류했으나, 조사 결과 **각각 저위험 실행 경로가 확인**되어 진행한다.

- **TOTP TOCTOU** — 동시 이중 등록을 방언 무관하게 DB 레벨로 차단.
- **i18n(en)** — 엔진에 ko 폴백 + SSR 로케일 결정을 넣고, 엔드유저 인증 플로우를 영어화.
- **CRUD 팩토리+zod** — 정형 4라우트(teams/parts/positions/departments)를 팩토리로 통합하고 zod 로 폼 검증 표준화.

---

## 범위 (In / Out)

### Phase A — TOTP TOCTOU (스키마 + 로직)

- **In**: `credentials` 3방언 스키마에 nullable `totpOwnerId` + 일반 unique index 추가. enroll/confirm 이 INSERT 를 try/catch 로 감싸 unique 위반을 409 로 변환. TOTP+백업코드 INSERT 원자화(dialect 분기). `db:generate` 로 마이그레이션 생성(적용 안 함).
- **Out**: 실제 마이그레이션 적용(사용자 몫). password 중복(별개 사안).

### Phase B — i18n(en) 엔진 + 엔드유저 영어화

- **In**: 엔진에 `en` 로케일 + **ko 폴백**(누락 키는 원본 key 대신 한국어). 루트 `+layout.server.ts` 신설로 SSR 로케일 결정(쿠키 → Accept-Language → 기본 ko), `+layout.svelte` 에서 `setLocale`, `app.html` lang 동적화. `en.json`(엔드유저 플로우: login/signup/mfa_login/find_id/find_password/reset_password + common ≈ 72키). 5개 auth `.svelte` 잔존 하드코딩을 t() 로. 간단한 언어 전환 UI(쿠키 설정).
- **Out**: **admin 콘솔 영어화**(내부 운영자용 → ko 폴백으로 한국어 유지). **서버(+page.server.ts) 에러 메시지 t() 전환**(서버 로케일 인지 리팩터가 커서 별도). 원어민 최종 검수(문구는 표준 auth 용어 기준으로 작성하되 검수 권고 명시).

### Phase C — CRUD 팩토리 + zod

- **In**: zod 도입(dependencies). `$lib/server/validation.ts` 확장 또는 신규 `$lib/server/admin/crud-factory.ts` 로 정형 4라우트(teams/parts/positions/departments) create/update/delete 를 팩토리화. 라우트별 훅으로 departments 계층검증·positions level 주입. zod 스키마로 폼 검증 표준화(status enum, 숫자 coerce). **부수 개선**: teams/parts 의 FK 무검증(존재하지 않는/타 tenant departmentId·teamId 삽입 가능한 latent 결함)을 팩토리 FK-검증 훅으로 차단. 팩토리·zod 로직 유닛 테스트.
- **Out**: 비정형 라우트(users/oidc-clients/saml-sps/skins/ldap-providers) 팩토리화(액션 다양성 커서 별도). signing-keys(방언 분기 특수).

---

## 코드베이스 사실관계 (조사 근거)

### TOTP

- `api/totp/enroll/confirm/+server.ts`: SELECT(43-48) → verifyTotp(50) → INSERT(56-64) 사이 락/제약 없음 = 완전한 TOCTOU. rate-limit(34-38)은 브루트포스용이라 동시요청 무관.
- `credentials`(schema.sqlite.ts:75-98 등 3방언): `type` enum(password/totp/webauthn/backup_code). webauthn/backup_code 는 사용자당 다수 정상 → `UNIQUE(userId,type)` 불가. `credentials_user_type_idx` 는 **비-unique**.
- signing-keys 는 sqlite/pg 는 partial unique index(`WHERE active=1`), **mysql 은 인덱스 없이 앱 트랜잭션만**(schema.mysql.ts:513-516 주석). → partial index 는 mysql drift 재생산이라 회피.
- **해법(조사 제안)**: nullable `totpOwnerId`(type='totp' 행만 userId 채움, 나머지 NULL) + **일반** `uniqueIndex(totpOwnerId)`. NULL 은 unique 검사 제외(4방언 표준) → totp 만 사용자당 1개 강제, 다른 type 무영향. 최종 방어는 INSERT try/catch → 409. `grant.ts:findAndConsumeGrant` 의 방언별 affectedRows/RETURNING 패턴이 참고 선례.

### i18n

- `i18n.svelte.ts`(53줄): `Locale="ko"` 만(3), `messages={ko}`(13-15), 누락 키 시 `return key`(37,42). `$state("ko")`(17) 클라이언트 전용.
- SSR 로케일 결정 **전무**: 루트 `+layout.server.ts`/`+layout.ts` 없음, `hooks.server.ts` 로케일 로직 없음. (profile 의 `locale` 필드는 OIDC claim 용, UI 언어와 무관.)
- `app.html:2` `lang="en"` 하드코딩(현재 ko 콘텐츠와 불일치 = 버그).
- `setLocale` 호출부 0건(전환 UI 없음).
- ko.json 469줄 27섹션. 엔드유저: login(5)/signup(9)/mfa_login(9)/find_id(8)/find_password(7)/reset_password(6) + common(28).
- auth `.svelte` 잔존 하드코딩: login(서브타이틀/구분자/패스키 라벨·에러), signup·reset placeholder. 서버 에러 메시지는 리터럴 하드코딩(범위 밖).

### CRUD/zod

- teams(118)/parts(126)/positions(94)/departments(173) create/update/delete 가 near-identical: requireAdminContext → formData → 수동 캐스팅 → fail(400) → tenant-scoped drizzle → recordAuditEvent(kind=`<entity>_<action>`) → `{created/updated/deleted:true}`.
- 고유부: departments `validateParentHierarchy`(self/순환/깊이8/참조무결성), positions `level` parseInt+isNaN. teams/parts 는 FK(departmentId/teamId) 무검증.
- UI 계약: `{error}` 와 `{create:true,error}` 만 의존. 성공 플래그(created 등)는 **어느 svelte 도 미소비**(enhance `result.type` 로 판정). → 성공 shape 자유.
- zod/valibot 미설치. 통합/e2e 테스트·DB 하네스 전무(순수 유닛 테스트만). audit `kind`는 `string`(enum 아님) → 파라미터화 용이.

---

## 접근법 / 대안 / 리스크

| Phase  | 접근                                                             | 대안(기각)                                                                | 리스크 & 완화                                                                                                                                                                                                                                    |
| ------ | ---------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A TOTP | nullable `totpOwnerId` + 일반 unique index + INSERT try/catch    | partial unique(mysql 미지원→drift), app 트랜잭션만(phantom-row race 잔존) | 스키마 변경 → parity 테스트가 3방언 동기화 강제. 적용은 사용자. 유닛 테스트 어려움(DB 필요) → 로직 리뷰 + build 로 검증                                                                                                                          |
| B i18n | 엔진 ko 폴백 + SSR 로케일(layout.server) + 엔드유저 en + 전환 UI | 클라이언트-only 로케일(하이드레이션 미스매치), 전면 번역(품질/UX 리스크)  | admin 은 ko 폴백 유지(부분영어 UX 문제 회피). SSR 로케일로 하이드레이션 안전. 번역 검수 권고 명시                                                                                                                                                |
| C CRUD | zod + 정형 4라우트 팩토리(훅 주입)                               | 전 라우트 일괄 팩토리(비정형 리스크), zod-only(중복 잔존)                 | **통합 테스트 부재가 최대 리스크** → (1) 팩토리·zod 를 순수 유닛 테스트로 커버, (2) 기존 동작 정확 보존(에러 shape/tenant 스코프/audit kind 회귀 금지), (3) **작성과 분리된 독립 에이전트 검증**(작성자≠검증자), (4) build/lint/typecheck 게이트 |

**공통 리스크**: Phase C 가 보안 민감(tenant 스코프/audit) 라우트를 건드림 → 검증 레인 분리 필수. Phase A/B/C 는 파일이 겹치지 않아 병렬 가능(단 각 Phase 내부 쓰기는 파일 겹침 시 직렬).

---

## 열린 질문 (승인 시 확정)

1. **Phase C teams/parts FK 검증 추가** — 현재 존재하지 않는/타 tenant FK 도 통과하는 latent 결함이 있다. 팩토리에서 FK 참조 검증을 **추가**할지(권장), 기존 동작 유지할지?
2. **Phase B 언어 전환 UI 위치** — auth 레이아웃(로그인 화면)에 소형 토글 배치로 충분한지, 아니면 이번엔 쿠키/Accept-Language 자동 판별만 하고 명시 토글은 생략할지?
3. **진행 순서** — 리스크 낮은 순(A → B → C) 직렬 권장. 병렬 원하면 A/B/C 동시 착수 가능(파일 비겹침).

---

## 산출물

- `docs/plans/deferred-followups/PLAN.md` (본 문서)
- 승인 후 `docs/plans/deferred-followups/TODO.md` (페이즈별 상세 투두)
