# 실행 투두 — 보류 3건 (병렬 A/B/C)

> **상태: 완료 (병합됨). 이 문서는 실행 이력이며 현행 사양서가 아닙니다.** (최종 확인: 2026-08-07)
> A/B/C 전부 구현·검증·커밋 완료. 이후 admin 콘솔 영어화(cc44d7c)·auth 서버 에러 i18n(1c8c5c0)으로 당초 "Out" 범위였던 항목도 추가 반영됨.
> 마이그레이션 생성분(d1 0019, pg/mysql/sqlite 0002)의 **실제 DB 적용 여부는 배포 환경에서 직접 확인하세요.**
> 후속 전수 개선은 `docs/plans/project-improvement-audit/` 참조. 현행 사양은 [README](../../../README.md) · [관리자 매뉴얼](../../ADMIN_GUIDE.md).

> 승인된 결정: 기획서 승인 · Phase C FK 검증 **추가** · Phase B 자동판별+**수동 토글** · **병렬 진행**(worktree 격리).
> 규칙: 스키마 변경은 `db:generate` 까지만(적용 금지). 커밋은 검증 통과 + 승인 후. 쓰기=Opus 위임, 검증=작성자와 분리된 독립 Opus 에이전트.
> 파일 경계: A/B/C 는 서로 파일이 겹치지 않아 worktree 병렬 안전. 각 Phase 내부는 단일 에이전트 직렬.

---

## Phase A — TOTP TOCTOU (스키마 + 로직)

**목적**: 동시 이중 TOTP 등록을 방언 무관하게 DB 레벨로 차단.

### A-1. `credentials` 3방언 스키마에 섀도 컬럼 + unique index 추가

- 파일: `src/lib/server/db/schema.sqlite.ts`, `schema.pg.ts`, `schema.mysql.ts`
- 작업: `credentials` 테이블에 `totpOwnerId: text("totp_owner_id")` (nullable) 추가. 각 파일 인덱스 배열에 **일반**(partial 아님) `uniqueIndex("credentials_totp_owner_uidx").on(t.totpOwnerId)` 추가.
- 수용 기준: 3방언 모두 동일 컬럼명(`totp_owner_id`)·동일 인덱스명. `where(...)` 절 없는 순수 unique index(mysql 포함 지원). `test/unit/schema-parity.test.ts` 통과(컬럼 parity).

### A-2. enroll/confirm 원자화 + unique 위반 → 409

- 파일: `src/routes/api/totp/enroll/confirm/+server.ts`
- 작업: (a) TOTP 크레덴셜 INSERT 시 `totpOwnerId: userId` 채움(다른 type INSERT 는 미설정=NULL 유지). (b) 사전 SELECT 체크는 사용자 친화적 빠른 실패로 유지하되, **실제 방어는 INSERT 를 try/catch 로 감싸 unique 위반 시 `throw error(409, "TOTP already enrolled for this user")`**. (c) TOTP INSERT + 백업코드 10개 INSERT 를 dialect 분기로 원자화: d1/sqlite → `db.batch([...])`, postgres/mysql → `db.transaction(async (tx) => {...})` (signing-keys `+page.server.ts` 패턴 참고). 실패 시 백업코드 고아 방지.
- 수용 기준: 두 동시 confirm 중 하나만 성공(두 번째는 409). 백업코드는 TOTP INSERT 성공 시에만 커밋. 기존 성공 응답 shape(`{ ok:true, backupCodes }`) 보존. rate-limit(C3) 유지.

### A-3. 마이그레이션 생성 (적용 금지)

- 작업: `DB_DIALECT=d1 bun run db:generate` + `db:generate:pg` + `db:generate:mysql` + `db:generate:sqlite`. 생성된 `drizzle/**` SQL·meta 커밋 대상. `migrate`/`push` **실행 금지**.
- 수용 기준: 4트랙 모두 `totp_owner_id` 컬럼 + unique index ADD 마이그레이션 생성. 적용은 사용자 몫으로 보고.

### A-검증 (독립 에이전트)

- `bun run test`(schema-parity 포함), `svelte-check`, `bun run lint`. TOCTOU 로직 리뷰(SELECT~INSERT 창이 있어도 DB unique 가 최종 결정하는지). 가짜 완료(스텁/skip) 없는지.

---

## Phase B — i18n(en) 엔진 + 엔드유저 영어화

**목적**: 엔진 ko 폴백 + SSR 로케일 결정, 엔드유저 인증 플로우 영어 제공, 자동판별+수동 토글.

### B-1. 엔진: en 로케일 + ko 폴백

- 파일: `src/lib/i18n.svelte.ts`
- 작업: `Locale` 타입에 `"en"` 추가. `import en from "./i18n/en.json"`, `messages = { ko, en }`. `t()` 를 수정해 **현재 로케일에서 키 실패 시 ko 로 폴백 후, ko 도 실패 시에만 원본 key 반환**(37·42행 로직 교체, `lookup(dict, keys)` 헬퍼 도입). `setLocale` 이 초기값을 서버 주입값으로 받을 수 있게 유지.
- 수용 기준: en 에 없는 키는 한국어로 표시(원본 key 노출 0). ko 로케일 동작 회귀 없음.

### B-2. SSR 로케일 결정 (루트 layout 신설)

- 파일: `src/routes/+layout.server.ts`(신규), `src/routes/+layout.svelte`(수정), `src/app.html`(수정)
- 작업: `+layout.server.ts` load 에서 로케일 판별 — **쿠키(`idp_locale`) → Accept-Language 헤더 → 기본 "ko"** 순. `data.locale` 반환. `+layout.svelte` 에서 `data.locale` 로 `setLocale()` 을 렌더 전(모듈 초기화 시점 또는 `$derived`/즉시 호출)에 적용해 하이드레이션 미스매치 방지. `app.html` 의 하드코딩 `lang="en"` 을 SSR 로케일 반영(`%sveltekit.html.lang%` 류 치환 또는 hooks transform)으로 동적화.
- 수용 기준: 쿠키/Accept-Language 에 따라 SSR·클라이언트 로케일 일치(하이드레이션 경고 없음). `<html lang>` 이 실제 로케일과 일치.

### B-3. en.json 작성 (엔드유저 플로우)

- 파일: `src/lib/i18n/en.json`(신규)
- 작업: ko.json 의 엔드유저 섹션을 영어로 번역 — `common`(28), `app`, `nav`, `login`(5), `signup`(9), `mfa_login`(9), `find_id`(8), `find_password`(7), `reset_password`(6) + 신규 추출 키(아래 B-4). admin/조직/oidc/saml/skins 등 내부 섹션은 **생략**(ko 폴백). 표준 auth 용어 사용, 문구는 자연스럽게. 파일 상단 주석에 "원어민 검수 권고".
- 수용 기준: 포함 섹션 키가 ko.json 과 1:1 대응(구조 동일). JSON 유효.

### B-4. auth `.svelte` 잔존 하드코딩 → t()

- 파일: `src/routes/(auth)/login/+page.svelte`, `signup/+page.svelte`, `reset-password/+page.svelte`
- 작업: login 의 서브타이틀·구분자("또는")·패스키 로딩/버튼 라벨·패스키 클라이언트 에러 4종, signup·reset placeholder 를 t() 키로 전환하고 해당 키를 ko.json·en.json 양쪽에 추가. (서버 `+page.server.ts` 에러 메시지는 범위 밖 — 손대지 않음.)
- 수용 기준: 대상 화면에 하드코딩 한국어 리터럴 0(서버 파일 제외). ko/en 양쪽 키 존재.

### B-5. 언어 전환 UI (수동 토글)

- 파일: auth 레이아웃 또는 소형 컴포넌트(신규, 예: `src/lib/components/LocaleToggle.svelte`) + 쿠키 설정 경로
- 작업: ko/en 토글. 클릭 시 `idp_locale` 쿠키 설정 후 리로드(또는 setLocale + 쿠키). auth 화면(로그인 등)에 배치.
- 수용 기준: 토글로 언어 전환되고 새로고침 후 유지(쿠키). SSR 로케일과 일관.

### B-검증 (독립 에이전트)

- `bun run build`(SSR), `svelte-check`, `lint`. 하이드레이션 미스매치 없는지, ko 폴백 동작, en 화면 확인. 가짜 완료 없는지.

---

## Phase C — CRUD 팩토리 + zod (정형 4라우트)

**목적**: teams/parts/positions/departments 를 팩토리로 통합, zod 로 폼 검증 표준화, teams/parts FK 검증 **추가**.

### C-1. zod 도입

- 파일: `package.json`
- 작업: `bun add zod` (dependencies). 락파일 동기화.
- 수용 기준: zod dependencies 등재. build 영향 없음.

### C-2. CRUD 팩토리 모듈

- 파일: `src/lib/server/admin/crud-factory.ts`(신규)
- 작업: tenant-scoped CRUD 팩토리 작성. 파라미터: drizzle 테이블, zod create/update 스키마, audit kind 접두사(`team`/`part`/…), 성공 shape, 그리고 **훅**: `beforeCreate/beforeUpdate`(검증·FK 참조 확인용, 실패 시 에러 메시지 반환), 선택적 load 조인 셀렉터. 공통 골격(requireAdminContext → formData → zod 검증 → tenant 스코프 insert/update/delete → recordAuditEvent → 성공 반환)을 생성. **에러 반환은 반드시 기존 계약**: create 실패 `fail(400,{create:true,error})`, update/delete 실패 `fail(400,{error})`.
- 수용 기준: 팩토리가 create/update/delete 액션 객체를 생성. tenant 필터·audit kind·에러 shape 를 기존과 동일하게 재현.

### C-3. 4라우트 팩토리 적용 + 훅

- 파일: `src/routes/admin/{teams,parts,positions,departments}/+page.server.ts`
- 작업: 각 라우트를 팩토리 호출로 재작성. zod 스키마 정의(status `z.enum`, level/displayOrder `z.coerce.number().int()`, optional `.trim()→null`). 훅 주입: **departments** = `validateParentHierarchy`(self/순환/깊이8/참조무결성 보존), **positions** = level 검증(zod 로 흡수), **teams** = departmentId 존재+동일 tenant FK 검증(신규 추가), **parts** = teamId 존재+동일 tenant FK 검증(신규 추가). load 도 팩토리/공통화(조인은 라우트별 셀렉터).
- 수용 기준: 네 라우트의 기존 동작 보존(생성/수정/삭제/목록, audit kind, tenant 스코프). teams/parts 는 존재하지 않는/타 tenant FK 를 이제 `fail(400)` 로 거부. UI(`{error}`/`{create:true,error}`) 무변경으로 동작.

### C-4. 유닛 테스트

- 파일: `test/unit/crud-factory.test.ts`(신규), `test/unit/admin-zod.test.ts`(신규)
- 작업: zod 스키마 검증(유효/무효 입력, status enum 거부, 숫자 coerce), 팩토리의 순수 로직(에러 shape 매핑, audit kind 생성) 테스트. DB 없이 가능한 범위.
- 수용 기준: 신규 테스트 통과. 전체 `bun run test` 그린.

### C-검증 (독립 에이전트)

- **작성자와 분리된 독립 Opus 에이전트**가 검증: 4라우트의 tenant 스코프·audit kind·에러 shape 회귀 없는지 diff 리뷰, FK 검증 추가가 올바른지, departments 계층검증 보존 확인. `bun run test`·`svelte-check`·`build`·`lint`. 가짜 완료 없는지.

---

## 통합 & 커밋 (STEP 7-8)

- 3개 worktree 변경을 기준 브랜치(`fix/security-hardening-phase1`)로 통합, 충돌 정리.
- 전체 게이트: `bun run test` · `svelte-check`(또는 `bun run check`) · `bun run lint` · `bun run build` 그린.
- Phase 별 논리 커밋(승인 후). 푸시는 사용자 요청 시에만.
- 스키마 마이그레이션 실제 적용은 사용자에게 요청.
