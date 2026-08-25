# Keystone 설정·CI 전수검사 보고서

## 감사 범위

- 대상: `.github/**`(워크플로 4종·dependabot·CodeQL 설정), 저장소 브랜치 보호·시크릿 등록 상태, 빌드/툴체인 설정(`vite`·`svelte`·`vitest`·`tsconfig`·`eslint`·`prettier`·`bunfig`·`.npmrc`·`lefthook`), 패키지 스크립트, `drizzle.config.ts`, 런타임 진입점(`server.js`·`shutdown.js`), 추적되는 설정 파일의 시크릿 노출
- 제외: 애플리케이션 소스(`src/**`) 로직 — 해당 범위는 [CODE_AUDIT_REPORT.md](./CODE_AUDIT_REPORT.md)
- 계기: `Secret Scan` 워크플로가 시크릿은 등록됐는데 액션에 전달되지 않아 실패한 건(PR #104). **"시크릿/설정이 선언과 실제 사이에서 끊기는" 같은 부류를 전부 훑는 것**이 이 감사의 목적이다.

모든 발견은 코드·API 응답·실제 실행 로그로 확증했으며, 근거에 출처를 명시한다.

## 요약

동일 부류(선언과 실제의 단절)가 **2건 더** 있었고, 그중 1건은 매 프로덕션 배포마다 조용히 발생 중이다.

| ID   | 심각도 | 항목                                              | 상태          |
| ---- | ------ | ------------------------------------------------- | ------------- |
| C-01 | 높음   | `CLOUDFLARE_ZONE_ID` 미등록 → 캐시 퍼지 항상 스킵 | 실제 발생 중  |
| C-02 | 높음   | `CI Required` 게이트가 선행 잡 실패 시 통과       | 도달 가능     |
| C-03 | 높음   | Gitleaks 가 머지 필수 체크가 아님                 | 실제 미적용   |
| C-04 | 중간   | 서드파티 액션 가변 태그 고정 (배포 토큰 노출면)   | 상시 노출     |
| C-05 | 중간   | `bun install` 이 lockfile 을 강제하지 않음        | 실측 확인     |
| C-06 | 중간   | postgres 방언 빌드가 CI 에서 미검증               | 상시          |
| C-07 | 중간   | `ci.yml`·`deploy.yml` 에 `permissions` 미선언     | 상시          |
| C-08 | 낮음   | `scripts/` 가 CodeQL·타입체크 양쪽에서 제외       | 상시          |
| C-09 | 낮음   | Node24 강제 opt-in 이 `deploy.yml` 에만 적용      | 불일치        |
| C-10 | 낮음   | `ci.yml` 이 merge commit 이 아닌 head 를 체크아웃 | 조건부        |
| C-11 | 낮음   | `WORKFLOW_PAT` 이 어디에서도 참조되지 않음        | 유휴 자격증명 |
| C-12 | 정보   | main 브랜치 리뷰 0건·커밋 서명 미요구             | 정책 판단     |

## 조치 현황

이 보고서와 함께 올라간 PR 이 코드로 고칠 수 있는 항목을 처리했다. 나머지는 저장소 설정 영역이라 별도 조치가 필요하다.

| ID   | 조치                                                                                    | 처리 주체       |
| ---- | --------------------------------------------------------------------------------------- | --------------- |
| C-01 | 스킵 로그를 `::warning::` 으로 승격해 무증상 실패를 없앰. **시크릿 등록 자체는 미처리** | 사용자 (시크릿) |
| C-02 | `needs.check-changes.result` 검사 추가 — 게이트 우회 차단                               | PR              |
| C-03 | 미처리 — 브랜치 보호 필수 컨텍스트 변경 필요                                            | 사용자 (설정)   |
| C-05 | 양쪽 워크플로 `bun install --frozen-lockfile`                                           | PR              |
| C-07 | 양쪽 워크플로 `permissions` 명시                                                        | PR              |

`permissions` 를 좁힐 때 `ci.yml` 에는 `pull-requests: read` 를 함께 넣었다. 저장소 기본 워크플로 권한이 `read`(전체 읽기)라
`contents: read` 만 선언하면 `dorny/paths-filter` 가 PR 이벤트에서 REST API 로 변경 파일을 조회하지 못해 오히려 `check-changes` 가
깨진다 (paths-filter README 가 해당 권한을 명시 요구).

C-04 / C-06 / C-08 이하는 이 PR 범위 밖으로 남겨 두었다.

## 발견 사항

### C-01 — `CLOUDFLARE_ZONE_ID` 미등록으로 캐시 퍼지가 매 배포마다 조용히 스킵됨

- 심각도: 높음
- 유형: 설정 단절 / 배포 후 stale 콘텐츠 / 무증상 실패

`Purge Cloudflare cache` 단계가 `secrets.CLOUDFLARE_ZONE_ID` 를 참조하지만 **해당 시크릿은 저장소에 등록돼 있지 않다.** 스텝은 빈 값을 보고 `exit 0` 으로 빠져나가므로 잡은 초록색으로 끝난다. gitleaks 건과 정확히 같은 부류이되, 그쪽은 **빨갛게 실패**해서 발견됐고 이쪽은 **초록색이라 9시간 넘게 아무도 몰랐다.**

근거:

- [deploy.yml:97](/Users/henry/github/henryj-dev/keystone/.github/workflows/deploy.yml:97) — `CLOUDFLARE_ZONE_ID: ${{ secrets.CLOUDFLARE_ZONE_ID }}`
- [deploy.yml:99-102](/Users/henry/github/henryj-dev/keystone/.github/workflows/deploy.yml:99) — 빈 값이면 메시지 출력 후 `exit 0`
- `gh secret list` 결과 — 등록 시크릿은 `CLOUDFLARE_ACCOUNT_ID` / `CLOUDFLARE_API_TOKEN` / `GITLEAKS_LICENSE` / `WORKFLOW_PAT` / `WRANGLER_JSONC` 5종뿐, `CLOUDFLARE_ZONE_ID` 없음
- 실행 로그 [run 32807039213](https://github.com/henryj-dev/keystone/actions/runs/32807039213) 1258행 `CLOUDFLARE_ZONE_ID: `(빈 값), 1260행 `CLOUDFLARE_ZONE_ID 시크릿이 없으므로 캐시 퍼지를 건너뜁니다.` — 배포는 성공(38s)했고 퍼지만 누락

영향: `idp.hyochan.site` 커스텀 도메인에 Cloudflare 캐시가 걸려 있다면 배포 후에도 구 자산이 계속 서빙된다. 인증 서버라 로그인 페이지 JS/CSS 가 stale 하면 실제 장애로 이어진다.

권장 조치:

- `CLOUDFLARE_ZONE_ID` 시크릿 등록 (Cloudflare 대시보드 → 해당 zone → Overview 우측 Zone ID)
- 또는 캐시 퍼지가 불필요하다면 스텝 자체를 제거 — **조용한 스킵을 남겨두지 않는다**
- 스킵 시 `::warning::` 을 남겨 로그에서 눈에 띄게 한다

### C-02 — `CI Required` 게이트가 선행 잡 실패 시 통과한다

- 심각도: 높음
- 유형: 머지 게이트 우회

`required` 잡은 `if: always()` 라 선행 잡이 실패해도 실행된다. 그런데 판정식이 `needs.check-changes.outputs.build-affected == 'true'` 를 보는데, **`check-changes` 잡 자체가 실패하면 이 output 은 빈 문자열**이 된다. 따라서 조건은 거짓이 되고 `echo "CI passed or skipped"; exit 0` 으로 빠져 **필수 체크가 초록색이 된다.**

근거:

- [ci.yml:96-108](/Users/henry/github/henryj-dev/keystone/.github/workflows/ci.yml:96) — `needs: [check-changes, ci]`, `if: always()`, `build-affected` 만 검사하고 `needs.check-changes.result` 는 보지 않음
- [ci.yml:48](/Users/henry/github/henryj-dev/keystone/.github/workflows/ci.yml:48) — `check-changes` 실패 시 `ci` 는 스킵됨
- 브랜치 보호 API 응답 — 필수 컨텍스트가 `["CI Required", "CodeQL"]` 이므로 이 잡이 곧 머지 게이트

도달 경로: `actions/checkout` 또는 `dorny/paths-filter` 가 실패하는 상황(액션 장애, 레이트리밋, 네트워크). 실제로 [run 32807039213](https://github.com/henryj-dev/keystone/actions/runs/32807039213) 에서 paths-filter 는 이미 `'before' field is missing in event payload` 경고를 낸 적이 있다.

권장 조치:

- `needs.check-changes.result != 'success'` 를 명시적 실패 조건으로 추가
- 회귀 확인: `check-changes` 를 일부러 실패시켰을 때 `CI Required` 가 빨간색이 되는지

### C-03 — Gitleaks 가 머지 필수 체크가 아니다

- 심각도: 높음
- 유형: 보안 게이트 미적용

`Secret Scan` 은 PR·push 양쪽에서 돌지만 **브랜치 보호의 필수 컨텍스트에 없다.** 시크릿이 포함된 PR 이 Gitleaks 빨간불 상태로도 머지된다.

근거:

- 브랜치 보호 API — `required_status_checks.contexts: ["CI Required", "CodeQL"]`, `Gitleaks` 부재
- [gitleaks.yml:4-7](/Users/henry/github/henryj-dev/keystone/.github/workflows/gitleaks.yml:4) — 트리거 자체는 정상(PR + push)

방금 PR #104 로 라이선스 전달을 고쳐 스캔이 동작하게 만들었지만, **게이트로는 여전히 작동하지 않는다.**

권장 조치:

- 필수 컨텍스트에 `Gitleaks` 추가
- 커밋 이력 스캔이라 기존 `.gitleaksignore` 지문 5건은 그대로 유지 필요

### C-04 — 서드파티 액션이 가변 태그로 고정돼 배포 토큰이 공급망에 노출된다

- 심각도: 중간
- 유형: 공급망 / 자격증명 탈취 가능성

모든 액션이 `@v7` / `@v4` / `@v3` / `@v2` 같은 **이동 가능한 태그**로 고정돼 있다. 태그는 업스트림에서 언제든 다른 커밋으로 옮길 수 있다. 특히 `deploy` 잡은 `CLOUDFLARE_API_TOKEN` 과 `WRANGLER_JSONC`(프로덕션 wrangler 설정 전문) 를 다루는데, 그 잡 안에서 서드파티 액션 `oven-sh/setup-bun@v2` 가 **이후 스텝이 실행할 `bun` 바이너리를 설치**한다.

근거:

- [deploy.yml:63](/Users/henry/github/henryj-dev/keystone/.github/workflows/deploy.yml:63) — `oven-sh/setup-bun@v2` 가 배포 잡 내부
- [deploy.yml:70](/Users/henry/github/henryj-dev/keystone/.github/workflows/deploy.yml:70), [deploy.yml:91](/Users/henry/github/henryj-dev/keystone/.github/workflows/deploy.yml:91) — 같은 잡 후속 스텝이 `WRANGLER_JSONC`·`CLOUDFLARE_API_TOKEN` 주입
- [gitleaks.yml:24](/Users/henry/github/henryj-dev/keystone/.github/workflows/gitleaks.yml:24) — `gitleaks/gitleaks-action@v3`
- [ci.yml:22](/Users/henry/github/henryj-dev/keystone/.github/workflows/ci.yml:22) — `dorny/paths-filter@v4`

인증·SSO 제품이라 배포 토큰 탈취의 파급이 일반 웹앱보다 크다.

권장 조치:

- 최소한 `oven-sh/setup-bun`·`dorny/paths-filter`·`gitleaks/gitleaks-action` 은 커밋 SHA 로 핀 고정 (`uses: oven-sh/setup-bun@<sha> # v2.x.x`)
- dependabot 의 `github-actions` 에코시스템이 이미 켜져 있어 SHA 핀도 자동 갱신 PR 이 온다 ([dependabot.yml:32-41](/Users/henry/github/henryj-dev/keystone/.github/dependabot.yml:32))

### C-05 — `bun install` 이 lockfile 을 강제하지 않는다

- 심각도: 중간
- 유형: 재현성 / 공급망

CI·배포 모두 `bun install` 을 플래그 없이 호출한다. **bun 은 CI 환경에서 frozen lockfile 을 자동 적용하지 않는다** — 실측으로 확인했다.

근거:

- [ci.yml:65](/Users/henry/github/henryj-dev/keystone/.github/workflows/ci.yml:65), [deploy.yml:66](/Users/henry/github/henryj-dev/keystone/.github/workflows/deploy.yml:66) — `run: bun install`
- 실측(bun 1.3.14): 락파일에 없는 의존성을 `package.json` 에 추가한 뒤 `CI=true bun install` 실행 → `Saved lockfile` 출력, 설치 성공, `exit 0`. 즉 `--frozen-lockfile` 은 기본값이 아니다.

영향: `bun.lock` 을 갱신하지 않고 `package.json` 만 고친 PR 이 CI 를 통과한다. 배포 시점에 semver 범위 내 신규 버전이 새로 해석돼 **락파일과 다른 트리가 프로덕션에 나갈 수 있다.**

권장 조치:

- `ci.yml`·`deploy.yml` 모두 `bun install --frozen-lockfile` 로 변경
- dependabot npm PR 이 `bun.lock` 을 함께 갱신하는지 첫 PR 에서 확인 (갱신하지 않으면 그 PR 들이 일제히 실패한다)

### C-06 — postgres 방언 빌드가 CI 에서 한 번도 검증되지 않는다

- 심각도: 중간
- 유형: 검증 공백 / 배포 시점 노출

배포는 `DB_DIALECT: postgres` 로 빌드하는데, **CI 에는 `DB_DIALECT` 가 전혀 없어 기본값 `d1` 로만 lint·check·test·build 가 돈다.** 즉 프로덕션에 나가는 번들 구성은 머지 전에 한 번도 빌드되지 않는다.

근거:

- [deploy.yml:84](/Users/henry/github/henryj-dev/keystone/.github/workflows/deploy.yml:84) — `DB_DIALECT: postgres` (주석도 "미설정 시 d1 로 번들링됨" 을 명시)
- `.github/workflows/` 전체에서 `DB_DIALECT` 는 위 1곳뿐
- [svelte.config.js:26-27](/Users/henry/github/henryj-dev/keystone/svelte.config.js:26) — `$db-active-schema`·`$db-active-driver` alias 가 방언별로 다른 파일로 해석됨
- [vitest.config.ts:11,16-17](/Users/henry/github/henryj-dev/keystone/vitest.config.ts:11) — 테스트도 sqlite 로 고정

완화 요소: [test/unit/schema-parity.test.ts](/Users/henry/github/henryj-dev/keystone/test/unit/schema-parity.test.ts) 가 3방언 스키마의 테이블·컬럼·nullable·타입계열·인덱스 parity 를 강제한다. **스키마 형상 drift 는 이미 잘 막힌다.** 남는 공백은 그 위의 빌드/번들 계층 — `driver-pg.ts` 배선, `postgres` 패키지의 Workers 번들링, vite `define` 치환 결과다.

권장 조치:

- CI 에 `DB_DIALECT: postgres` 빌드 잡 1개 추가 (matrix 로 d1/postgres 병렬)
- 최소한 `bun run build` 만이라도 postgres 로 한 번 더 돌린다

### C-07 — `ci.yml` 과 `deploy.yml` 에 `permissions` 선언이 없다

- 심각도: 중간
- 유형: 최소 권한 위반

`gitleaks.yml`·`codeql.yml` 은 `permissions` 를 명시하는데 `ci.yml`·`deploy.yml` 은 선언이 없어 저장소 기본 토큰 권한을 그대로 상속한다.

근거:

- [gitleaks.yml:20-21](/Users/henry/github/henryj-dev/keystone/.github/workflows/gitleaks.yml:20), [codeql.yml:17-20](/Users/henry/github/henryj-dev/keystone/.github/workflows/codeql.yml:17) — 선언 있음
- `ci.yml`·`deploy.yml` — `permissions` 키 부재

권장 조치:

- 두 워크플로 최상단에 `permissions: { contents: read }` 추가

### C-08 — `scripts/` 가 CodeQL 과 타입체크 양쪽에서 빠져 있다

- 심각도: 낮음
- 유형: 검증 공백

`scripts/` 는 CodeQL 분석에서 제외돼 있고, 루트 `tsconfig.json` 에서도 제외돼 있다. `typecheck` 스크립트는 CI 에서 호출되지 않는다(`lint`·`check`·`test`·`build` 만 실행). 결과적으로 **`scripts/` 는 CodeQL·타입체크 어느 쪽에도 걸리지 않는다.**

근거:

- [codeql-config.yml:3-4](/Users/henry/github/henryj-dev/keystone/.github/codeql/codeql-config.yml:3) — `paths-ignore: scripts/`
- [tsconfig.json:18](/Users/henry/github/henryj-dev/keystone/tsconfig.json:18) — `exclude: ["scripts/**", ...]`
- [ci.yml:76-94](/Users/henry/github/henryj-dev/keystone/.github/workflows/ci.yml:76) — `typecheck` 미호출
- 해당 디렉터리 파일 — `reencrypt-secrets.ts`, `reset-admin-password.ts`, `verify-saml-encryption.ts`, `migrate-d1-to-pg.ts` 등 **시크릿·자격증명·암호화 키를 직접 다루는 스크립트**

완화 요소: ESLint 는 `.gitignore` 기반 무시만 적용하므로 `scripts/` 를 커버한다. `scripts/tsconfig.json` 도 존재하지만 CI 가 사용하지 않는다.

권장 조치:

- CI 에 `bunx tsc --noEmit -p scripts/tsconfig.json` 추가
- CodeQL `paths-ignore` 에서 `scripts/` 제거 검토 (시크릿 취급 코드라 스캔 가치가 높다)

### C-09 — Node 24 강제 opt-in 이 `deploy.yml` 에만 적용돼 있다

- 심각도: 낮음
- 유형: 설정 불일치

`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` 를 둔 이유가 주석에 "`dorny/paths-filter` 등 미업그레이드 액션" 이라고 적혀 있는데, **같은 액션을 쓰는 `ci.yml` 에는 이 env 가 없다.**

근거:

- [deploy.yml:12-15](/Users/henry/github/henryj-dev/keystone/.github/workflows/deploy.yml:12) — env 및 사유 주석
- [ci.yml:22](/Users/henry/github/henryj-dev/keystone/.github/workflows/ci.yml:22) — 동일한 `dorny/paths-filter@v4` 사용, env 없음

권장 조치:

- 판단을 한쪽으로 통일한다 — `ci.yml` 에도 추가하거나, 전환이 이미 완료됐다면 `deploy.yml` 에서도 제거

### C-10 — `ci.yml` 이 merge commit 이 아닌 PR head 를 체크아웃한다

- 심각도: 낮음
- 유형: 검증 대상 불일치 / fork PR 미지원

`ci` 잡만 `ref: ${{ github.head_ref }}` 로 체크아웃한다. `check-changes` 잡은 기본값(merge ref)을 쓰므로 **두 잡이 서로 다른 트리를 본다.** 또한 `actions/checkout` 은 기본적으로 base 저장소를 대상으로 하므로, fork 에서 온 PR 은 해당 브랜치가 base 에 없어 체크아웃이 실패한다.

근거:

- [ci.yml:53-54](/Users/henry/github/henryj-dev/keystone/.github/workflows/ci.yml:53) — `with: ref: ${{ github.head_ref }}`
- [ci.yml:18-19](/Users/henry/github/henryj-dev/keystone/.github/workflows/ci.yml:18) — `check-changes` 는 `with` 없음

완화 요소: 브랜치 보호의 `strict: true`(up-to-date 요구)가 head 와 merge 결과의 괴리를 상당히 줄인다. 현재 기여가 같은 저장소 브랜치로만 이뤄져 fork 경로는 미발생.

권장 조치:

- `ref` 를 제거해 기본 merge ref 를 쓰거나, 두 잡의 체크아웃 방식을 일치시킨다

### C-11 — `WORKFLOW_PAT` 이 어느 워크플로에서도 참조되지 않는다

- 심각도: 낮음
- 유형: 유휴 자격증명

저장소 시크릿에 `WORKFLOW_PAT`(2026-05-07 등록)이 있으나 `.github/` 전체에서 참조가 없다. PAT 는 보통 기본 `GITHUB_TOKEN` 보다 넓은 권한을 갖기 때문에, 쓰이지 않는 채 남아 있으면 회수·만료 관리 대상에서 누락된다.

근거:

- `gh secret list` — `WORKFLOW_PAT` 존재
- `grep -rn 'WORKFLOW_PAT' .github/` — 결과 없음
- 워크플로가 참조하는 시크릿 6종 중 `WORKFLOW_PAT` 미포함

권장 조치:

- 용도가 없으면 삭제, 있으면 어디에 쓰는지 문서화

### C-12 — main 브랜치가 리뷰 0건·커밋 서명 미요구로 설정돼 있다

- 심각도: 정보 (정책 판단 영역)
- 유형: 저장소 정책

양호한 부분과 판단이 필요한 부분이 섞여 있어 사실만 기록한다.

근거 (브랜치 보호 API):

- 양호: `enforce_admins: true`, `allow_force_pushes: false`, `allow_deletions: false`, `required_status_checks.strict: true`
- 판단 필요: `required_approving_review_count: 0`, `required_signatures: false`, `required_linear_history: false`, `required_conversation_resolution: false`

1인 개발 저장소라면 리뷰 0건은 합리적 선택이다. 다만 인증 제품이라 **커밋 서명 요구**는 검토할 가치가 있다.

## 이상 없음으로 확인된 항목

부정 결과도 근거와 함께 남긴다.

- **추적 파일 내 시크릿 노출 없음** — `.env.example`·`wrangler.example.jsonc` 는 전부 플레이스홀더(`""`, `YOUR_D1_DATABASE_ID`, `your-very-long-random-secret-...`). `.mcp.json`·`.vscode/mcp.json`·`.vscode/settings.json` 도 공개 URL·에디터 설정뿐
- **`wrangler.jsonc`·`wrangler.prod.jsonc` 미추적** — `.gitignore:39-41` 로 무시되며 `git ls-files` 상 추적 파일은 `wrangler.example.jsonc` 하나뿐
- **마이그레이션 drift 검사가 4방언 전부 커버** — `db:generate:all` 의 출력 경로가 `./drizzle`(d1) / `./drizzle/pg` / `./drizzle/mysql` / `./drizzle/sqlite` 로 모두 `drizzle/` 하위라, `git diff --exit-code -- drizzle` 한 줄로 전부 잡힌다 ([drizzle.config.ts:14,26,38,58](/Users/henry/github/henryj-dev/keystone/drizzle.config.ts:14), [ci.yml:85-91](/Users/henry/github/henryj-dev/keystone/.github/workflows/ci.yml:85))
- **배포의 시크릿 주입 방식이 안전** — `WRANGLER_JSONC` 를 `run:` 안에 직접 보간하지 않고 `env:` 로 넘긴 뒤 `printf '%s' "$WRANGLER_JSONC"` 로 기록한다 ([deploy.yml:68-71](/Users/henry/github/henryj-dev/keystone/.github/workflows/deploy.yml:68)). 셸 인젝션·로그 노출 경로가 없다
- **`bun audit --audit-level=high` 가 CI 에 포함** ([ci.yml:67-68](/Users/henry/github/henryj-dev/keystone/.github/workflows/ci.yml:67)), `package.json` `overrides` 로 취약 전이 의존성 7종 상향 고정
- **CSP 가 `unsafe-inline` 없이 hash 모드** ([svelte.config.js:43-62](/Users/henry/github/henryj-dev/keystone/svelte.config.js:43)). `form-action` 에 `https:` 를 넣은 사유도 주석에 근거와 함께 기록돼 있다

## 참고 — 무해하지만 죽어 있는 설정

- `.npmrc` 의 `engine-strict=true` 는 `package.json` 에 `engines` 필드가 없어 아무 효과가 없다. 게다가 이 프로젝트는 bun 을 쓴다
- `@types/node: ^26.1.1` 과 CI 런타임 `node-version: 22` 가 불일치한다. Node 26 에만 있는 API 가 타입상 통과할 수 있다

## 권장 수정 순서

즉시 악용/장애 가능성 × 수정 비용 기준이다.

1. **C-01** — 시크릿 1개 등록. 지금도 매 배포마다 발생 중
2. **C-03** — 필수 체크에 `Gitleaks` 추가. 클릭 한 번
3. **C-02** — `ci.yml` 조건 한 줄. 게이트 무결성
4. **C-05** — `--frozen-lockfile` 두 곳
5. **C-07** — `permissions` 두 곳
6. **C-11** — 미사용 PAT 정리
7. **C-04** — SHA 핀 고정
8. **C-06** — CI 에 postgres 빌드 잡 추가
9. **C-08** — `scripts/` 타입체크·CodeQL 편입
10. **C-09 / C-10 / C-12** — 일관성·정책 정리

---

_감사일: 2026-08-25 · 대상 커밋: `83a2480` (main) · 후속 조치는 별도 PR 로 분리한다._
