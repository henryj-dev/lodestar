# 인증 화면 디자인 참조 (mono 테마)

이 디렉터리의 HTML 은 **디자인 참조**입니다. 브라우저로 바로 열어 보는 목적이고, 커스텀 스킨으로
**그대로 등록하면 일부가 동작하지 않습니다.**

스킨으로 가져온 HTML 은 서버에서 정화(sanitize)된 뒤 렌더되기 때문입니다. 이 목업들이 정화에
걸리는 지점은 하나입니다.

| 목업이 쓰는 것 | 스킨으로 등록하면        | 대응                                                           |
| -------------- | ------------------------ | -------------------------------------------------------------- |
| `<script>`     | **제거됨**               | IdP 가 주입하는 공통 스크립트의 훅(선택자)에 맞춰 마크업 구성  |
| `<style>`      | 유지됨(내용은 일부 정화) | 위치·레이어링 속성(`position`/`z-index`/`transform` 등)만 제거 |

즉 시각적 디자인은 대체로 그대로 살지만, 입력 검증·OTP 자동 이동·플래시 자동 숨김 같은 동작은
자체 스크립트로 붙일 수 없습니다. 대신 IdP 가 `/api/skin-scripts` 를 주입하며, 정해진 선택자
(`.auth-shell[data-skin-type]`, `#flash-msg`, `#username`, `#submit` …)를 맞추면 같은 동작이
자동으로 붙습니다.

전체 제약과 치환자·훅 계약은 다음을 보세요.

- 관리 콘솔의 **`/admin/skins/guide`** — 치환자 표, 폼 필드 이름, 스크립트 훅, 정화 규칙, 예제
- [`docs/ADMIN_GUIDE.md` §7](../ADMIN_GUIDE.md) — 등록 필드, 해석 순서, 캐시 동작

## 파일

| 파일                  | 대응 스킨 타입   | 화면              |
| --------------------- | ---------------- | ----------------- |
| `index.html`          | —                | 목업 모아 보기    |
| `login.html`          | `login`          | `/login`          |
| `signup.html`         | `signup`         | `/signup`         |
| `find-id.html`        | `find_id`        | `/find-id`        |
| `find-password.html`  | `find_password`  | `/find-password`  |
| `reset-password.html` | `reset_password` | `/reset-password` |
| `verify.html`         | `verify_email`   | `/verify-email`   |
