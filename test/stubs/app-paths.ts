// vitest 용 $app/paths 스텁.
//
// SvelteKit 의 `resolve()` 는 라우트 ID 를 실제 URL 경로로 바꾸고 `base` 를 붙인다.
// 통합 테스트는 base path 없이 구동하므로 항등 함수로 충분하다 — 라우트 ID 와 경로가
// 같은 형태이고(`/login` → `/login`), 테스트는 리다이렉트 Location 문자열만 검증한다.
export const base = "";
export const assets = "";

export function resolve(id: string): string {
    return id;
}

export function asset(file: string): string {
    return file;
}
