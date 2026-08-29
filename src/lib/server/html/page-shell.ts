/**
 * SvelteKit 라우트가 아닌 엔드포인트(`+server.ts`)가 직접 만들어 내보내는 사용자 대면 HTML 의
 * 공통 셸.
 *
 * 이런 응답은 SvelteKit 레이아웃을 거치지 않아 Tailwind 가 주입되지 않는다. 그렇다고 엔드포인트마다
 * 스타일을 따로 하드코딩하면 기본 UI((auth)/account 페이지)와 어긋난 화면이 사용자 흐름 중간에
 * 끼어든다 — 로그인 직후에 오는 로그아웃 확인/진행 화면처럼 바로 눈에 띄는 자리에서 특히 그렇다.
 *
 * 그래서 기본 UI 의 카드 레이아웃을 CSS 로 1:1 옮겨 한 곳에 모아둔다. 클래스와 Tailwind 유틸리티의
 * 대응은 다음과 같고, 값은 이 프로젝트가 쓰는 Tailwind v4 기본 테마 토큰에서 그대로 가져왔다.
 *
 *   body            → `flex min-h-screen items-center justify-center bg-gray-50 p-4`
 *   .card           → `w-full max-w-md rounded-2xl border border-gray-200 bg-white p-8 shadow-sm`
 *   h1              → `text-2xl font-bold text-gray-900`
 *   .sub            → `mt-1 text-sm text-gray-500`
 *   .status         → `mt-6 flex items-center gap-2 text-sm text-gray-600`
 *   .actions        → `mt-6 flex gap-2`
 *   .btn-primary    → `rounded-lg bg-blue-600 py-2.5 text-sm font-medium text-white hover:bg-blue-700`
 *   .btn-secondary  → `rounded-lg border border-gray-300 bg-white text-gray-700 hover:bg-gray-50`
 *
 * Tailwind v4 팔레트는 oklch 라서 hex 를 기준값으로 두고 `@supports` 로 oklch 를 덮어쓴다.
 * oklch 미지원 브라우저에서도 같은 색으로 보이고, 지원 브라우저에서는 Tailwind 와 정확히 일치한다.
 *
 * CSS 는 인라인 `<style>` 로 내보낸다. 이 응답들은 SvelteKit 의 hash 기반 CSP 를 거치지 않으며,
 * 자체 CSP 를 붙이는 프론트채널 로그아웃 페이지는 `style-src 'unsafe-inline'` 을 허용한다.
 */

// Tailwind v4 기본 `--font-sans`.
const FONT_SANS = `-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue','Noto Sans',Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji','Segoe UI Symbol','Noto Color Emoji'`;

const SHELL_CSS =
    `*,::before,::after{box-sizing:border-box}` +
    // hex = 기준값(구형 브라우저), oklch = Tailwind v4 테마 토큰과 동일한 값.
    `:root{color-scheme:light;` +
    `--bg:#f9fafb;--surface:#fff;--border:#e5e7eb;--border-strong:#d1d5db;` +
    `--text:#111827;--text-sub:#6b7280;--text-body:#4b5563;--text-alt:#374151;` +
    `--accent:#2563eb;--accent-hover:#1d4ed8}` +
    `@supports (color:oklch(0% 0 0)){:root{` +
    `--bg:oklch(98.5% 0.002 247.839);--border:oklch(92.8% 0.006 264.531);--border-strong:oklch(87.2% 0.01 258.338);` +
    `--text:oklch(21% 0.034 264.665);--text-sub:oklch(55.1% 0.027 264.364);--text-body:oklch(44.6% 0.03 256.802);` +
    `--text-alt:oklch(37.3% 0.034 259.733);--accent:oklch(54.6% 0.245 262.881);--accent-hover:oklch(48.8% 0.243 264.376)}}` +
    `html{-webkit-text-size-adjust:100%}` +
    `body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem;` +
    `background:var(--bg);color:var(--text);font-family:${FONT_SANS};font-size:1rem;line-height:1.5;` +
    `-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}` +
    `.card{width:100%;max-width:28rem;padding:2rem;background:var(--surface);border:1px solid var(--border);` +
    `border-radius:1rem;box-shadow:0 1px 3px 0 rgba(0,0,0,.1),0 1px 2px -1px rgba(0,0,0,.1)}` +
    `h1{margin:0;font-size:1.5rem;line-height:calc(2/1.5);font-weight:700;color:var(--text)}` +
    `.sub{margin:.25rem 0 0;font-size:.875rem;line-height:calc(1.25/.875);color:var(--text-sub)}` +
    `.rp{font-weight:600;color:var(--text)}` +
    `.status{display:flex;align-items:center;gap:.5rem;margin:1.5rem 0 0;` +
    `font-size:.875rem;line-height:calc(1.25/.875);color:var(--text-body)}` +
    `.spinner{flex:none;width:1rem;height:1rem;border:2px solid currentColor;border-top-color:transparent;` +
    `border-radius:9999px;animation:idp-spin .6s linear infinite}` +
    `@keyframes idp-spin{to{transform:rotate(360deg)}}` +
    `@media (prefers-reduced-motion:reduce){.spinner{animation:none}}` +
    `.actions{display:flex;gap:.5rem;margin-top:1.5rem}` +
    `.btn{flex:1;display:inline-flex;align-items:center;justify-content:center;gap:.5rem;padding:.625rem 1rem;` +
    `font-family:inherit;font-size:.875rem;line-height:calc(1.25/.875);font-weight:500;` +
    `border:1px solid transparent;border-radius:.5rem;cursor:pointer;text-decoration:none}` +
    `.btn-primary{background:var(--accent);color:#fff}` +
    `.btn-primary:hover{background:var(--accent-hover)}` +
    `.btn-secondary{background:var(--surface);border-color:var(--border-strong);color:var(--text-alt)}` +
    `.btn-secondary:hover{background:var(--bg)}` +
    `.btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}`;

export interface PageShellOptions {
    /** `<html lang>` 값. **이미 이스케이프된** 문자열이어야 한다. */
    lang: string;
    /** `<title>` 텍스트. **이미 이스케이프된** 문자열이어야 한다. */
    title: string;
    /** `<body>` 안에 그대로 들어가는 HTML. 사용자 입력에서 온 값은 호출자가 이스케이프한다. */
    body: string;
    /** `</head>` 앞에 덧붙일 태그(예: meta refresh). **이미 이스케이프된** 문자열이어야 한다. */
    head?: string;
    /**
     * `<body>` 에 붙일 속성 문자열(예: SAML auto-submit 의 `onload="…"`). **이미 이스케이프된**
     * 문자열이어야 하며, 사용자 입력에서 온 값을 여기 넣어서는 안 된다.
     */
    bodyAttributes?: string;
}

/** 공통 셸로 감싼 완결 HTML 문서를 만든다. 반환값을 그대로 `new Response(...)` 에 넣으면 된다. */
export function renderPageShell(options: PageShellOptions): string {
    const bodyAttributes = options.bodyAttributes ? ` ${options.bodyAttributes}` : "";
    return (
        `<!DOCTYPE html><html lang="${options.lang}"><head>` +
        `<meta charset="utf-8" />` +
        `<meta name="viewport" content="width=device-width, initial-scale=1" />` +
        `<meta name="robots" content="noindex,nofollow" />` +
        `<title>${options.title}</title>` +
        (options.head ?? "") +
        `<style>${SHELL_CSS}</style>` +
        `</head><body${bodyAttributes}>${options.body}</body></html>`
    );
}

function escapeText(s: string): string {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

export interface MessagePageOptions {
    /** `<html lang>` 값. */
    lang: string;
    /** 카드 제목 겸 `<title>`. */
    title: string;
    /** 제목 아래 안내문. */
    message: string;
    /** 있으면 카드 하단에 보조 버튼으로 링크를 붙인다. */
    link?: { href: string; label: string };
}

/**
 * 제목 + 안내문(+링크)만 있는 단순 안내 페이지. 폼도 스크립트도 필요 없는 거절/안내 응답용이다.
 *
 * `renderPageShell` 과 달리 **인자를 평문으로 받아 내부에서 이스케이프한다** — 호출부가 이스케이프를
 * 잊어서 생기는 사고를 없애기 위한 의도적인 차이다. HTML 조각을 넣어야 하면 `renderPageShell` 을
 * 직접 쓴다.
 */
export function renderMessagePage(options: MessagePageOptions): string {
    const title = escapeText(options.title);
    const link = options.link ? `<div class="actions"><a class="btn btn-secondary" href="${escapeText(options.link.href)}">${escapeText(options.link.label)}</a></div>` : "";
    return renderPageShell({
        lang: escapeText(options.lang),
        title,
        body: `<div class="card"><h1>${title}</h1><p class="sub">${escapeText(options.message)}</p>${link}</div>`,
    });
}
