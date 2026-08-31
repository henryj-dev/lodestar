import { describe, it, expect } from "vitest";
import { renderMessagePage, renderPageShell } from "../../src/lib/server/html/page-shell";

// SvelteKit 라우트가 아닌 엔드포인트가 직접 내보내는 HTML 의 공통 셸.
// 두 함수의 계약이 다르다는 점이 중요하다:
//   renderPageShell   — 인자를 **이스케이프된 HTML** 로 받는다(폼/iframe 등 조각을 넣어야 하므로).
//   renderMessagePage — 인자를 **평문** 으로 받아 내부에서 이스케이프한다(호출부 실수 방지).

describe("renderPageShell", () => {
    it("완결 문서를 만들고 공통 CSS 를 인라인으로 싣는다", () => {
        const html = renderPageShell({ lang: "ko", title: "제목", body: `<div class="card">본문</div>` });

        expect(html.startsWith("<!DOCTYPE html>")).toBe(true);
        expect(html).toContain('<html lang="ko">');
        expect(html).toContain("<title>제목</title>");
        expect(html).toContain('<meta name="robots" content="noindex,nofollow" />');
        expect(html).toContain('<div class="card">본문</div>');
        expect(html.endsWith("</body></html>")).toBe(true);

        // 기본 UI 카드와 같은 Tailwind 토큰 값이 들어 있어야 한다.
        expect(html).toContain("max-width:28rem");
        expect(html).toContain("border-radius:1rem");
    });

    it("CSS 의 중괄호가 균형을 이룬다", () => {
        const html = renderPageShell({ lang: "ko", title: "t", body: "" });
        const css = html.slice(html.indexOf("<style>") + "<style>".length, html.indexOf("</style>"));

        let depth = 0;
        let lowest = 0;
        for (const ch of css) {
            if (ch === "{") depth++;
            else if (ch === "}") {
                depth--;
                lowest = Math.min(lowest, depth);
            }
        }
        expect(depth).toBe(0);
        expect(lowest).toBe(0); // 닫는 중괄호가 먼저 나오는 구간이 없다
    });

    it("bodyAttributes 를 <body> 에 붙인다 (SAML auto-submit 용)", () => {
        const html = renderPageShell({
            lang: "ko",
            title: "t",
            body: "",
            bodyAttributes: `onload="document.getElementById('samlForm').submit()"`,
        });
        expect(html).toContain(`<body onload="document.getElementById('samlForm').submit()">`);
    });

    it("bodyAttributes 가 없으면 <body> 에 불필요한 공백을 남기지 않는다", () => {
        expect(renderPageShell({ lang: "ko", title: "t", body: "" })).toContain("<body>");
    });

    it("head 옵션은 </head> 앞에 들어간다 (meta refresh 용)", () => {
        const html = renderPageShell({ lang: "ko", title: "t", body: "", head: `<meta http-equiv="refresh" content="3;url=/">` });
        expect(html.indexOf("http-equiv")).toBeLessThan(html.indexOf("</head>"));
    });
});

describe("renderMessagePage", () => {
    it("제목·안내문·링크를 카드로 렌더한다", () => {
        const html = renderMessagePage({
            lang: "ko",
            title: "요청을 처리할 수 없습니다",
            message: "다시 시도해 주세요.",
            link: { href: "/", label: "홈으로" },
        });

        expect(html).toContain('<div class="card">');
        expect(html).toContain("<h1>요청을 처리할 수 없습니다</h1>");
        expect(html).toContain('<p class="sub">다시 시도해 주세요.</p>');
        expect(html).toContain('<a class="btn btn-secondary" href="/">홈으로</a>');
    });

    it("링크가 없으면 버튼 영역을 만들지 않는다", () => {
        const html = renderMessagePage({ lang: "ko", title: "t", message: "m" });
        // `.actions` 규칙은 공통 CSS 에 늘 들어 있으므로 마크업만 본다.
        expect(html).not.toContain('<div class="actions">');
        expect(html).toContain('<div class="card"><h1>t</h1><p class="sub">m</p></div>');
    });

    it("인자를 평문으로 받아 내부에서 이스케이프한다", () => {
        const html = renderMessagePage({
            lang: "ko",
            title: `<img src=x onerror="alert(1)">`,
            message: `a & b <script>alert(2)</script>`,
            link: { href: `/?a=1&b=2`, label: `"'` },
        });

        // 원본 태그가 살아 있으면 안 된다.
        expect(html).not.toContain("<img src=x");
        expect(html).not.toContain("<script>alert(2)");
        expect(html).toContain("&lt;img src=x");
        expect(html).toContain("a &amp; b &lt;script&gt;");
        expect(html).toContain('href="/?a=1&amp;b=2"');
        expect(html).toContain("&quot;&#39;");
    });
});
