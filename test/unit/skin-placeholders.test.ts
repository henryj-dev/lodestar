import { describe, it, expect } from "vitest";
import { escapeHtml, replacePlaceholders } from "../../src/lib/server/skin/resolver";

// 커스텀 스킨 HTML 에 서버 값을 꽂아 넣는 두 순수 함수.
//
// 스킨은 관리자가 등록한 **외부 호스트**의 HTML 이고, 그 안의 `{{IDP_*}}` 자리에 서버 값이
// 들어간 뒤 `{@html}` 로 렌더된다. 즉 이 두 함수가 스킨 경로의 마지막 문자열 방어선이다.
// HTMLRewriter 를 쓰지 않으므로 node 에서 그대로 검증할 수 있다.

describe("escapeHtml", () => {
    it("HTML 특수문자 다섯 개를 모두 치환한다", () => {
        expect(escapeHtml(`&<>"'`)).toBe("&amp;&lt;&gt;&quot;&#39;");
    });

    it("& 를 먼저 치환해 이중 이스케이프가 깨지지 않는다", () => {
        expect(escapeHtml("<a&b>")).toBe("&lt;a&amp;b&gt;");
    });

    it("평범한 문자열은 그대로 둔다", () => {
        expect(escapeHtml("alice@test.example")).toBe("alice@test.example");
    });
});

describe("replacePlaceholders", () => {
    it("전달된 키를 값으로 치환한다", () => {
        expect(replacePlaceholders(`<input value="{{IDP_SKIN_HINT}}">`, { IDP_SKIN_HINT: "oidc:abc" })).toBe(`<input value="oidc:abc">`);
    });

    it("전달되지 않은 키는 빈 문자열로 지운다 (치환자가 화면에 남지 않게)", () => {
        expect(replacePlaceholders(`a{{IDP_UNKNOWN}}b`, {})).toBe("ab");
    });

    it("대문자·숫자·밑줄 패턴만 치환자로 인식한다", () => {
        // 소문자나 하이픈이 섞인 토큰은 치환 대상이 아니라 그대로 남는다.
        expect(replacePlaceholders(`{{idp_lower}} {{IDP-DASH}}`, { idp_lower: "x" })).toBe("{{idp_lower}} {{IDP-DASH}}");
    });

    it("같은 치환자가 여러 번 나오면 모두 치환한다", () => {
        expect(replacePlaceholders(`{{A}}-{{A}}`, { A: "1" })).toBe("1-1");
    });

    // ctrls H-FRONT-3: 스킨 작성자가 치환자를 href/src/action 같은 URL 컨텍스트에 넣었을 때,
    // escapeHtml 은 `< > " ' &` 만 바꾸므로 scheme 기반 XSS 를 막지 못한다. 그래서 위험한
    // scheme 토큰이 섞인 값은 통째로 비운다.
    describe("위험한 URL scheme 이 섞인 값은 통째로 비운다", () => {
        const blocked = [
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "  javascript:alert(1)",
            "vbscript:msgbox(1)",
            "data:text/html,<script>alert(1)</script>",
            "data : text/html,x",
            "data:application/javascript,alert(1)",
            "\tjavascript:alert(1)",
        ];

        for (const value of blocked) {
            it(`${JSON.stringify(value)} → ""`, () => {
                expect(replacePlaceholders("{{V}}", { V: value })).toBe("");
            });
        }
    });

    describe("정상적인 값은 보존한다", () => {
        const allowed = [
            "https://app.test.example/callback",
            "/login?redirectTo=%2Fapp",
            "#anchor",
            "mailto:alice@test.example",
            "tel:+8210",
            "data:image/png;base64,AAAA",
            "회원가입이 완료되었습니다",
            "oidc:9f2c-4a",
        ];

        for (const value of allowed) {
            it(JSON.stringify(value), () => {
                expect(replacePlaceholders("{{V}}", { V: value })).toBe(value);
            });
        }
    });
});
