import { describe, it, expect } from "vitest";
import { renderTermsBody } from "$lib/server/terms";

// 약관 본문 렌더러. **이스케이프를 먼저 하고 그 위에 서식만 얹는다** — 원본 HTML 이 구조적으로
// 살아남을 수 없다. 의존성을 늘리지 않는 최소 구현이므로 지원 범위와 한계를 여기서 고정한다.

describe("renderTermsBody: 안전성", () => {
    it("HTML 태그를 살려두지 않는다", () => {
        const out = renderTermsBody("<script>alert(1)</script>");
        expect(out).not.toContain("<script>");
        expect(out).toContain("&lt;script&gt;");
    });

    it("이벤트 핸들러가 섞인 태그도 문구로만 남는다", () => {
        const out = renderTermsBody(`<img src=x onerror="steal()">`);
        // `onerror=` 라는 **문자열**은 남는다 — 그게 정상이다. 중요한 건 그것이 살아 있는 속성이
        // 아니라는 것이고, 태그 자체가 이스케이프됐으므로 요소가 만들어지지 않는다.
        expect(out).toContain("&lt;img");
        expect(out).not.toMatch(/<img/);
        expect(out).toContain("&quot;steal()&quot;"); // 값도 문구로만
    });

    it("javascript: 링크는 링크로 만들지 않는다", () => {
        const out = renderTermsBody("[클릭](javascript:alert(1))");
        expect(out).not.toContain("<a ");
        expect(out).toContain("[클릭]");
    });

    it("data: 링크도 링크로 만들지 않는다", () => {
        expect(renderTermsBody("[x](data:text/html,<b>)")).not.toContain("<a ");
    });

    it("따옴표를 이스케이프해 속성을 깨지 않는다", () => {
        const out = renderTermsBody(`he said "hi" and 'bye'`);
        expect(out).toContain("&quot;hi&quot;");
        expect(out).toContain("&#39;bye&#39;");
    });
});

describe("renderTermsBody: 지원 서식", () => {
    it("빈 줄로 단락을 나눈다", () => {
        expect(renderTermsBody("첫 단락\n\n둘째 단락")).toBe("<p>첫 단락</p><p>둘째 단락</p>");
    });

    it("단락 안의 줄바꿈은 <br /> 로 유지한다", () => {
        expect(renderTermsBody("1행\n2행")).toBe("<p>1행<br />2행</p>");
    });

    it("## 제목을 h3 으로 (문서 제목이 h1 을 이미 쓴다)", () => {
        expect(renderTermsBody("## 제1조 목적")).toBe("<h3>제1조 목적</h3>");
    });

    it("# 은 h2, ### 은 h4", () => {
        expect(renderTermsBody("# 큰제목")).toBe("<h2>큰제목</h2>");
        expect(renderTermsBody("### 작은제목")).toBe("<h4>작은제목</h4>");
    });

    it("**굵게** 를 strong 으로", () => {
        expect(renderTermsBody("이것은 **중요** 합니다")).toBe("<p>이것은 <strong>중요</strong> 합니다</p>");
    });

    it("- 목록을 ul/li 로", () => {
        expect(renderTermsBody("- 하나\n- 둘")).toBe("<ul><li>하나</li><li>둘</li></ul>");
    });

    it("* 도 목록으로 인식한다", () => {
        expect(renderTermsBody("* 하나\n* 둘")).toBe("<ul><li>하나</li><li>둘</li></ul>");
    });

    it("https 링크는 새 창 + noopener 로 만든다", () => {
        const out = renderTermsBody("[정책](https://example.test/privacy)");
        expect(out).toContain('<a href="https://example.test/privacy" target="_blank" rel="noopener noreferrer">정책</a>');
    });

    it("목록 안에서도 굵게·링크가 동작한다", () => {
        const out = renderTermsBody("- **필수** 항목\n- [자세히](https://a.test)");
        expect(out).toContain("<strong>필수</strong>");
        expect(out).toContain('<a href="https://a.test"');
    });

    it("현실적인 약관 문서를 처리한다", () => {
        const out = renderTermsBody(`## 제1조 (목적)

본 약관은 서비스 이용 조건을 정합니다.
자세한 내용은 [정책](https://example.test/p) 을 참고하세요.

## 제2조 (수집 항목)

- 이메일 주소
- **전화번호** (선택)`);

        expect(out).toContain("<h3>제1조 (목적)</h3>");
        expect(out).toContain("<h3>제2조 (수집 항목)</h3>");
        expect(out).toContain("<ul><li>이메일 주소</li>");
        expect(out).toContain("<strong>전화번호</strong>");
        expect(out).not.toContain("&lt;p&gt;");
    });
});

describe("renderTermsBody: 경계", () => {
    it("빈 입력은 빈 문자열", () => {
        expect(renderTermsBody("")).toBe("");
        expect(renderTermsBody("\n\n  \n")).toBe("");
    });

    it("닫히지 않은 굵게 표시는 그대로 남는다", () => {
        expect(renderTermsBody("**열림만")).toBe("<p>**열림만</p>");
    });

    it("연속된 빈 줄이 많아도 빈 단락을 만들지 않는다", () => {
        expect(renderTermsBody("A\n\n\n\n\nB")).toBe("<p>A</p><p>B</p>");
    });
});
