/**
 * upstream HTTP 래퍼(`oauth/http.ts`)의 fetch 호출 규약 검증.
 *
 * 이 파일이 존재하는 이유: 프로바이더 어댑터 테스트는 `globalThis.fetch` 를 스텁하면서
 * `init` 을 무시했기 때문에, **fetch 에 넘기는 옵션 자체가 틀린 것**을 잡지 못했다.
 * 실제로 `redirect: "error"` 가 그대로 배포됐고 Cloudflare Workers 는 이 값을 거부해
 * 모든 소셜 로그인이 실패했다(Node/undici 는 받아주므로 로컬에서는 재현되지 않는다).
 *
 * 그래서 여기서는 응답 내용이 아니라 **호출 인자와 거부 조건**을 검증한다.
 */

import { describe, it, expect, vi, afterEach } from "vitest";

vi.mock("node:dns/promises", () => ({
    resolve4: async () => ["140.82.114.4"],
    resolve6: async () => [],
}));

import { getJson, postForm } from "$lib/server/oauth/http";

/** fetch 를 스텁하고 전달된 init 을 캡처한다. */
function captureFetch(response: Response) {
    const calls: RequestInit[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (_input, init) => {
        calls.push(init ?? {});
        return response;
    });
    return calls;
}

function json(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => {
    vi.restoreAllMocks();
});

describe("아웃바운드 fetch 옵션", () => {
    it('redirect 는 "manual" 이어야 한다 (Workers 는 "error" 를 거부한다)', async () => {
        const calls = captureFetch(json({ ok: true }));
        await getJson("https://api.github.com/user");

        expect(calls).toHaveLength(1);
        expect(calls[0].redirect).toBe("manual");
        // 회귀 방지: "error" 는 edge 에서 TypeError 를 던진다.
        expect(calls[0].redirect).not.toBe("error");
    });

    it("POST 도 동일한 redirect 정책을 쓴다", async () => {
        const calls = captureFetch(json({ access_token: "t" }));
        await postForm("https://nid.naver.com/oauth2.0/token", { grant_type: "authorization_code" });

        expect(calls[0].redirect).toBe("manual");
    });

    it("User-Agent 를 붙인다 (GitHub 은 없으면 403 을 준다)", async () => {
        const calls = captureFetch(json({ ok: true }));
        await getJson("https://api.github.com/user");

        const headers = calls[0].headers as Record<string, string>;
        expect(headers["user-agent"]).toBeTruthy();
    });

    it("호출부 헤더가 기본 헤더를 덮어쓸 수 있다", async () => {
        const calls = captureFetch(json({ ok: true }));
        await getJson("https://api.github.com/user", { authorization: "Bearer abc" });

        const headers = calls[0].headers as Record<string, string>;
        expect(headers.authorization).toBe("Bearer abc");
    });

    it("타임아웃용 signal 을 넘긴다", async () => {
        const calls = captureFetch(json({ ok: true }));
        await getJson("https://api.github.com/user");

        expect(calls[0].signal).toBeInstanceOf(AbortSignal);
    });
});

describe("리다이렉트 거부", () => {
    it("3xx 응답은 따라가지 않고 예외로 끊는다", async () => {
        captureFetch(new Response(null, { status: 302, headers: { location: "http://169.254.169.254/" } }));

        // 검증을 통과한 호스트가 3xx 로 내부 주소를 가리키는 SSRF 우회를 막는다.
        await expect(getJson("https://api.github.com/user")).rejects.toThrow(/리다이렉트\(302\)/);
    });

    it("POST 의 3xx 도 거부한다 (client_secret 재전송 방지)", async () => {
        captureFetch(new Response(null, { status: 307, headers: { location: "https://evil.example/" } }));

        await expect(postForm("https://nid.naver.com/oauth2.0/token", { code: "c" })).rejects.toThrow(/리다이렉트\(307\)/);
    });
});

describe("스킴·호스트 게이트", () => {
    it("https 가 아닌 원격 호스트는 거부한다", async () => {
        captureFetch(json({ ok: true }));
        await expect(getJson("http://api.github.com/user")).rejects.toThrow(/허용되지 않는 스킴/);
    });

    it("내부 주소는 거부한다", async () => {
        captureFetch(json({ ok: true }));
        await expect(getJson("https://169.254.169.254/latest/meta-data/")).rejects.toThrow(/SSRF blocked/);
    });

    it("잘못된 URL 은 거부한다", async () => {
        captureFetch(json({ ok: true }));
        await expect(getJson("not-a-url")).rejects.toThrow(/잘못된 URL/);
    });
});

describe("에러 응답 처리", () => {
    it("HTTP 200 에 error 필드가 실린 실패를 잡아낸다", async () => {
        // 네이버·카카오·깃허브 모두 200 에 error 를 담아 실패를 알리는 경우가 있다.
        captureFetch(json({ error: "invalid_request", error_description: "잘못된 요청" }));

        await expect(postForm("https://nid.naver.com/oauth2.0/token", { code: "c" })).rejects.toThrow(/invalid_request/);
    });

    it("JSON 이 아닌 응답은 상태코드와 본문 일부를 포함해 던진다", async () => {
        vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response("<html>500</html>", { status: 500 }));

        await expect(getJson("https://api.github.com/user")).rejects.toThrow(/500/);
    });
});
