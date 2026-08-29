import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { handle } from "../../src/hooks.server";
import { openMemoryDb, makeEvent, TEST_ISSUER_URL, type MemoryDb } from "./harness";

// hooks.server 의 CSRF 게이트는 라우트 핸들러보다 먼저 돌고 SvelteKit 렌더링을 아예 건너뛴다.
// 따라서 여기서 나가는 응답은 +error.svelte 가 아니라 hook 이 직접 만든 HTML 이다.
//
// 검증 대상은 (1) 거부가 그대로 유지되는지 (2) 문서 요청에는 기본 UI 와 같은 카드가, fetch/API
// 요청에는 종전과 같은 짧은 평문이 가는지 (3) 실패 사유가 응답으로 구분되어 새지 않는지.

let mem: MemoryDb;

beforeEach(async () => {
    mem = await openMemoryDb();
});

afterEach(() => mem.close());

/** resolve 가 호출되면 CSRF 게이트를 통과한 것이므로 테스트를 실패시킨다. */
const resolveMustNotRun = () => {
    throw new Error("resolve() 가 호출되었다 — CSRF 게이트가 요청을 통과시켰다");
};

function crossOriginPost(headers: Record<string, string>, path = "/login") {
    return makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}${path}`,
        headers,
        form: { username: "alice", password: "hunter2" },
        locals: { db: mem.db, tenant: null, env: mem.env },
    });
}

async function runHandle(event: ReturnType<typeof makeEvent>): Promise<Response> {
    return (await handle({ event, resolve: resolveMustNotRun } as never)) as Response;
}

describe("hooks CSRF 거부 응답", () => {
    it("문서 요청은 공통 셸 카드로 403 을 돌려준다", async () => {
        const res = await runHandle(crossOriginPost({ Origin: "https://evil.example", Accept: "text/html,application/xhtml+xml,*/*" }));

        expect(res.status).toBe(403);
        expect(res.headers.get("content-type")).toContain("text/html");
        expect(res.headers.get("cache-control")).toContain("no-store");

        const html = await res.text();
        // 기본 UI 카드와 동일한 Tailwind 토큰 값 (max-w-md / rounded-2xl).
        expect(html).toContain('<div class="card">');
        expect(html).toContain("max-width:28rem");
        expect(html).toContain("border-radius:1rem");
        expect(html).toContain("요청을 처리할 수 없습니다");
        expect(html).toContain("홈으로 돌아가기");
    });

    it("Accept-Language 에 따라 로케일이 적용된다", async () => {
        const res = await runHandle(
            crossOriginPost({
                Origin: "https://evil.example",
                Accept: "text/html",
                "Accept-Language": "en-US,en;q=0.9",
            }),
        );

        const html = await res.text();
        expect(html).toContain('<html lang="en">');
        expect(html).toContain("Request could not be processed");
        expect(html).not.toContain("요청을 처리할 수 없습니다");
    });

    it("fetch/API 요청에는 종전처럼 짧은 평문을 준다", async () => {
        const res = await runHandle(crossOriginPost({ Origin: "https://evil.example", Accept: "application/json" }, "/api/webauthn/register/verify"));

        expect(res.status).toBe(403);
        expect(res.headers.get("content-type")).toContain("text/plain");
        expect(await res.text()).toBe("CSRF check failed");
    });

    it("Origin/Referer 가 모두 없어도 사유를 구분해 알려주지 않는다", async () => {
        const noHeaders = await runHandle(crossOriginPost({ Accept: "text/html" }));
        const badOrigin = await runHandle(crossOriginPost({ Origin: "https://evil.example", Accept: "text/html" }));

        expect(noHeaders.status).toBe(badOrigin.status);
        expect(await noHeaders.text()).toBe(await badOrigin.text());
    });

    it("교차 출처 Referer 만 있는 경우도 거부한다", async () => {
        const res = await runHandle(crossOriginPost({ Referer: "https://evil.example/attack", Accept: "text/html" }));
        expect(res.status).toBe(403);
    });

    it("망가진 Origin 헤더도 거부한다 (URL 파싱 실패)", async () => {
        const res = await runHandle(crossOriginPost({ Origin: "not-a-url", Accept: "text/html" }));
        expect(res.status).toBe(403);
    });
});
