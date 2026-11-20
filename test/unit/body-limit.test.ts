import { describe, it, expect } from "vitest";
import { AUTH_BODY_LIMIT_BYTES, AUTH_BODY_LIMITED_PATHS, exceedsBodyLimit } from "../../src/lib/server/auth/body-limit";

describe("exceedsBodyLimit (64 KiB)", () => {
    it("Content-Length 가 한도 이하면 통과", async () => {
        const req = new Request("https://idp.test/login", { method: "POST", body: "a".repeat(AUTH_BODY_LIMIT_BYTES), headers: { "content-length": String(AUTH_BODY_LIMIT_BYTES) } });
        expect(await exceedsBodyLimit(req)).toBe(false);
    });

    it("Content-Length 가 한도를 넘으면 거부", async () => {
        const req = new Request("https://idp.test/login", { method: "POST", body: "a", headers: { "content-length": String(AUTH_BODY_LIMIT_BYTES + 1) } });
        expect(await exceedsBodyLimit(req)).toBe(true);
    });

    it("Content-Length 가 없으면 본문을 한도까지 읽어 판정하고, 원래 본문은 그대로 남긴다", async () => {
        const big = new ReadableStream({
            start(c) {
                c.enqueue(new TextEncoder().encode("a".repeat(AUTH_BODY_LIMIT_BYTES)));
                c.enqueue(new TextEncoder().encode("b"));
                c.close();
            },
        });
        const req = new Request("https://idp.test/login", { method: "POST", body: big, duplex: "half" } as RequestInit);
        expect(await exceedsBodyLimit(req)).toBe(true);

        const small = new Request("https://idp.test/login", { method: "POST", body: new Blob(["username=a"]).stream(), duplex: "half" } as RequestInit);
        expect(await exceedsBodyLimit(small)).toBe(false);
        expect(await small.text()).toBe("username=a");
    });

    it("비밀번호를 받는 경로만 대상이다", () => {
        for (const p of ["/login", "/signup", "/reset-password", "/accept-invite"]) expect(AUTH_BODY_LIMITED_PATHS.test(p)).toBe(true);
        for (const p of ["/mfa", "/oidc/token", "/api/totp/verify", "/loginx"]) expect(AUTH_BODY_LIMITED_PATHS.test(p)).toBe(false);
    });
});
