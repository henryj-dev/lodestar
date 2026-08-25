import { describe, expect, it, vi } from "vitest";
import { RedisRateLimitStore } from "$lib/server/ratelimit/store";

describe("RedisRateLimitStore", () => {
    it("uses an atomic EVAL increment and reads the previous bucket", async () => {
        const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
            const command = JSON.parse(String(init?.body)) as unknown[];
            if (command[0] === "EVAL") return new Response(JSON.stringify({ result: [3, 2] }), { status: 200 });
            return new Response(JSON.stringify({ result: null }), { status: 200 });
        });
        const store = new RedisRateLimitStore("https://redis.example.test", "secret", fetchMock);

        await expect(store.increment("login:ip", 60_000, 120_000)).resolves.toEqual({ current: 3, prev: 2 });
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))[0]).toBe("EVAL");
    });
});
