import { describe, it, expect } from "vitest";
import { MemoryRateLimitStore } from "../../src/lib/server/ratelimit";
import { checkThrottle, clearThrottle, recordThrottleFailure, throttleDelayMs, THROTTLE_MAX_DELAY_MS, THROTTLE_RESET_MS } from "../../src/lib/server/auth/login-throttle";

// 계정+IP 지수 지연: 5회 실패까지 지연 없음, 5회째부터 1초·2초·4초…, 상한 15분, 15분 무실패면 초기화.

describe("throttleDelayMs", () => {
    it("5회 미만은 지연이 없다", () => {
        for (let n = 0; n < 5; n++) expect(throttleDelayMs(n)).toBe(0);
    });
    it("5회째부터 1초에서 두 배씩 늘어난다", () => {
        expect(throttleDelayMs(5)).toBe(1000);
        expect(throttleDelayMs(6)).toBe(2000);
        expect(throttleDelayMs(7)).toBe(4000);
        expect(throttleDelayMs(14)).toBe(512_000);
    });
    it("상한은 15분이다", () => {
        expect(throttleDelayMs(15)).toBe(THROTTLE_MAX_DELAY_MS);
        expect(throttleDelayMs(1000)).toBe(THROTTLE_MAX_DELAY_MS);
    });
});

describe("checkThrottle / recordThrottleFailure", () => {
    it("5회 실패 직후에는 1초 동안 막고, 1초 뒤에는 허용한다", async () => {
        const store = new MemoryRateLimitStore();
        const t0 = 1_800_000_000_000;
        for (let i = 0; i < 4; i++) await recordThrottleFailure(store, "k", t0);
        expect((await checkThrottle(store, "k", t0)).allowed).toBe(true);

        await recordThrottleFailure(store, "k", t0);
        const blocked = await checkThrottle(store, "k", t0 + 500);
        expect(blocked.allowed).toBe(false);
        expect(blocked.retryAfterMs).toBe(500);
        expect((await checkThrottle(store, "k", t0 + 1000)).allowed).toBe(true);
    });

    it("마지막 실패 후 15분이 지나면 초기화된다", async () => {
        const store = new MemoryRateLimitStore();
        const t0 = 1_800_000_000_000;
        for (let i = 0; i < 12; i++) await recordThrottleFailure(store, "k", t0);
        expect((await checkThrottle(store, "k", t0 + 1000)).allowed).toBe(false);

        const later = t0 + THROTTLE_RESET_MS + 1;
        expect(await checkThrottle(store, "k", later)).toEqual({ allowed: true, retryAfterMs: 0, failures: 0 });
        expect(await recordThrottleFailure(store, "k", later)).toBe(1);
    });

    it("성공하면 바로 초기화된다", async () => {
        const store = new MemoryRateLimitStore();
        const t0 = Date.now();
        for (let i = 0; i < 6; i++) await recordThrottleFailure(store, "k", t0);
        await clearThrottle(store, "k");
        expect((await checkThrottle(store, "k", t0)).failures).toBe(0);
    });

    it("범위(scope)가 다르면 서로 영향이 없다 — 다른 IP 는 막히지 않는다", async () => {
        const store = new MemoryRateLimitStore();
        const t0 = Date.now();
        for (let i = 0; i < 8; i++) await recordThrottleFailure(store, "login:t:alice:ip-a", t0);
        expect((await checkThrottle(store, "login:t:alice:ip-a", t0)).allowed).toBe(false);
        expect((await checkThrottle(store, "login:t:alice:ip-b", t0)).allowed).toBe(true);
    });
});
