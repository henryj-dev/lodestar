import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("node:dns/promises", () => ({
    resolve4: async () => ["140.82.114.4"],
    resolve6: async () => [],
}));

import { postOidcWebhook } from "$lib/server/oidc/webhook-fetch";

afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
});

describe("OIDC webhook fetch", () => {
    it("uses manual redirects and never makes a second request", async () => {
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 307, headers: { location: "https://internal.example.test" } }));

        await expect(postOidcWebhook("https://rp.example.test/logout", "logout_token=secret")).rejects.toThrow(/redirected/);
        expect(fetchSpy).toHaveBeenCalledTimes(1);
        expect(fetchSpy.mock.calls[0][1]).toMatchObject({ redirect: "manual", method: "POST", body: "logout_token=secret" });
    });

    it("aborts a hanging webhook", async () => {
        vi.useFakeTimers();
        let signal: AbortSignal | undefined;
        vi.spyOn(globalThis, "fetch").mockImplementation((_input, init) => {
            signal = init?.signal as AbortSignal;
            return new Promise<Response>((_resolve, reject) => signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError"))));
        });

        const pending = expect(postOidcWebhook("https://rp.example.test/logout", "token=x")).rejects.toThrow(/Aborted/);
        await vi.advanceTimersByTimeAsync(30_000);
        await pending;
        expect(signal?.aborted).toBe(true);
    });

    it("rejects forbidden hosts before fetch and accepts 200", async () => {
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
        await expect(postOidcWebhook("https://127.0.0.1/logout", "token=x")).rejects.toThrow(/SSRF/);
        expect(fetchSpy).not.toHaveBeenCalled();
        await expect(postOidcWebhook("https://rp.example.test/logout", "token=x")).resolves.toMatchObject({ status: 200 });
    });

    it("retries transient 5xx responses and then hands off to the queue", async () => {
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 503 }));
        const send = vi.fn().mockResolvedValue(undefined);

        await expect(postOidcWebhook("https://rp.example.test/logout", "token=x", { queue: { send } })).resolves.toMatchObject({ status: 202, queued: true });
        expect(fetchSpy).toHaveBeenCalledTimes(3);
        expect(send).toHaveBeenCalledWith({ url: "https://rp.example.test/logout", body: "token=x" });
    });
});
