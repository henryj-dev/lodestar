import { afterEach, describe, expect, it, vi } from "vitest";

const dnsMock = vi.hoisted(() => ({
    resolve4: vi.fn<(host: string) => Promise<string[]>>().mockResolvedValue(["140.82.114.4"]),
    resolve6: vi.fn<(host: string) => Promise<string[]>>().mockResolvedValue([]),
}));
vi.mock("node:dns/promises", () => dnsMock);

import { env } from "$env/dynamic/private";
import { postOidcWebhook } from "$lib/server/oidc/webhook-fetch";

// env($env/dynamic/private 스텁)는 선언상 필수 string 속성이라 delete가 막힌다 — optional 뷰로 캐스팅.
const mutEnv = env as Record<string, string | undefined>;

afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    dnsMock.resolve4.mockResolvedValue(["140.82.114.4"]);
    dnsMock.resolve6.mockResolvedValue([]);
    delete mutEnv.OIDC_WEBHOOK_ALLOWED_PRIVATE_HOSTS;
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

    it("OIDC_WEBHOOK_ALLOWED_PRIVATE_HOSTS 미설정 — 사설 IP 로 풀리는 호스트는 차단", async () => {
        dnsMock.resolve4.mockResolvedValue(["10.253.65.250"]);
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
        await expect(postOidcWebhook("https://barycenter.tinyuniver.se/api/v1/oidc/role-change", "token=x")).rejects.toThrow(/SSRF/);
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("OIDC_WEBHOOK_ALLOWED_PRIVATE_HOSTS 에 있는 호스트는 사설 IP 로 풀려도 통과", async () => {
        dnsMock.resolve4.mockResolvedValue(["10.253.65.250"]);
        mutEnv.OIDC_WEBHOOK_ALLOWED_PRIVATE_HOSTS = "barycenter.tinyuniver.se";
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
        await expect(postOidcWebhook("https://barycenter.tinyuniver.se/api/v1/oidc/role-change", "token=x")).resolves.toMatchObject({ status: 200 });
        expect(fetchSpy).toHaveBeenCalledTimes(1);
    });

    it("목록 밖 호스트는 다른 항목이 허용돼 있어도 계속 차단", async () => {
        dnsMock.resolve4.mockResolvedValue(["10.0.0.9"]);
        mutEnv.OIDC_WEBHOOK_ALLOWED_PRIVATE_HOSTS = "barycenter.tinyuniver.se";
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
        await expect(postOidcWebhook("https://other.tinyuniver.se/api/v1/oidc/role-change", "token=x")).rejects.toThrow(/SSRF/);
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("허용 목록에 있어도 loopback 으로 풀리면 계속 차단", async () => {
        dnsMock.resolve4.mockResolvedValue(["127.0.0.1"]);
        mutEnv.OIDC_WEBHOOK_ALLOWED_PRIVATE_HOSTS = "barycenter.tinyuniver.se";
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
        await expect(postOidcWebhook("https://barycenter.tinyuniver.se/api/v1/oidc/role-change", "token=x")).rejects.toThrow(/SSRF/);
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("retries transient 5xx responses and then hands off to the queue", async () => {
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 503 }));
        const send = vi.fn().mockResolvedValue(undefined);

        await expect(postOidcWebhook("https://rp.example.test/logout", "token=x", { queue: { send } })).resolves.toMatchObject({ status: 202, queued: true });
        expect(fetchSpy).toHaveBeenCalledTimes(3);
        expect(send).toHaveBeenCalledWith({ url: "https://rp.example.test/logout", body: "token=x" });
    });
});
