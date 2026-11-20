import { afterEach, describe, expect, it, vi } from "vitest";

const dnsMock = vi.hoisted(() => ({
    resolve4: vi.fn<(host: string) => Promise<string[]>>(),
    resolve6: vi.fn<(host: string) => Promise<string[]>>(),
}));
vi.mock("node:dns/promises", () => dnsMock);

import { assertResolvedHostAllowed, parseAllowedPrivateHosts } from "$lib/server/validation";

afterEach(() => {
    vi.restoreAllMocks();
});

describe("parseAllowedPrivateHosts", () => {
    it("빈/미설정 값은 빈 Set(= 허용 없음)", () => {
        expect(parseAllowedPrivateHosts(undefined).size).toBe(0);
        expect(parseAllowedPrivateHosts(null).size).toBe(0);
        expect(parseAllowedPrivateHosts("").size).toBe(0);
    });

    it("콤마 구분 + trim + 소문자화", () => {
        const set = parseAllowedPrivateHosts(" Barycenter.Tinyuniver.se , other.example.com ,, ");
        expect(set).toEqual(new Set(["barycenter.tinyuniver.se", "other.example.com"]));
    });
});

describe("assertResolvedHostAllowed", () => {
    it("허용 목록 없음(기존 동작) — 사설 IP 로 풀리면 차단", async () => {
        dnsMock.resolve4.mockResolvedValue(["10.253.65.250"]);
        dnsMock.resolve6.mockResolvedValue([]);
        await expect(assertResolvedHostAllowed("barycenter.tinyuniver.se")).rejects.toThrow(/SSRF blocked/);
    });

    it("허용 목록에 있는 호스트는 사설 IP 로 풀려도 통과", async () => {
        dnsMock.resolve4.mockResolvedValue(["10.253.65.250"]);
        dnsMock.resolve6.mockResolvedValue([]);
        const allowed = new Set(["barycenter.tinyuniver.se"]);
        await expect(assertResolvedHostAllowed("barycenter.tinyuniver.se", allowed)).resolves.toBeUndefined();
    });

    it("허용 목록 밖 호스트는 계속 차단", async () => {
        dnsMock.resolve4.mockResolvedValue(["10.0.0.5"]);
        dnsMock.resolve6.mockResolvedValue([]);
        const allowed = new Set(["barycenter.tinyuniver.se"]);
        await expect(assertResolvedHostAllowed("other.example.com", allowed)).rejects.toThrow(/SSRF blocked/);
    });

    it("허용 목록에 있어도 loopback 으로 풀리면 차단", async () => {
        dnsMock.resolve4.mockResolvedValue(["127.0.0.1"]);
        dnsMock.resolve6.mockResolvedValue([]);
        const allowed = new Set(["barycenter.tinyuniver.se"]);
        await expect(assertResolvedHostAllowed("barycenter.tinyuniver.se", allowed)).rejects.toThrow(/SSRF blocked/);
    });

    it("허용 목록에 있어도 link-local(메타데이터 포함)으로 풀리면 차단", async () => {
        dnsMock.resolve4.mockResolvedValue(["169.254.169.254"]);
        dnsMock.resolve6.mockResolvedValue([]);
        const allowed = new Set(["barycenter.tinyuniver.se"]);
        await expect(assertResolvedHostAllowed("barycenter.tinyuniver.se", allowed)).rejects.toThrow(/SSRF blocked/);
    });
});
