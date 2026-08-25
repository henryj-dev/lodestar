import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("node:dns/promises", () => ({
    resolve4: async () => ["140.82.114.4"],
    resolve6: async () => [],
}));

import { b64uEncode } from "$lib/server/crypto/keys";
import { getJwksCacheSize, invalidateJwksCache, verifyUpstreamIdToken } from "$lib/server/oauth/jwt";

const ISSUER = "https://issuer.example.test";
const AUDIENCE = "client-id";

function jwt(): string {
    const encode = (value: unknown) => b64uEncode(new TextEncoder().encode(JSON.stringify(value)));
    return `${encode({ alg: "RS256", kid: "test-key" })}.${encode({ iss: ISSUER, aud: AUDIENCE, exp: Math.floor(Date.now() / 1000) + 300, iat: Math.floor(Date.now() / 1000) })}.signature`;
}

async function verify(jwksUri: string): Promise<void> {
    await verifyUpstreamIdToken(jwt(), { jwksUri, issuer: ISSUER, audience: AUDIENCE });
}

describe("upstream JWKS fetch hardening", () => {
    beforeEach(() => {
        invalidateJwksCache();
        vi.spyOn(crypto.subtle, "importKey").mockResolvedValue({} as CryptoKey);
        vi.spyOn(crypto.subtle, "verify").mockResolvedValue(true);
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("rejects internal and non-HTTPS JWKS URLs before fetch", async () => {
        const fetchSpy = vi.spyOn(globalThis, "fetch");
        await expect(verifyUpstreamIdToken(jwt(), { jwksUri: "http://169.254.169.254/latest/meta-data", issuer: ISSUER, audience: AUDIENCE })).rejects.toThrow();
        await expect(verifyUpstreamIdToken(jwt(), { jwksUri: "http://jwks.example.test/keys", issuer: ISSUER, audience: AUDIENCE })).rejects.toThrow();
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("rejects redirects and oversized JWKS bodies", async () => {
        const fetchSpy = vi.spyOn(globalThis, "fetch");
        fetchSpy.mockResolvedValueOnce(new Response(null, { status: 302, headers: { location: "https://internal.example.test" } }));
        await expect(verify("https://jwks.example.test/redirect")).rejects.toThrow(/리다이렉트/);

        fetchSpy.mockResolvedValueOnce(new Response("x".repeat(512 * 1024 + 1), { status: 200 }));
        await expect(verify("https://jwks.example.test/large")).rejects.toThrow(/허용 크기/);
    });

    it("caches a URI during TTL and evicts the oldest entry at the bound", async () => {
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify({ keys: [] }), { status: 200 }));

        await verify("https://jwks.example.test/reused").catch(() => undefined);
        await verify("https://jwks.example.test/reused").catch(() => undefined);
        expect(fetchSpy).toHaveBeenCalledTimes(1);

        for (let i = 0; i < 40; i++) await verify(`https://jwks.example.test/${i}`).catch(() => undefined);
        expect(getJwksCacheSize()).toBeLessThanOrEqual(32);
    });
});
