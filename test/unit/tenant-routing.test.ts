import { describe, expect, it } from "vitest";
import { resolveTenantSlug } from "$lib/server/auth/bootstrap";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";
import { reroute } from "../../src/hooks";

describe("tenant routing", () => {
    it("resolves an explicit tenant path and strips it for SvelteKit route matching", () => {
        const url = new URL("https://idp.example.test/t/acme/login");
        expect(resolveTenantSlug(url)).toBe("acme");
        expect(reroute({ url })).toBe("/login");
    });

    it("resolves a configured subdomain and rejects path/host mismatches", () => {
        expect(resolveTenantSlug(new URL("https://acme.example.test/login"), { env: { IDP_TENANT_BASE_DOMAIN: "example.test" } } as never)).toBe("acme");
        expect(() => resolveTenantSlug(new URL("https://acme.example.test/t/other/login"), { env: { IDP_TENANT_BASE_DOMAIN: "example.test" } } as never)).toThrow(/일치하지/);
    });

    it("supports tenant-aware host and path issuer strategies", () => {
        const base = { issuerUrl: "https://idp.example.test", tenantBaseDomain: "example.test", tenantIssuerMode: "host" as const };
        expect(resolveIssuerUrl(base as never, "https://idp.example.test", "acme")).toBe("https://acme.example.test");
        expect(resolveIssuerUrl({ ...base, tenantIssuerMode: "path" } as never, "https://idp.example.test", "acme")).toBe("https://idp.example.test/t/acme");
    });
});
