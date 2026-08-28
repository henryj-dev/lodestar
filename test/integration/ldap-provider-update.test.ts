import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { actions, load } from "../../src/routes/admin/ldap-providers/+page.server";
import { auditEvents, identityProviders } from "../../src/lib/server/db/schema";
import { decryptSecret, encryptSecret } from "../../src/lib/server/crypto/keys";
import { openMemoryDb, makeEvent, seedIdentityProvider, seedTenantAndSigningKey, seedUser, seedMfaSession, TEST_ISSUER_URL, TEST_SIGNING_SECRET, type MemoryDb } from "./harness";
import type { Tenant, User, Session } from "../../src/lib/server/db/schema";

let mem: MemoryDb;
let tenant: Tenant;
let admin: User;
let adminSession: Session;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    admin = await seedUser(mem.db, { tenantId: tenant.id, email: "ldap-admin@test.example", username: "ldapadmin", role: "admin" });
    adminSession = (await seedMfaSession(mem.db, { tenantId: tenant.id, userId: admin.id })).session;
});

afterEach(() => mem.close());

function adminEvent(form: Record<string, string>) {
    return makeEvent({
        method: "POST",
        url: `${TEST_ISSUER_URL}/admin/ldap-providers`,
        form,
        locals: { db: mem.db, tenant, user: admin, session: adminSession, env: mem.env },
    });
}

function updateForm(id: string, bindPassword = "") {
    return {
        id,
        name: "Updated LDAP",
        enabled: "true",
        host: "ldap.example.test",
        port: "389",
        baseDN: "dc=example,dc=test",
        tlsMode: "none",
        bindDN: "cn=reader,dc=example,dc=test",
        bindPassword,
        userSearchFilter: "(uid={username})",
        userDnPattern: "",
        attrEmail: "mail",
        attrDisplayName: "cn",
        attrGivenName: "givenName",
        attrFamilyName: "sn",
    };
}

describe("LDAP provider update", () => {
    it("preserves an encrypted bind password when the form is blank", async () => {
        const encrypted = await encryptSecret("old-password", TEST_SIGNING_SECRET, "idp-ldap-bind-password-v1");
        const provider = await seedIdentityProvider(mem.db, {
            tenantId: tenant.id,
            config: { host: "old.example.test", port: 389, baseDN: "dc=example,dc=test", tlsMode: "none", bindDN: "cn=reader,dc=example,dc=test", bindPasswordEnc: encrypted },
        });

        const result = await actions.update!(adminEvent(updateForm(provider.id)));
        expect(result).toMatchObject({ update: true });
        const [row] = await mem.db.select().from(identityProviders).where(eq(identityProviders.id, provider.id));
        expect(JSON.parse(row.configJson!).bindPasswordEnc).toBe(encrypted);
    });

    it("rotates the password without storing plaintext and records a redacted audit event", async () => {
        const provider = await seedIdentityProvider(mem.db, {
            tenantId: tenant.id,
            config: {
                host: "old.example.test",
                port: 389,
                baseDN: "dc=example,dc=test",
                tlsMode: "none",
                bindDN: "cn=reader,dc=example,dc=test",
                bindPasswordEnc: await encryptSecret("old-password", TEST_SIGNING_SECRET, "idp-ldap-bind-password-v1"),
            },
        });

        await actions.update!(adminEvent(updateForm(provider.id, "new-password")));
        const [row] = await mem.db.select().from(identityProviders).where(eq(identityProviders.id, provider.id));
        const config = JSON.parse(row.configJson!);
        expect(config.bindPassword).toBeUndefined();
        expect(await decryptSecret(config.bindPasswordEnc, TEST_SIGNING_SECRET, "idp-ldap-bind-password-v1")).toBe("new-password");

        const [audit] = await mem.db.select().from(auditEvents).where(eq(auditEvents.kind, "ldap_provider_updated"));
        expect(audit).toBeTruthy();
        expect(audit.detailJson).not.toContain("new-password");
        expect(JSON.parse(audit.detailJson!)).toMatchObject({ bindPasswordChanged: true, enabledBefore: true, enabledAfter: true });
    });

    it("removes a stale bind secret when switching to DN pattern mode", async () => {
        const encrypted = await encryptSecret("old-password", TEST_SIGNING_SECRET, "idp-ldap-bind-password-v1");
        const provider = await seedIdentityProvider(mem.db, {
            tenantId: tenant.id,
            config: { host: "ldap.example.test", port: 389, baseDN: "dc=example", tlsMode: "none", bindDN: "cn=reader", bindPasswordEnc: encrypted },
        });
        const form = updateForm(provider.id);
        form.bindDN = "";
        form.userDnPattern = "uid={username},dc=example";
        await actions.update!(adminEvent(form));
        const [row] = await mem.db.select().from(identityProviders).where(eq(identityProviders.id, provider.id));
        const config = JSON.parse(row.configJson!);
        expect(config.bindPassword).toBeUndefined();
        expect(config.bindPasswordEnc).toBeUndefined();
        expect(config.userDnPattern).toBe("uid={username},dc=example");
    });

    it("does not update a provider from another tenant", async () => {
        const otherTenantId = crypto.randomUUID();
        await mem.db.insert((await import("../../src/lib/server/db/schema")).tenants).values({ id: otherTenantId, slug: "other-ldap", name: "Other" });
        const provider = await seedIdentityProvider(mem.db, {
            tenantId: otherTenantId,
            config: { host: "other.example.test", port: 389, baseDN: "dc=other", tlsMode: "none", userDnPattern: "uid={username},dc=other" },
        });

        const result = await actions.update!(adminEvent(updateForm(provider.id)));
        expect(result).toMatchObject({ status: 404 });
    });

    it("never returns bind secrets in the admin page DTO", async () => {
        const provider = await seedIdentityProvider(mem.db, {
            tenantId: tenant.id,
            config: { host: "ldap.example.test", port: 389, baseDN: "dc=example", tlsMode: "none", bindDN: "cn=reader", bindPassword: "legacy-plaintext" },
        });
        const result = (await load(
            makeEvent({ method: "GET", url: `${TEST_ISSUER_URL}/admin/ldap-providers`, locals: { db: mem.db, tenant, user: admin, session: adminSession, env: mem.env } }) as never,
        )) as {
            providers: Array<{ configJson: string; hasBindPassword: boolean }>;
        };
        const serialized = JSON.stringify(result.providers);
        expect(serialized).not.toContain("legacy-plaintext");
        expect(result.providers.find((item) => item.hasBindPassword)).toBeTruthy();
        const [row] = await mem.db.select().from(identityProviders).where(eq(identityProviders.id, provider.id));
        expect(JSON.parse(row.configJson!).bindPassword).toBeUndefined();
    });
});
