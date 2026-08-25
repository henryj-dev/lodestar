import { fail } from "@sveltejs/kit";
import { and, desc, eq } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireAdminContext } from "$lib/server/auth/guards";
import { adminError, requireFormId } from "$lib/server/admin/errors";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { getRuntimeConfig } from "$lib/server/auth/runtime";
import { encryptSecret } from "$lib/server/crypto/keys";
import { identityProviders } from "$lib/server/db/schema";
import type { LdapProviderConfig } from "$lib/server/ldap/types";
import { validateLdapHost, validateLdapPort } from "$lib/server/validation";
import type { Locale } from "$lib/i18n/core";

function buildConfig(fd: FormData): LdapProviderConfig {
    const port = parseInt(String(fd.get("port") ?? "389"), 10);
    const tlsMode = String(fd.get("tlsMode") ?? "none") as "none" | "tls" | "starttls";

    const bindDN = String(fd.get("bindDN") ?? "").trim();
    const bindPassword = String(fd.get("bindPassword") ?? "").trim();
    const userDnPattern = String(fd.get("userDnPattern") ?? "").trim();
    const userSearchFilter = String(fd.get("userSearchFilter") ?? "").trim();

    const config: LdapProviderConfig = {
        host: String(fd.get("host") ?? "").trim(),
        port: isNaN(port) ? 389 : port,
        baseDN: String(fd.get("baseDN") ?? "").trim(),
        tlsMode,
    };

    if (bindDN) {
        config.bindDN = bindDN;
        if (bindPassword) config.bindPassword = bindPassword;
        if (userSearchFilter) config.userSearchFilter = userSearchFilter;
    } else if (userDnPattern) {
        config.userDnPattern = userDnPattern;
    }

    // 속성 매핑 — 기본값과 다를 때만 포함
    const email = String(fd.get("attrEmail") ?? "").trim();
    const displayName = String(fd.get("attrDisplayName") ?? "").trim();
    const givenName = String(fd.get("attrGivenName") ?? "").trim();
    const familyName = String(fd.get("attrFamilyName") ?? "").trim();

    if (email || displayName || givenName || familyName) {
        config.attributeMap = {};
        if (email) config.attributeMap.email = email;
        if (displayName) config.attributeMap.displayName = displayName;
        if (givenName) config.attributeMap.givenName = givenName;
        if (familyName) config.attributeMap.familyName = familyName;
    }

    return config;
}

// ctrls H-ADMIN-4: signingKeySecret 가 미설정인 상태에서 bindPassword 가 입력되면
// 평문 그대로 저장하던 silent fallback 을 제거. 운영 환경 (signingKeySecret 항상
// 존재) 에서 정상 동작, dev 환경에서 secret 미설정 시 admin 에게 명시적 에러로
// 알려 평문 LDAP 자격증명이 DB 에 박히는 사고 차단.
async function encryptBindPassword(config: LdapProviderConfig, existing: LdapProviderConfig | undefined, signingKeySecret: string | undefined, locale: Locale): Promise<LdapProviderConfig> {
    const stripBindSecrets = (value: LdapProviderConfig): LdapProviderConfig => {
        const safe = { ...value };
        delete safe.bindPassword;
        delete safe.bindPasswordEnc;
        return safe;
    };

    // DN pattern mode does not use an admin bind credential; remove stale secrets
    // when switching away from bind/search mode.
    if (!config.bindDN) {
        return stripBindSecrets(config);
    }

    const plaintext = config.bindPassword ?? existing?.bindPassword;
    const existingEncrypted = existing?.bindPasswordEnc;
    if (!plaintext && existingEncrypted) {
        return { ...stripBindSecrets(config), bindPasswordEnc: existingEncrypted };
    }
    if (!plaintext) {
        throw new Error(adminError(locale, "ldap_bind_password_required"));
    }
    if (!signingKeySecret) {
        throw new Error(adminError(locale, "ldap_signing_key_secret_required"));
    }
    const enc = await encryptSecret(plaintext, signingKeySecret, "idp-ldap-bind-password-v1");
    return { ...stripBindSecrets(config), bindPasswordEnc: enc };
}

export const load: PageServerLoad = async ({ locals, platform }) => {
    const { db, tenant } = requireAdminContext(locals);
    const { signingKeySecret } = getRuntimeConfig(platform);

    const rows = await db
        .select()
        .from(identityProviders)
        .where(and(eq(identityProviders.tenantId, tenant.id), eq(identityProviders.kind, "ldap")))
        .orderBy(desc(identityProviders.createdAt));

    const providers = await Promise.all(
        rows.map(async (row) => {
            let config: LdapProviderConfig = { host: "", port: 389, baseDN: "", tlsMode: "none" };
            try {
                config = JSON.parse(row.configJson ?? "{}") as LdapProviderConfig;
            } catch {
                // Keep the admin page renderable; malformed configuration is still shown as empty.
            }

            if (config.bindPassword && signingKeySecret) {
                const encrypted = await encryptSecret(config.bindPassword, signingKeySecret, "idp-ldap-bind-password-v1");
                const withoutPlaintext = { ...config };
                delete withoutPlaintext.bindPassword;
                config = { ...withoutPlaintext, bindPasswordEnc: encrypted };
                await db
                    .update(identityProviders)
                    .set({ configJson: JSON.stringify(config), updatedAt: new Date() })
                    .where(and(eq(identityProviders.id, row.id), eq(identityProviders.tenantId, tenant.id)));
            }

            const safeConfig = { ...config };
            delete safeConfig.bindPassword;
            delete safeConfig.bindPasswordEnc;
            return {
                ...row,
                configJson: JSON.stringify(safeConfig),
                hasBindPassword: Boolean(config.bindPassword || config.bindPasswordEnc),
            };
        }),
    );

    return { providers };
};

export const actions: Actions = {
    create: async (event) => {
        const { db, tenant } = requireAdminContext(event.locals);
        const locale = event.locals.locale;
        const fd = await event.request.formData();

        const name = String(fd.get("name") ?? "").trim();
        const host = String(fd.get("host") ?? "").trim();
        const hasBind = String(fd.get("bindDN") ?? "").trim();
        const hasPattern = String(fd.get("userDnPattern") ?? "").trim();

        if (!name) return fail(400, { create: true, error: adminError(locale, "name_required") });
        if (!host) return fail(400, { create: true, error: adminError(locale, "ldap_host_required") });
        if (!hasBind && !hasPattern)
            return fail(400, {
                create: true,
                error: adminError(locale, "ldap_bind_or_userdn_required"),
            });

        const hostV = validateLdapHost(host);
        if (!hostV.ok) return fail(400, { create: true, error: adminError(locale, hostV.reason.key, hostV.reason.params) });

        const port = parseInt(String(fd.get("port") ?? "389"), 10);
        const portV = validateLdapPort(isNaN(port) ? 389 : port);
        if (!portV.ok) return fail(400, { create: true, error: adminError(locale, portV.reason.key, portV.reason.params) });

        const { signingKeySecret } = getRuntimeConfig(event.platform);
        let config: LdapProviderConfig;
        try {
            config = await encryptBindPassword(buildConfig(fd), undefined, signingKeySecret, locale);
        } catch (e) {
            return fail(503, { create: true, error: (e as Error).message });
        }

        await db.insert(identityProviders).values({
            tenantId: tenant.id,
            kind: "ldap",
            name,
            configJson: JSON.stringify(config),
            enabled: false,
        });

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: event.locals.user!.id,
            kind: "ldap_provider_created",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { name },
        });

        return { create: true };
    },

    update: async (event) => {
        const { db, tenant } = requireAdminContext(event.locals);
        const locale = event.locals.locale;
        const fd = await event.request.formData();

        const id = String(fd.get("id") ?? "");
        const name = String(fd.get("name") ?? "").trim();
        const enabled = fd.get("enabled") === "true";

        if (!id || !name) return fail(400, { error: adminError(locale, "invalid_request") });

        const [existingRow] = await db
            .select()
            .from(identityProviders)
            .where(and(eq(identityProviders.id, id), eq(identityProviders.tenantId, tenant.id), eq(identityProviders.kind, "ldap")))
            .limit(1);
        if (!existingRow) return fail(404, { error: adminError(locale, "ldap_provider_not_found") });

        let existingConfig: LdapProviderConfig = { host: "", port: 389, baseDN: "", tlsMode: "none" };
        try {
            existingConfig = JSON.parse(existingRow.configJson ?? "{}") as LdapProviderConfig;
        } catch {
            // Treat malformed legacy config as having no reusable secret.
        }

        const host = String(fd.get("host") ?? "").trim();
        if (host) {
            const hostV = validateLdapHost(host);
            if (!hostV.ok) return fail(400, { error: adminError(locale, hostV.reason.key, hostV.reason.params) });
        }
        const port = parseInt(String(fd.get("port") ?? "389"), 10);
        const portV = validateLdapPort(isNaN(port) ? 389 : port);
        if (!portV.ok) return fail(400, { error: adminError(locale, portV.reason.key, portV.reason.params) });

        const { signingKeySecret } = getRuntimeConfig(event.platform);
        let config: LdapProviderConfig;
        try {
            config = await encryptBindPassword(buildConfig(fd), existingConfig, signingKeySecret, locale);
        } catch (e) {
            return fail(503, { error: (e as Error).message });
        }

        await db
            .update(identityProviders)
            .set({ name, configJson: JSON.stringify(config), enabled, updatedAt: new Date() })
            .where(and(eq(identityProviders.id, id), eq(identityProviders.tenantId, tenant.id)));

        const oldKeys = Object.keys(existingConfig).filter((key) => key !== "bindPassword" && key !== "bindPasswordEnc");
        const newKeys = Object.keys(config).filter((key) => key !== "bindPassword" && key !== "bindPasswordEnc");
        const changedFields = Array.from(new Set([...oldKeys, ...newKeys])).filter(
            (key) => JSON.stringify(existingConfig[key as keyof LdapProviderConfig]) !== JSON.stringify(config[key as keyof LdapProviderConfig]),
        );
        if (existingRow.name !== name) changedFields.push("name");
        if (existingRow.enabled !== enabled) changedFields.push("enabled");

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: event.locals.user!.id,
            kind: "ldap_provider_updated",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: {
                id,
                name,
                changedFields: Array.from(new Set(changedFields)),
                bindPasswordChanged: Boolean(buildConfig(fd).bindPassword),
                enabledBefore: existingRow.enabled,
                enabledAfter: enabled,
            },
        });

        return { update: true };
    },

    delete: async (event) => {
        const { db, tenant } = requireAdminContext(event.locals);
        const locale = event.locals.locale;
        const fd = await event.request.formData();

        const idr = requireFormId(fd, locale);
        if (!idr.ok) return idr.failure;
        const id = idr.id;

        await db.delete(identityProviders).where(and(eq(identityProviders.id, id), eq(identityProviders.tenantId, tenant.id)));

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: event.locals.user!.id,
            kind: "ldap_provider_deleted",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { id },
        });

        return { deleted: true };
    },
};
