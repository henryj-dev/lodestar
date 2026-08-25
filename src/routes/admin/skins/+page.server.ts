import { fail } from "@sveltejs/kit";
import { desc, eq, and } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireAdminContext } from "$lib/server/auth/guards";
import { adminError } from "$lib/server/admin/errors";
import { clientSkins, oidcClients, samlSps } from "$lib/server/db/schema";
import { invalidateSkinCache } from "$lib/server/skin/resolver";
import { isLinkLocalHost, isLoopbackHost } from "$lib/server/validation";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";

const MAX_SKIN_CACHE_TTL_SECONDS = 86400; // 1일

function validateSkinFetchUrl(raw: string): { ok: true; url: URL } | { ok: false; reason: string } {
    let url: URL;
    try {
        url = new URL(raw);
    } catch {
        return { ok: false, reason: "invalid_url" };
    }
    if (url.protocol !== "https:") {
        return { ok: false, reason: "https_only" };
    }
    const host = url.hostname.toLowerCase();
    if (isLoopbackHost(host)) {
        return { ok: false, reason: "loopback_forbidden" };
    }
    if (/^127\./.test(host) || isLinkLocalHost(host)) {
        return { ok: false, reason: "internal_addr_forbidden" };
    }
    return { ok: true, url };
}

export const load: PageServerLoad = async ({ locals }) => {
    const { db, tenant } = requireAdminContext(locals);

    const [skins, oidcList, samlList] = await Promise.all([
        db.select().from(clientSkins).where(eq(clientSkins.tenantId, tenant.id)).orderBy(desc(clientSkins.createdAt)),
        db.select({ id: oidcClients.id, name: oidcClients.name, clientId: oidcClients.clientId }).from(oidcClients).where(eq(oidcClients.tenantId, tenant.id)),
        db.select({ id: samlSps.id, name: samlSps.name, entityId: samlSps.entityId }).from(samlSps).where(eq(samlSps.tenantId, tenant.id)),
    ]);

    return { skins, oidcList, samlList };
};

export const actions: Actions = {
    create: async ({ request, locals }) => {
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await request.formData();

        const clientType = fd.get("clientType") as "oidc" | "saml";
        const clientRefId = String(fd.get("clientRefId") ?? "").trim();
        const skinType = (fd.get("skinType") ?? "login") as "login" | "signup" | "find_id" | "find_password" | "mfa" | "reset_password";
        const fetchUrl = String(fd.get("fetchUrl") ?? "").trim();
        const fetchSecret = String(fd.get("fetchSecret") ?? "").trim() || null;
        const cacheTtlSeconds = Number(fd.get("cacheTtlSeconds") ?? 3600);

        if (!clientType || !clientRefId || !fetchUrl) {
            return fail(400, { create: true, error: adminError(locale, "required_fields") });
        }
        if (clientType !== "oidc" && clientType !== "saml") {
            return fail(400, { create: true, error: adminError(locale, "invalid_client_type") });
        }

        const v = validateSkinFetchUrl(fetchUrl);
        if (!v.ok) return fail(400, { create: true, error: adminError(locale, v.reason) });

        const ttl = isNaN(cacheTtlSeconds) ? 3600 : cacheTtlSeconds;
        if (ttl < 0) return fail(400, { create: true, error: adminError(locale, "cache_ttl_negative") });
        if (ttl > MAX_SKIN_CACHE_TTL_SECONDS) {
            return fail(400, { create: true, error: adminError(locale, "cache_ttl_max", { max: MAX_SKIN_CACHE_TTL_SECONDS }) });
        }

        try {
            await db.insert(clientSkins).values({
                tenantId: tenant.id,
                clientType,
                clientRefId,
                skinType,
                fetchUrl,
                fetchSecret: fetchSecret && fetchSecret.length > 0 ? fetchSecret : null,
                cacheTtlSeconds: ttl,
                enabled: true,
            });
        } catch {
            return fail(409, { create: true, error: adminError(locale, "skin_config_exists") });
        }

        return { created: true };
    },

    delete: async ({ request, locals, platform }) => {
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await request.formData();
        const id = String(fd.get("id") ?? "");

        const [skin] = await db
            .select()
            .from(clientSkins)
            .where(and(eq(clientSkins.id, id), eq(clientSkins.tenantId, tenant.id)))
            .limit(1);

        if (!skin) return fail(404, { error: adminError(locale, "skin_not_found") });

        await invalidateSkinCache(platform, tenant.id, skin.clientType, skin.clientRefId, skin.skinType);
        await db.delete(clientSkins).where(eq(clientSkins.id, id));

        return { deleted: true };
    },

    toggleEnabled: async ({ request, locals }) => {
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await request.formData();
        const id = String(fd.get("id") ?? "");

        const [skin] = await db
            .select()
            .from(clientSkins)
            .where(and(eq(clientSkins.id, id), eq(clientSkins.tenantId, tenant.id)))
            .limit(1);

        if (!skin) return fail(404, { error: adminError(locale, "skin_not_found") });

        await db.update(clientSkins).set({ enabled: !skin.enabled }).where(eq(clientSkins.id, id));

        return { toggled: true };
    },

    invalidateCache: async ({ request, locals, platform }) => {
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await request.formData();
        const id = String(fd.get("id") ?? "");

        const [skin] = await db
            .select()
            .from(clientSkins)
            .where(and(eq(clientSkins.id, id), eq(clientSkins.tenantId, tenant.id)))
            .limit(1);

        if (!skin) return fail(404, { error: adminError(locale, "skin_not_found") });

        await invalidateSkinCache(platform, tenant.id, skin.clientType, skin.clientRefId, skin.skinType);

        return { invalidated: true };
    },

    update: async (event) => {
        const { request, locals, platform } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;
        const fd = await request.formData();
        const id = String(fd.get("id") ?? "").trim();
        const fetchUrl = String(fd.get("fetchUrl") ?? "").trim();
        const fetchSecret = String(fd.get("fetchSecret") ?? "").trim() || null;
        const cacheTtlSeconds = Number(fd.get("cacheTtlSeconds") ?? 3600);

        if (!fetchUrl) return fail(400, { update: true, updateId: id, error: adminError(locale, "url_required") });

        const v = validateSkinFetchUrl(fetchUrl);
        if (!v.ok) return fail(400, { update: true, updateId: id, error: adminError(locale, v.reason) });

        const ttl = isNaN(cacheTtlSeconds) ? 3600 : cacheTtlSeconds;
        if (ttl < 0) return fail(400, { update: true, updateId: id, error: adminError(locale, "cache_ttl_negative") });
        if (ttl > MAX_SKIN_CACHE_TTL_SECONDS) {
            return fail(400, { update: true, updateId: id, error: adminError(locale, "cache_ttl_max", { max: MAX_SKIN_CACHE_TTL_SECONDS }) });
        }

        const [skin] = await db
            .select()
            .from(clientSkins)
            .where(and(eq(clientSkins.id, id), eq(clientSkins.tenantId, tenant.id)))
            .limit(1);

        if (!skin) return fail(404, { update: true, updateId: id, error: adminError(locale, "skin_not_found") });

        await db
            .update(clientSkins)
            .set({ fetchUrl, fetchSecret: fetchSecret && fetchSecret.length > 0 ? fetchSecret : null, cacheTtlSeconds: ttl })
            .where(eq(clientSkins.id, id));

        await invalidateSkinCache(platform, tenant.id, skin.clientType, skin.clientRefId, skin.skinType);

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            kind: "client_skin_updated",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { id, fetchUrlChanged: skin.fetchUrl !== fetchUrl, secretRotated: Boolean(fetchSecret), cacheTtlChanged: skin.cacheTtlSeconds !== ttl },
        });

        return { updated: true };
    },
};
