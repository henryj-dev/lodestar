/**
 * 소셜 로그인 프로바이더 관리 (계획서 §2.6).
 *
 * `/admin/ldap-providers` 와 같은 구조를 따른다 — 같은 `identity_providers` 테이블을
 * 쓰되 `kind` 가 `oauth2`/`oidc` 인 행만 다룬다.
 *
 * client secret 은 LDAP bindPassword 와 동일하게 `encryptSecret` 으로 암호화해 저장하고,
 * 화면에는 절대 되돌려 보내지 않는다(설정 여부만 노출).
 */

import { fail } from "@sveltejs/kit";
import { and, desc, eq, inArray, ne } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireAdminContext } from "$lib/server/auth/guards";
import { adminError, requireCsrf, requireFormId } from "$lib/server/admin/errors";
import { ensureCsrfToken } from "$lib/server/auth/csrf";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { getRuntimeConfig } from "$lib/server/auth/runtime";
import { encryptSecret } from "$lib/server/crypto/keys";
import { identityProviders } from "$lib/server/db/schema";
import { validateOAuthUrl } from "$lib/server/validation";
import { getPreset, listPresets } from "$lib/server/oauth/registry";
import { OAUTH_SECRET_CONTEXT } from "$lib/server/oauth/provider-store";
import type { OAuthProviderConfig, ProvisioningMode } from "$lib/server/oauth/types";
import type { Locale } from "$lib/i18n/core";

const SOCIAL_KINDS = ["oauth2", "oidc"] as const;

/** 콜백 URL 에 그대로 들어가므로 URL 안전 문자만 허용한다. */
const SLUG_REGEX = /^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/;

const PROVISIONING_MODES: ProvisioningMode[] = ["signup_form", "jit", "deny"];

function parseScopes(raw: string): string[] {
    return raw
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
}

/** 폼에서 OAuthProviderConfig 를 조립한다. 시크릿은 여기서 다루지 않는다. */
function buildConfig(fd: FormData, providerType: string): OAuthProviderConfig {
    const mode = String(fd.get("provisioningMode") ?? "signup_form") as ProvisioningMode;
    const scopes = parseScopes(String(fd.get("scopes") ?? ""));

    const config: OAuthProviderConfig = {
        providerType,
        provisioningMode: PROVISIONING_MODES.includes(mode) ? mode : "signup_form",
        autoLinkVerifiedEmail: fd.get("autoLinkVerifiedEmail") === "true",
    };

    if (scopes.length > 0) config.scopes = scopes;

    const buttonLabel = String(fd.get("buttonLabel") ?? "").trim();
    if (buttonLabel) config.buttonLabel = buttonLabel;

    const discoveryUrl = String(fd.get("discoveryUrl") ?? "").trim();
    if (discoveryUrl) config.discoveryUrl = discoveryUrl;

    const issuer = String(fd.get("issuer") ?? "").trim();
    if (issuer) config.issuer = issuer;

    const directoryTenant = String(fd.get("directoryTenant") ?? "").trim();
    if (directoryTenant) config.directoryTenant = directoryTenant;

    return config;
}

/** 저장 전 공통 검증. 통과하면 null, 실패하면 사용자에게 보여줄 메시지. */
function validateInput(fd: FormData, locale: Locale): string | null {
    const name = String(fd.get("name") ?? "").trim();
    if (!name) return adminError(locale, "name_required");

    const slug = String(fd.get("slug") ?? "")
        .trim()
        .toLowerCase();
    if (!SLUG_REGEX.test(slug)) return adminError(locale, "social_slug_invalid");

    const providerType = String(fd.get("providerType") ?? "").trim();
    if (!getPreset(providerType)) return adminError(locale, "social_provider_type_invalid");

    if (!String(fd.get("clientId") ?? "").trim()) return adminError(locale, "social_client_id_required");

    // admin 이 입력한 URL 은 서버가 fetch 하므로 SSRF 게이트를 통과해야 한다.
    for (const field of ["discoveryUrl", "issuer"] as const) {
        const value = String(fd.get(field) ?? "").trim();
        if (!value) continue;
        const result = validateOAuthUrl(value, field);
        if (!result.ok) return adminError(locale, result.reason.key, result.reason.params);
    }

    return null;
}

export const load: PageServerLoad = async ({ locals, cookies, url, platform }) => {
    const { db, tenant } = requireAdminContext(locals);

    const rows = await db
        .select({
            id: identityProviders.id,
            kind: identityProviders.kind,
            name: identityProviders.name,
            slug: identityProviders.slug,
            clientId: identityProviders.clientId,
            clientSecretEnc: identityProviders.clientSecretEnc,
            configJson: identityProviders.configJson,
            enabled: identityProviders.enabled,
            createdAt: identityProviders.createdAt,
        })
        .from(identityProviders)
        .where(and(eq(identityProviders.tenantId, tenant.id), inArray(identityProviders.kind, [...SOCIAL_KINDS])))
        .orderBy(desc(identityProviders.createdAt));

    const providers = rows.map((row) => {
        // 손상된 config_json 이 관리 화면 전체를 죽이지 않게 한다 — 해당 행만 빈 설정으로 보인다.
        let config: OAuthProviderConfig | null;
        try {
            config = row.configJson ? (JSON.parse(row.configJson) as OAuthProviderConfig) : null;
        } catch {
            config = null;
        }
        return {
            id: row.id,
            kind: row.kind,
            name: row.name,
            slug: row.slug,
            clientId: row.clientId,
            // 암호문 자체는 절대 내려보내지 않는다 — 설정 여부만 알린다.
            hasClientSecret: Boolean(row.clientSecretEnc),
            enabled: row.enabled,
            providerType: config?.providerType ?? "",
            provisioningMode: config?.provisioningMode ?? "signup_form",
            autoLinkVerifiedEmail: config?.autoLinkVerifiedEmail ?? false,
            scopes: config?.scopes?.join(" ") ?? "",
            buttonLabel: config?.buttonLabel ?? "",
            discoveryUrl: config?.discoveryUrl ?? "",
            issuer: config?.issuer ?? "",
            directoryTenant: config?.directoryTenant ?? "",
        };
    });

    return {
        providers,
        presets: listPresets(),
        csrf: ensureCsrfToken(cookies, url),
        // 프로바이더 콘솔에 등록할 Redirect URI 를 안내하기 위한 오리진.
        callbackOrigin: url.origin,
        // 시크릿 암호화가 불가능한 환경이면 저장 시 503 이 나므로 화면에서 미리 경고한다.
        signingKeyReady: Boolean(getRuntimeConfig(platform).signingKeySecret),
    };
};

export const actions: Actions = {
    create: async (event) => {
        const { db, tenant } = requireAdminContext(event.locals);
        const locale = event.locals.locale;
        const fd = await event.request.formData();

        const bad = requireCsrf(event, fd);
        if (bad) return bad;

        const invalid = validateInput(fd, locale);
        if (invalid) return fail(400, { create: true, error: invalid });

        const clientSecret = String(fd.get("clientSecret") ?? "").trim();
        if (!clientSecret) return fail(400, { create: true, error: adminError(locale, "social_client_secret_required") });

        const { signingKeySecret } = getRuntimeConfig(event.platform);
        if (!signingKeySecret) {
            // 평문 저장으로 조용히 폴백하지 않는다(LDAP 의 H-ADMIN-4 와 같은 결정).
            return fail(503, { create: true, error: adminError(locale, "social_signing_key_secret_required") });
        }

        const providerType = String(fd.get("providerType") ?? "").trim();
        const preset = getPreset(providerType)!;
        const slug = String(fd.get("slug") ?? "")
            .trim()
            .toLowerCase();

        const [slugTaken] = await db
            .select({ id: identityProviders.id })
            .from(identityProviders)
            .where(and(eq(identityProviders.tenantId, tenant.id), eq(identityProviders.slug, slug)))
            .limit(1);
        if (slugTaken) return fail(409, { create: true, error: adminError(locale, "social_slug_taken") });

        await db.insert(identityProviders).values({
            tenantId: tenant.id,
            kind: preset.kind,
            name: String(fd.get("name") ?? "").trim(),
            slug,
            clientId: String(fd.get("clientId") ?? "").trim(),
            clientSecretEnc: await encryptSecret(clientSecret, signingKeySecret, OAUTH_SECRET_CONTEXT),
            configJson: JSON.stringify(buildConfig(fd, providerType)),
            // 설정을 검토한 뒤 명시적으로 켜도록 기본은 비활성이다.
            enabled: false,
        });

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: event.locals.user!.id,
            kind: "social_provider_created",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { slug, providerType },
        });

        return { create: true };
    },

    update: async (event) => {
        const { db, tenant } = requireAdminContext(event.locals);
        const locale = event.locals.locale;
        const fd = await event.request.formData();

        const bad = requireCsrf(event, fd);
        if (bad) return bad;

        const idr = requireFormId(fd, locale);
        if (!idr.ok) return idr.failure;
        const id = idr.id;

        const invalid = validateInput(fd, locale);
        if (invalid) return fail(400, { error: invalid });

        const slug = String(fd.get("slug") ?? "")
            .trim()
            .toLowerCase();
        const [slugTaken] = await db
            .select({ id: identityProviders.id })
            .from(identityProviders)
            .where(and(eq(identityProviders.tenantId, tenant.id), eq(identityProviders.slug, slug), ne(identityProviders.id, id)))
            .limit(1);
        if (slugTaken) return fail(409, { error: adminError(locale, "social_slug_taken") });

        const providerType = String(fd.get("providerType") ?? "").trim();
        const preset = getPreset(providerType)!;

        const patch: Partial<typeof identityProviders.$inferInsert> = {
            kind: preset.kind,
            name: String(fd.get("name") ?? "").trim(),
            slug,
            clientId: String(fd.get("clientId") ?? "").trim(),
            configJson: JSON.stringify(buildConfig(fd, providerType)),
            enabled: fd.get("enabled") === "true",
            updatedAt: new Date(),
        };

        // 새 시크릿이 입력됐을 때만 교체한다. 빈 칸이면 기존 값을 그대로 둔다.
        const clientSecret = String(fd.get("clientSecret") ?? "").trim();
        if (clientSecret) {
            const { signingKeySecret } = getRuntimeConfig(event.platform);
            if (!signingKeySecret) return fail(503, { error: adminError(locale, "social_signing_key_secret_required") });
            patch.clientSecretEnc = await encryptSecret(clientSecret, signingKeySecret, OAUTH_SECRET_CONTEXT);
        }

        await db
            .update(identityProviders)
            .set(patch)
            .where(and(eq(identityProviders.id, id), eq(identityProviders.tenantId, tenant.id)));

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: event.locals.user!.id,
            kind: "social_provider_updated",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { id, slug, enabled: patch.enabled, secretRotated: Boolean(clientSecret) },
        });

        return { update: true };
    },

    delete: async (event) => {
        const { db, tenant } = requireAdminContext(event.locals);
        const locale = event.locals.locale;
        const fd = await event.request.formData();

        const bad = requireCsrf(event, fd);
        if (bad) return bad;

        const idr = requireFormId(fd, locale);
        if (!idr.ok) return idr.failure;

        await db.delete(identityProviders).where(and(eq(identityProviders.id, idr.id), eq(identityProviders.tenantId, tenant.id), inArray(identityProviders.kind, [...SOCIAL_KINDS])));

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: event.locals.user!.id,
            kind: "social_provider_deleted",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { id: idr.id },
        });

        return { deleted: true };
    },
};
