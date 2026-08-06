import { fail } from "@sveltejs/kit";
import { desc, eq, and } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireAdminContext } from "$lib/server/auth/guards";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";
import { oidcClients } from "$lib/server/db/schema";
import { hashClientSecret } from "$lib/server/oidc/client";
import { ensureCsrfToken, isValidCsrf } from "$lib/server/auth/csrf";
import { isLoopbackHost, validateWebhookUrl } from "$lib/server/validation";
import { adminError, requireFormId } from "$lib/server/admin/errors";
import type { Locale } from "$lib/i18n/core";

function generateClientId(): string {
    return crypto.randomUUID().replace(/-/g, "").slice(0, 20);
}

function generateClientSecret(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

const ALLOWED_TOKEN_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"] as const;
type TokenAuthMethod = (typeof ALLOWED_TOKEN_AUTH_METHODS)[number];

// `groups`/`organization` 은 **조직 소속**(부서·팀·파트)을 내보내는 표시용 scope 다.
// 인가에 쓰면 팀 이동·부서 개편이 곧바로 보안 경계를 움직인다. 서비스 권한은 `roles` 클레임을
// 쓴다(`user_service_assignments` 기반 — scope 가 아니라 배정 존재로 발행).
const ALLOWED_OIDC_SCOPES = ["openid", "profile", "email", "address", "phone", "offline_access", "organization", "groups"] as const;

/**
 * 단일 redirect URI / post-logout / channel logout URL 검증.
 * @param value 검증할 URL 문자열
 * @param opts.allowCustomScheme 모바일 등 커스텀 scheme 허용 여부 (redirect_uri 한정)
 */
function validateClientUri(value: string, locale: Locale, opts: { allowCustomScheme?: boolean } = {}): { ok: true } | { ok: false; reason: string } {
    let parsed: URL;
    try {
        parsed = new URL(value);
    } catch {
        return { ok: false, reason: adminError(locale, "url_invalid_format", { value }) };
    }

    // RFC 6749 §3.1.2 — fragment 포함 redirect URI 금지
    if (parsed.hash && parsed.hash.length > 0) {
        return { ok: false, reason: adminError(locale, "url_fragment_forbidden", { value }) };
    }

    const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
    const blocked = ["javascript", "data", "file", "vbscript", "blob"];
    if (blocked.includes(scheme)) {
        return { ok: false, reason: adminError(locale, "scheme_forbidden", { scheme }) };
    }

    if (scheme === "https") return { ok: true };
    if (scheme === "http") {
        if (isLoopbackHost(parsed.hostname)) return { ok: true };
        return { ok: false, reason: adminError(locale, "http_localhost_only", { value }) };
    }
    if (opts.allowCustomScheme) {
        // 커스텀 scheme (모바일 redirect 등): RFC 3986 scheme 형식
        if (/^[a-z][a-z0-9+.-]*$/i.test(scheme)) return { ok: true };
        return { ok: false, reason: adminError(locale, "custom_scheme_invalid", { value }) };
    }
    return { ok: false, reason: adminError(locale, "scheme_not_allowed", { scheme, value }) };
}

function splitUriList(raw: string): string[] {
    return raw
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
}

function validateUriList(raw: string, label: string, locale: Locale, opts: { allowCustomScheme?: boolean } = {}): { ok: true; json: string } | { ok: false; reason: string } {
    const list = splitUriList(raw);
    for (const v of list) {
        const r = validateClientUri(v, locale, opts);
        if (!r.ok) return { ok: false, reason: `${label}: ${r.reason}` };
    }
    return { ok: true, json: JSON.stringify(list) };
}

// frontchannel/backchannel logout·role-change URI 검증. 이 세 URI 는 IdP 가 서버측에서
// 직접 fetch 하는 아웃바운드 웹훅이므로(브라우저 redirect_uri 와 다름) https 강제 +
// SSRF 호스트 차단(loopback/사설망/메타데이터)을 적용한다. ctrls M-1(SSRF).
function validateSingleUri(value: string, label: string, locale: Locale): { ok: true } | { ok: false; reason: string } {
    const r = validateWebhookUrl(value, label);
    if (!r.ok) return { ok: false, reason: adminError(locale, r.reason.key, r.reason.params) };
    return { ok: true };
}

function normalizeScopes(raw: string, locale: Locale): { ok: true; value: string } | { ok: false; reason: string } {
    const tokens = raw
        .split(/\s+/)
        .map((s) => s.trim())
        .filter(Boolean);
    const seen = new Set<string>();
    const out: string[] = [];
    for (const t of tokens) {
        if (!(ALLOWED_OIDC_SCOPES as readonly string[]).includes(t)) {
            return { ok: false, reason: adminError(locale, "scope_not_allowed", { scope: t }) };
        }
        if (!seen.has(t)) {
            seen.add(t);
            out.push(t);
        }
    }
    if (!seen.has("openid")) {
        return { ok: false, reason: adminError(locale, "scope_openid_required") };
    }
    return { ok: true, value: out.join(" ") };
}

export const load: PageServerLoad = async ({ locals, cookies, url }) => {
    const { db, tenant } = requireAdminContext(locals);
    const csrfToken = ensureCsrfToken(cookies, url);
    const rows = await db
        .select({
            id: oidcClients.id,
            clientId: oidcClients.clientId,
            name: oidcClients.name,
            redirectUris: oidcClients.redirectUris,
            postLogoutRedirectUris: oidcClients.postLogoutRedirectUris,
            frontchannelLogoutUri: oidcClients.frontchannelLogoutUri,
            frontchannelLogoutSessionRequired: oidcClients.frontchannelLogoutSessionRequired,
            backchannelLogoutUri: oidcClients.backchannelLogoutUri,
            backchannelLogoutSessionRequired: oidcClients.backchannelLogoutSessionRequired,
            roleChangeUri: oidcClients.roleChangeUri,
            scopes: oidcClients.scopes,
            tokenEndpointAuthMethod: oidcClients.tokenEndpointAuthMethod,
            requirePkce: oidcClients.requirePkce,
            allowWildcardRedirectUri: oidcClients.allowWildcardRedirectUri,
            requireVerifiedEmail: oidcClients.requireVerifiedEmail,
            allowAllUsers: oidcClients.allowAllUsers,
            enabled: oidcClients.enabled,
            createdAt: oidcClients.createdAt,
        })
        .from(oidcClients)
        .where(eq(oidcClients.tenantId, tenant.id))
        .orderBy(desc(oidcClients.createdAt));

    return { clients: rows, csrfToken };
};

export const actions: Actions = {
    // ── 클라이언트 생성 ────────────────────────────────────────────────────────
    create: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        if (!isValidCsrf(event.cookies, fd)) return fail(403, { create: true, error: adminError(locale, "csrf_failed") });
        const name = String(fd.get("name") ?? "").trim();
        const redirectUrisRaw = String(fd.get("redirectUris") ?? "").trim();
        const postLogoutUrisRaw = String(fd.get("postLogoutRedirectUris") ?? "").trim();
        const frontchannelLogoutUri = String(fd.get("frontchannelLogoutUri") ?? "").trim();
        const backchannelLogoutUri = String(fd.get("backchannelLogoutUri") ?? "").trim();
        const roleChangeUri = String(fd.get("roleChangeUri") ?? "").trim();
        const frontchannelLogoutSessionRequired = fd.get("frontchannelLogoutSessionRequired") === "true";
        const backchannelLogoutSessionRequired = fd.get("backchannelLogoutSessionRequired") === "true";
        const scopesRaw = String(fd.get("scopes") ?? "openid").trim();
        const tokenMethodRaw = String(fd.get("tokenEndpointAuthMethod") ?? "client_secret_basic");
        if (!(ALLOWED_TOKEN_AUTH_METHODS as readonly string[]).includes(tokenMethodRaw)) {
            return fail(400, { create: true, error: adminError(locale, "invalid_token_auth_method") });
        }
        const tokenMethod = tokenMethodRaw as TokenAuthMethod;
        // public client(none)는 PKCE 필수
        const requirePkce = tokenMethod === "none" ? true : fd.get("requirePkce") === "true";
        // ctrls H-OIDC-4: 와일드카드 redirect_uri 매칭은 명시적 opt-in.
        const allowWildcardRedirectUri = fd.get("allowWildcardRedirectUri") === "true";
        // ctrls R6: 이 클라이언트 로그인 시 이메일 인증 요구(opt-in).
        const requireVerifiedEmail = fd.get("requireVerifiedEmail") === "true";
        // 서비스 권한 게이트 우회 opt-in — 사용자별 매핑 없이 전체 허용.
        const allowAllUsers = fd.get("allowAllUsers") === "true";

        if (!name) return fail(400, { create: true, error: adminError(locale, "name_required") });
        if (!redirectUrisRaw) return fail(400, { create: true, error: adminError(locale, "redirect_uri_required") });

        // URL 검증
        const redirectV = validateUriList(redirectUrisRaw, "Redirect URI", locale, { allowCustomScheme: true });
        if (!redirectV.ok) return fail(400, { create: true, error: redirectV.reason });
        const postLogoutV = postLogoutUrisRaw ? validateUriList(postLogoutUrisRaw, "Post-Logout Redirect URI", locale) : null;
        if (postLogoutV && !postLogoutV.ok) return fail(400, { create: true, error: postLogoutV.reason });
        const frontV = validateSingleUri(frontchannelLogoutUri, "Frontchannel Logout URI", locale);
        if (!frontV.ok) return fail(400, { create: true, error: frontV.reason });
        const backV = validateSingleUri(backchannelLogoutUri, "Backchannel Logout URI", locale);
        if (!backV.ok) return fail(400, { create: true, error: backV.reason });
        const roleChangeV = validateSingleUri(roleChangeUri, "Role Change URI", locale);
        if (!roleChangeV.ok) return fail(400, { create: true, error: roleChangeV.reason });

        const scopesV = normalizeScopes(scopesRaw, locale);
        if (!scopesV.ok) return fail(400, { create: true, error: scopesV.reason });

        const clientId = generateClientId();
        const clientSecret = tokenMethod !== "none" ? generateClientSecret() : null;
        const clientSecretHashed = clientSecret ? await hashClientSecret(clientSecret) : null;

        await db.insert(oidcClients).values({
            id: crypto.randomUUID(),
            tenantId: tenant.id,
            clientId,
            clientSecretHash: clientSecretHashed,
            name,
            redirectUris: redirectV.json,
            postLogoutRedirectUris: postLogoutV ? postLogoutV.json : null,
            frontchannelLogoutUri: frontchannelLogoutUri || null,
            frontchannelLogoutSessionRequired,
            backchannelLogoutUri: backchannelLogoutUri || null,
            backchannelLogoutSessionRequired,
            roleChangeUri: roleChangeUri || null,
            scopes: scopesV.value,
            tokenEndpointAuthMethod: tokenMethod,
            requirePkce,
            allowWildcardRedirectUri,
            requireVerifiedEmail,
            allowAllUsers,
            enabled: true,
        });

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            kind: "oidc_client_created",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { clientId, name },
        });

        // 생성 직후 시크릿을 1회 노출
        return { create: true, clientId, clientSecret };
    },

    // ── 클라이언트 수정 ────────────────────────────────────────────────────────
    update: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        if (!isValidCsrf(event.cookies, fd)) return fail(403, { error: adminError(locale, "csrf_failed") });
        const id = String(fd.get("id") ?? "");
        const name = String(fd.get("name") ?? "").trim();
        const redirectUrisRaw = String(fd.get("redirectUris") ?? "").trim();
        const postLogoutUrisRaw = String(fd.get("postLogoutRedirectUris") ?? "").trim();
        const frontchannelLogoutUri = String(fd.get("frontchannelLogoutUri") ?? "").trim();
        const backchannelLogoutUri = String(fd.get("backchannelLogoutUri") ?? "").trim();
        const roleChangeUri = String(fd.get("roleChangeUri") ?? "").trim();
        const frontchannelLogoutSessionRequired = fd.get("frontchannelLogoutSessionRequired") === "true";
        const backchannelLogoutSessionRequired = fd.get("backchannelLogoutSessionRequired") === "true";
        const scopesRaw = String(fd.get("scopes") ?? "openid").trim();
        const enabled = fd.get("enabled") === "true";

        if (!id || !name) return fail(400, { error: adminError(locale, "invalid_request") });
        if (!redirectUrisRaw) return fail(400, { error: adminError(locale, "redirect_uri_required") });

        const redirectV = validateUriList(redirectUrisRaw, "Redirect URI", locale, { allowCustomScheme: true });
        if (!redirectV.ok) return fail(400, { error: redirectV.reason });
        const postLogoutV = postLogoutUrisRaw ? validateUriList(postLogoutUrisRaw, "Post-Logout Redirect URI", locale) : null;
        if (postLogoutV && !postLogoutV.ok) return fail(400, { error: postLogoutV.reason });
        const frontV = validateSingleUri(frontchannelLogoutUri, "Frontchannel Logout URI", locale);
        if (!frontV.ok) return fail(400, { error: frontV.reason });
        const backV = validateSingleUri(backchannelLogoutUri, "Backchannel Logout URI", locale);
        if (!backV.ok) return fail(400, { error: backV.reason });
        const roleChangeV = validateSingleUri(roleChangeUri, "Role Change URI", locale);
        if (!roleChangeV.ok) return fail(400, { error: roleChangeV.reason });
        const scopesV = normalizeScopes(scopesRaw, locale);
        if (!scopesV.ok) return fail(400, { error: scopesV.reason });

        // public client(none)는 PKCE를 수정 시에도 강제 유지
        const [existingClient] = await db
            .select({ tokenEndpointAuthMethod: oidcClients.tokenEndpointAuthMethod })
            .from(oidcClients)
            .where(and(eq(oidcClients.id, id), eq(oidcClients.tenantId, tenant.id)))
            .limit(1);
        const requirePkce = existingClient?.tokenEndpointAuthMethod === "none" ? true : fd.get("requirePkce") === "true";
        // ctrls H-OIDC-4: wildcard redirect_uri opt-in 플래그.
        const allowWildcardRedirectUri = fd.get("allowWildcardRedirectUri") === "true";
        // ctrls R6: 이 클라이언트 로그인 시 이메일 인증 요구(opt-in).
        const requireVerifiedEmail = fd.get("requireVerifiedEmail") === "true";
        // 서비스 권한 게이트 우회 opt-in — 사용자별 매핑 없이 전체 허용.
        const allowAllUsers = fd.get("allowAllUsers") === "true";

        await db
            .update(oidcClients)
            .set({
                name,
                redirectUris: redirectV.json,
                postLogoutRedirectUris: postLogoutV ? postLogoutV.json : null,
                frontchannelLogoutUri: frontchannelLogoutUri || null,
                frontchannelLogoutSessionRequired,
                backchannelLogoutUri: backchannelLogoutUri || null,
                backchannelLogoutSessionRequired,
                roleChangeUri: roleChangeUri || null,
                scopes: scopesV.value,
                requirePkce,
                allowWildcardRedirectUri,
                requireVerifiedEmail,
                allowAllUsers,
                enabled,
                updatedAt: new Date(),
            })
            .where(and(eq(oidcClients.id, id), eq(oidcClients.tenantId, tenant.id)));

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            kind: "oidc_client_updated",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { clientDbId: id, name, enabled, allowAllUsers },
        });

        return { update: true };
    },

    // ── 시크릿 재생성 ─────────────────────────────────────────────────────────
    regenerateSecret: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        if (!isValidCsrf(event.cookies, fd)) return fail(403, { error: adminError(locale, "csrf_failed") });
        const idr = requireFormId(fd, locale);
        if (!idr.ok) return idr.failure;
        const id = idr.id;

        const newSecret = generateClientSecret();
        const newSecretHashed = await hashClientSecret(newSecret);
        await db
            .update(oidcClients)
            .set({ clientSecretHash: newSecretHashed, updatedAt: new Date() })
            .where(and(eq(oidcClients.id, id), eq(oidcClients.tenantId, tenant.id)));

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            kind: "oidc_client_secret_regenerated",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { clientDbId: id },
        });

        return { regenerateSecret: true, clientSecret: newSecret };
    },

    // ── 삭제 ─────────────────────────────────────────────────────────────────
    delete: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        if (!isValidCsrf(event.cookies, fd)) return fail(403, { error: adminError(locale, "csrf_failed") });
        const idr = requireFormId(fd, locale);
        if (!idr.ok) return idr.failure;
        const id = idr.id;

        await db.delete(oidcClients).where(and(eq(oidcClients.id, id), eq(oidcClients.tenantId, tenant.id)));

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            kind: "oidc_client_deleted",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { clientDbId: id },
        });

        return { deleted: true };
    },
};
