import { redirect } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { and, eq } from "drizzle-orm";
import { oidcClients } from "$lib/server/db/schema";
import { clearSessionCookie, revokeSession } from "$lib/server/auth/session";
import { getActiveSigningKey, verifyIdToken } from "$lib/server/crypto/keys";
import { getOidcBackchannelTargets, getOidcFrontchannelTargets, sendOneBackchannelLogout } from "$lib/server/oidc/logout";
import { matchesRedirectUri } from "$lib/server/oidc/client";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";
import { translate } from "$lib/i18n/server";
import type { Locale } from "$lib/i18n/core";

function htmlEscape(s: string): string {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

// ctrls H-FRONT-1: meta refresh URL 의 scheme 을 사전 화이트리스트로 제한.
// resolvePostLogoutRedirect 가 client 등록된 패턴 매칭은 하지만, admin 이 잘못된
// 패턴 (예: javascript:) 을 등록한 경우 meta refresh 가 그 URI 로 자동 이동하여
// IDP 컨텍스트에서 JS 실행될 수 있다. 런타임에서 한 번 더 검증.
function isSafeRedirectScheme(url: string): boolean {
    try {
        const u = new URL(url, "https://placeholder.invalid");
        return u.protocol === "https:" || u.protocol === "http:";
    } catch {
        return false;
    }
}

function renderFrontchannelLogoutHtml(iframeUris: string[], redirectTo: string, locale: Locale): string {
    // ctrls H-OIDC-6: iframe sandbox 강화.
    // - sandbox="" (모든 권한 제거) → RP iframe 안에서 script/popup/topnav 전부 차단.
    //   기존 allow-scripts 는 RP frontchannel logout 표준 (script 로 RP 측 세션 정리)
    //   상 필요해 보이지만, 본 IDP 는 RP 가 server-side endpoint 만 호출하도록 가정.
    //   만약 클라이언트 JS 가 필요한 RP 가 있다면 별도 플래그로 분리.
    // - referrerpolicy="no-referrer" — RP 가 IDP 측 정보를 referer 로 받지 못함.
    // - loading="eager" — 즉시 로드 (별도 throttle 없음).
    const iframes = iframeUris.map((u) => `<iframe src="${htmlEscape(u)}" style="display:none" sandbox="" referrerpolicy="no-referrer" loading="eager"></iframe>`).join("");
    const safeRedirect = isSafeRedirectScheme(redirectTo) ? redirectTo : "/";
    // CSP 는 hash 모드이므로 inline JS 를 피하고 meta refresh 를 사용한다.
    return (
        `<!DOCTYPE html><html lang="${htmlEscape(locale)}"><head><meta charset="utf-8">` +
        `<title>Logging out...</title>` +
        `<meta http-equiv="refresh" content="3;url=${htmlEscape(safeRedirect)}">` +
        `</head><body>` +
        `<p>${htmlEscape(translate(locale, "oidc.errors.logging_out"))}</p>` +
        iframes +
        `</body></html>`
    );
}

async function resolvePostLogoutRedirect(locals: App.Locals, postLogoutRedirectUri: string | null, clientId: string | null, state: string | null): Promise<string> {
    if (!postLogoutRedirectUri || !clientId || !locals.db || !locals.tenant) return "/";
    const [client] = await locals.db
        .select({ postLogoutRedirectUris: oidcClients.postLogoutRedirectUris, allowWildcardRedirectUri: oidcClients.allowWildcardRedirectUri })
        .from(oidcClients)
        .where(and(eq(oidcClients.tenantId, locals.tenant.id), eq(oidcClients.clientId, clientId), eq(oidcClients.enabled, true)))
        .limit(1);
    if (!client?.postLogoutRedirectUris) return "/";
    let allowed: string[];
    try {
        allowed = JSON.parse(client.postLogoutRedirectUris) as string[];
    } catch {
        allowed = [];
    }
    // ctrls H-OIDC-4: 와일드카드 매칭은 client.allowWildcardRedirectUri 가 true 인 경우만.
    const allowWildcard = Boolean(client.allowWildcardRedirectUri);
    const isAllowed = Array.isArray(allowed) && allowed.some((p) => matchesRedirectUri(p, postLogoutRedirectUri, allowWildcard));
    if (isAllowed) {
        if (state) {
            const u = new URL(postLogoutRedirectUri);
            u.searchParams.set("state", state);
            return u.toString();
        }
        return postLogoutRedirectUri;
    }
    return "/";
}

export const GET: RequestHandler = async (event) => {
    const { locals, url } = event;

    // ctrls LOW: drive-by 로그아웃(CSRF) 완화. RP-Initiated Logout 은 최상위 네비게이션이라
    // Sec-Fetch-Dest=document 다. <img>/<iframe>/fetch 로 임베드된 요청(image/iframe/empty 등)은
    // 유출된 id_token_hint 만으로 강제 로그아웃을 유발할 수 있으므로 거부한다. Sec-Fetch 헤더를
    // 보내지 않는 구형 브라우저는 통과(id_token_hint 소유 증명 + sub 일치가 1차 방어).
    const fetchDest = event.request.headers.get("sec-fetch-dest");
    if (fetchDest && fetchDest !== "document") {
        return new Response(null, { status: 204 });
    }

    const postLogoutRedirectUri = url.searchParams.get("post_logout_redirect_uri");
    const clientId = url.searchParams.get("client_id");
    const idTokenHint = url.searchParams.get("id_token_hint");
    const state = url.searchParams.get("state");

    // ctrls M-10: id_token_hint 가 없으면 거부 (CSRF / drive-by logout 방지)
    if (!idTokenHint) {
        return new Response(JSON.stringify({ error: "invalid_request", error_description: translate(locals.locale, "oidc.errors.id_token_hint_required") }), {
            status: 400,
            headers: { "Content-Type": "application/json" },
        });
    }
    if (!locals.db || !locals.tenant) {
        return new Response(JSON.stringify({ error: "server_error" }), {
            status: 503,
            headers: { "Content-Type": "application/json" },
        });
    }

    // ctrls C-7: 미인증 상태에서는 confirm 페이지 렌더 불요.
    // 정리할 세션이 없는데 페이지를 그려주면 (1) clickjacking 으로 임의 사용자의 logout
    // 강제 트리거 표면이 생기고 (2) 유출된 id_token_hint 만으로 IDP 공식 도메인에서
    // phishing 흐름을 그려낼 수 있어 즉시 거부한다.
    if (!locals.user || !locals.session) {
        return new Response(null, { status: 204 });
    }

    const issuer = resolveIssuerUrl(locals.runtimeConfig, url.origin, locals.tenant?.slug ?? undefined);
    // RP-Initiated Logout: id_token_hint 는 만료돼도 유효한 힌트다(OIDC RP-Initiated Logout §2).
    // 만료 외 검증(서명/issuer/sub/aud)은 유지 — 세션 식별 목적이라 만료만 무시.
    const claims = await verifyIdToken(locals.db, locals.tenant.id, idTokenHint, { expectedIssuer: issuer, ignoreExpiry: true });
    if (!claims) {
        return new Response(JSON.stringify({ error: "invalid_id_token_hint" }), {
            status: 400,
            headers: { "Content-Type": "application/json" },
        });
    }
    // aud 검증: client_id 가 명시됐다면 정확히 일치해야 한다.
    if (clientId) {
        const aud = claims.aud;
        const audMatches = typeof aud === "string" ? aud === clientId : Array.isArray(aud) ? aud.includes(clientId) : false;
        if (!audMatches) {
            return new Response(JSON.stringify({ error: "invalid_id_token_hint", error_description: translate(locals.locale, "oidc.errors.aud_mismatch") }), {
                status: 400,
                headers: { "Content-Type": "application/json" },
            });
        }
    }
    if (claims.sub !== locals.user.id) {
        return new Response(JSON.stringify({ error: "id_token_hint_mismatch" }), {
            status: 400,
            headers: { "Content-Type": "application/json" },
        });
    }

    // client_id 누락 시 id_token_hint 의 aud 클레임에서 자동 추출.
    // 이 시점에 claims 가 이미 verify 통과했으므로 aud 는 신뢰 가능.
    // post_logout_redirect_uri 의 등록 client 매칭에 필요.
    const effectiveClientId = clientId ?? deriveClientIdFromAud(claims.aud);

    // GET 도 valid id_token_hint + 등록된 post_logout_redirect_uri 가 모두 검증된
    // 시점이면 confirmation 페이지 없이 바로 logout 수행 (RP-Initiated Logout).
    //
    // OIDC 명세 5장: confirmation 은 SHOULD (MUST 아님). 검증된 id_token_hint 는
    // 소유 증명이므로 drive-by logout CSRF 표면은 매우 좁다 (단기 TTL 의 id_token
    // 유출 + 동일 브라우저 세션 보유 시에만 가능).
    return executeLogout(event, postLogoutRedirectUri, effectiveClientId, state);
};

function deriveClientIdFromAud(aud: unknown): string | null {
    if (typeof aud === "string") return aud;
    if (Array.isArray(aud) && aud.length > 0 && typeof aud[0] === "string") return aud[0];
    return null;
}

async function executeLogout(event: Parameters<RequestHandler>[0], postLogoutRedirectUri: string | null, clientId: string | null, state: string | null): Promise<Response> {
    const { locals, url, cookies, platform } = event;
    if (!locals.db || !locals.tenant) {
        return new Response(JSON.stringify({ error: "server_error" }), {
            status: 503,
            headers: { "Content-Type": "application/json" },
        });
    }
    if (locals.session && locals.user) {
        const db = locals.db;
        const tenantId = locals.tenant.id;
        const sessionId = locals.session.id;
        const idpSessionId = locals.session.idpSessionId;
        const userId = locals.user.id;

        const issuerUrl = resolveIssuerUrl(locals.runtimeConfig, url.origin, locals.tenant?.slug ?? undefined);
        const signingKeySecrets = locals.runtimeConfig.signingKeySecrets;

        const bcTargets = await getOidcBackchannelTargets(db, tenantId, sessionId);
        const fcTargets = await getOidcFrontchannelTargets(db, tenantId, sessionId, idpSessionId, issuerUrl);

        if (bcTargets.length > 0 && signingKeySecrets.length > 0) {
            const signingKey = await getActiveSigningKey(db, tenantId, signingKeySecrets);
            if (signingKey) {
                const bcPromises = bcTargets.map((t) =>
                    sendOneBackchannelLogout(t, userId, idpSessionId, issuerUrl, signingKey.privateKey, signingKey.kid, platform?.env?.OIDC_WEBHOOK_QUEUE).catch(() => undefined),
                );
                const wait = platform?.ctx?.waitUntil?.bind(platform.ctx);
                if (wait) {
                    wait(Promise.all(bcPromises));
                } else {
                    await Promise.all(bcPromises);
                }
            }
        }

        await revokeSession(db, idpSessionId);
        clearSessionCookie(cookies, url);

        if (fcTargets.length > 0) {
            const redirectTo = await resolvePostLogoutRedirect(locals, postLogoutRedirectUri, clientId, state);
            const html = renderFrontchannelLogoutHtml(
                fcTargets.map((t) => t.uri),
                redirectTo,
                locals.locale,
            );
            return new Response(html, {
                status: 200,
                headers: {
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Security-Policy": "default-src 'none'; frame-src https: http://localhost:*; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                    "Cache-Control": "no-store",
                },
            });
        }
    }
    const redirectTo = await resolvePostLogoutRedirect(locals, postLogoutRedirectUri, clientId, state);
    throw redirect(302, redirectTo);
}

export const POST: RequestHandler = async (event) => {
    const { locals, url, request } = event;

    // CSRF 방어: Origin 또는 Referer 가 동일 origin 이어야 함.
    const origin = request.headers.get("Origin");
    const referer = request.headers.get("Referer");
    const sameOrigin = (val: string | null): boolean => {
        if (!val) return false;
        try {
            return new URL(val).origin === url.origin;
        } catch {
            return false;
        }
    };
    if (!sameOrigin(origin) && !sameOrigin(referer)) {
        return new Response(JSON.stringify({ error: "invalid_request", error_description: translate(locals.locale, "oidc.errors.cross_origin_post_blocked") }), {
            status: 403,
            headers: { "Content-Type": "application/json" },
        });
    }

    const ct = request.headers.get("Content-Type") ?? "";
    const isForm = ct.includes("application/x-www-form-urlencoded") || ct.includes("multipart/form-data");
    const formData = isForm ? await request.formData() : null;
    const readField = (key: string): string | null => (formData ? ((formData.get(key) as string | null) ?? null) : url.searchParams.get(key));

    const postLogoutRedirectUri: string | null = readField("post_logout_redirect_uri");
    const clientId: string | null = readField("client_id");
    const idTokenHint: string | null = readField("id_token_hint");
    const state: string | null = readField("state");

    if (!idTokenHint || !locals.db || !locals.tenant) {
        return new Response(JSON.stringify({ error: "invalid_request" }), {
            status: 400,
            headers: { "Content-Type": "application/json" },
        });
    }

    const issuer = resolveIssuerUrl(locals.runtimeConfig, url.origin, locals.tenant?.slug ?? undefined);
    // RP-Initiated Logout: id_token_hint 는 만료돼도 유효한 힌트다(OIDC RP-Initiated Logout §2).
    // 만료 외 검증(서명/issuer/sub/aud)은 유지 — 세션 식별 목적이라 만료만 무시.
    const claims = await verifyIdToken(locals.db, locals.tenant.id, idTokenHint, { expectedIssuer: issuer, ignoreExpiry: true });
    if (!claims) {
        return new Response(JSON.stringify({ error: "invalid_id_token_hint" }), {
            status: 400,
            headers: { "Content-Type": "application/json" },
        });
    }
    if (clientId) {
        const aud = claims.aud;
        const audMatches = typeof aud === "string" ? aud === clientId : Array.isArray(aud) ? aud.includes(clientId) : false;
        if (!audMatches) {
            return new Response(JSON.stringify({ error: "invalid_id_token_hint", error_description: translate(locals.locale, "oidc.errors.aud_mismatch") }), {
                status: 400,
                headers: { "Content-Type": "application/json" },
            });
        }
    }
    if (locals.user && claims.sub !== locals.user.id) {
        return new Response(JSON.stringify({ error: "id_token_hint_mismatch" }), {
            status: 400,
            headers: { "Content-Type": "application/json" },
        });
    }

    // client_id 누락 시 aud 에서 자동 추출
    const effectiveClientId = clientId ?? deriveClientIdFromAud(claims.aud);
    return executeLogout(event, postLogoutRedirectUri, effectiveClientId, state);
};
