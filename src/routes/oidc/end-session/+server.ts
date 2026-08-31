import { redirect } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { and, eq } from "drizzle-orm";
import { oidcClients } from "$lib/server/db/schema";
import { clearSessionCookie, revokeSession } from "$lib/server/auth/session";
import { ensureCsrfToken, isValidCsrf } from "$lib/server/auth/csrf";
import { getActiveSigningKey, verifyIdToken } from "$lib/server/crypto/keys";
import { getOidcBackchannelTargets, getOidcFrontchannelTargets, sendOneBackchannelLogout } from "$lib/server/oidc/logout";
import { matchesRedirectUri } from "$lib/server/oidc/client";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";
import { renderPageShell } from "$lib/server/html/page-shell";
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
    const t = (key: string) => htmlEscape(translate(locale, key));
    // CSP 는 hash 모드이므로 inline JS 를 피하고 meta refresh 를 사용한다.
    // 화면은 기본 UI 와 같은 카드로 렌더한다(renderPageShell) — 로그인 직후 흐름에서 이 페이지만
    // 브라우저 기본 스타일로 튀어나오지 않도록.
    return renderPageShell({
        lang: htmlEscape(locale),
        title: t("oidc.logout_progress.title"),
        head: `<meta http-equiv="refresh" content="3;url=${htmlEscape(safeRedirect)}">`,
        body:
            `<div class="card">` +
            `<h1>${t("oidc.logout_progress.title")}</h1>` +
            `<p class="status" role="status"><span class="spinner" aria-hidden="true"></span>` +
            `<span>${t("oidc.logout_progress.subtitle")}</span></p>` +
            `</div>` +
            iframes,
    });
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

    // RP 를 식별할 수단이 하나도 없으면 거부한다.
    //
    // OIDC RP-Initiated Logout 1.0 은 `id_token_hint` 를 RECOMMENDED 로 두고, §2 에서
    // `client_id` 를 "post_logout_redirect_uri 는 쓰지만 id_token_hint 는 쓰지 않을 때
    // 클라이언트를 지정하는 것이 가장 흔한 용도"로 규정한다. 그래서 둘 중 **하나**만
    // 있으면 진행하고, 대신 소유 증명이 없는 쪽(client_id 전용)은 아래에서 확인 화면을
    // 거치게 한다(§2: 사용자의 로그아웃 의사를 확인할 수 없으면 물어야 한다 — SHOULD).
    //
    // 예전에는 `id_token_hint` 를 필수로 요구했는데(ctrls M-10), 그것은 규격보다 엄격해서
    // 세션에 ID 토큰을 보관하지 않는 정상적인 RP 의 로그아웃을 400 으로 막았다. drive-by
    // 로그아웃 방어는 확인 화면 + Sec-Fetch-Dest 검사 + POST 의 CSRF 토큰이 담당한다.
    if (!idTokenHint && !clientId) {
        return new Response(JSON.stringify({ error: "invalid_request", error_description: translate(locals.locale, "oidc.errors.hint_or_client_id_required") }), {
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

    // ── id_token_hint 없는 경로 — 확인 화면을 거친다 ────────────────────────────
    // 소유 증명이 없으므로 즉시 로그아웃하지 않는다. RP 식별은 등록 정보로 한다:
    // client_id 가 이 테넌트에 존재하고 활성이어야 하며(§3 의 "OP 가 RP 를 확인할 수
    // 있어야 한다"), post_logout_redirect_uri 의 등록 여부는 실제 리다이렉트 시점에
    // resolvePostLogoutRedirect 가 다시 검증해 미등록이면 `/` 로 떨어뜨린다.
    if (!idTokenHint) {
        const client = await findEndSessionClient(locals, clientId!);
        if (!client) {
            return new Response(JSON.stringify({ error: "invalid_request", error_description: translate(locals.locale, "oidc.errors.unknown_client") }), {
                status: 400,
                headers: { "Content-Type": "application/json" },
            });
        }
        return renderLogoutConfirmPage(event, {
            clientId: clientId!,
            clientName: client.name,
            postLogoutRedirectUri,
            state,
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

/** 이 테넌트의 활성 클라이언트를 client_id 로 찾는다. 확인 화면에 이름을 보여주기 위해 name 도 읽는다. */
async function findEndSessionClient(locals: App.Locals, clientId: string): Promise<{ name: string } | null> {
    if (!locals.db || !locals.tenant) return null;
    const [row] = await locals.db
        .select({ name: oidcClients.name })
        .from(oidcClients)
        .where(and(eq(oidcClients.tenantId, locals.tenant.id), eq(oidcClients.clientId, clientId), eq(oidcClients.enabled, true)))
        .limit(1);
    return row ?? null;
}

/**
 * `id_token_hint` 없이 들어온 로그아웃 요청의 확인 화면.
 *
 * OIDC RP-Initiated Logout 1.0 §2 가 "사용자가 로그아웃을 의도했는지 확인할 수 없으면 물어라"
 * 고 하는 지점이다. 소유 증명(`id_token_hint`)이 없으니 여기서 사용자의 명시적 클릭을 받는다.
 * 이 화면이 drive-by 로그아웃(CSRF)의 실질 방어선이다 — 공격자가 최상위 네비게이션으로 유도해도
 * 버튼을 누르는 것은 사용자다.
 *
 * 폼은 double-submit CSRF 토큰을 실어 POST 한다. 토큰은 httpOnly 쿠키에 심고 폼에 서버
 * 렌더링으로 주입하므로 교차 출처 공격자는 쿠키도 페이지도 읽을 수 없어 위조할 수 없다.
 *
 * SvelteKit 라우트가 아니라 엔드포인트라서 자체 완결 HTML 을 직접 만든다(SAML auto-submit
 * 폼과 같은 방식). 사용자 입력에서 온 값은 전부 `htmlEscape` 를 통과시킨다.
 */
function renderLogoutConfirmPage(event: Parameters<RequestHandler>[0], p: { clientId: string; clientName: string; postLogoutRedirectUri: string | null; state: string | null }): Response {
    const { locals, url, cookies } = event;
    const locale = locals.locale;
    const csrf = ensureCsrfToken(cookies, url);
    const t = (key: string, params?: Record<string, string>) => htmlEscape(translate(locale, key, params));

    const hidden = [
        `<input type="hidden" name="csrf" value="${htmlEscape(csrf)}" />`,
        `<input type="hidden" name="client_id" value="${htmlEscape(p.clientId)}" />`,
        p.postLogoutRedirectUri ? `<input type="hidden" name="post_logout_redirect_uri" value="${htmlEscape(p.postLogoutRedirectUri)}" />` : "",
        p.state ? `<input type="hidden" name="state" value="${htmlEscape(p.state)}" />` : "",
    ].join("");

    // 클라이언트 이름만 강조하려면 문장 안에서의 위치를 알아야 하는데, 어순이 로케일마다 달라
    // 문자열을 쪼갤 수 없다. 제어문자 sentinel 로 자리를 잡아두고 이스케이프한 뒤 치환하면 어순과
    // 이스케이프를 모두 지킬 수 있다 (U+0001 은 메시지 카탈로그에도 클라이언트 이름에도 나타날 수
    // 없고 htmlEscape 도 건드리지 않는다).
    const CLIENT_SLOT = "\u0001";
    const bodyText = t("oidc.logout_confirm.body", { client: CLIENT_SLOT })
        .split(CLIENT_SLOT)
        .join(`<span class="rp">${htmlEscape(p.clientName)}</span>`);

    const html = renderPageShell({
        lang: htmlEscape(locale),
        title: t("oidc.logout_confirm.title"),
        body:
            `<div class="card">` +
            `<h1>${t("oidc.logout_confirm.title")}</h1>` +
            `<p class="sub">${bodyText}</p>` +
            `<form method="POST" action="${htmlEscape(url.pathname)}">` +
            hidden +
            `<div class="actions">` +
            `<a class="btn btn-secondary" href="/">${t("oidc.logout_confirm.cancel")}</a>` +
            `<button class="btn btn-primary" type="submit">${t("oidc.logout_confirm.confirm")}</button>` +
            `</div></form></div>`,
    });

    return new Response(html, {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", Pragma: "no-cache" },
    });
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
        // sid 는 ID 토큰과 동일한 sessions.id 를 쓴다. idpSessionId 는 세션 조회 키이므로
        // revokeSession 에만 넘기고 RP 로는 내보내지 않는다.
        const fcTargets = await getOidcFrontchannelTargets(db, tenantId, sessionId, issuerUrl);

        if (bcTargets.length > 0 && signingKeySecrets.length > 0) {
            const signingKey = await getActiveSigningKey(db, tenantId, signingKeySecrets);
            if (signingKey) {
                const bcPromises = bcTargets.map((t) =>
                    sendOneBackchannelLogout(t, userId, sessionId, issuerUrl, signingKey.privateKey, signingKey.kid, platform?.env?.OIDC_WEBHOOK_QUEUE).catch(() => undefined),
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

    if (!locals.db || !locals.tenant) {
        return new Response(JSON.stringify({ error: "server_error" }), {
            status: 503,
            headers: { "Content-Type": "application/json" },
        });
    }

    // ── 확인 화면에서 넘어온 제출 ────────────────────────────────────────────────
    // `id_token_hint` 가 없는 경로는 GET 에서 확인 화면을 거쳐 이 폼으로 들어온다.
    // 소유 증명이 없으므로 **double-submit CSRF 토큰을 반드시 요구한다** — Origin/Referer
    // 검사(위)만으로는 공격자 페이지가 우리 origin 으로 폼을 제출하는 것을 막을 수 없는
    // 브라우저·상황이 있고, 이 토큰은 httpOnly 쿠키와의 일치를 요구하므로 위조할 수 없다.
    if (!idTokenHint) {
        if (!clientId) {
            return new Response(JSON.stringify({ error: "invalid_request", error_description: translate(locals.locale, "oidc.errors.hint_or_client_id_required") }), {
                status: 400,
                headers: { "Content-Type": "application/json" },
            });
        }
        if (!formData || !isValidCsrf(event.cookies, formData)) {
            return new Response(JSON.stringify({ error: "invalid_request", error_description: translate(locals.locale, "oidc.errors.csrf_failed") }), {
                status: 403,
                headers: { "Content-Type": "application/json" },
            });
        }
        // 정리할 세션이 없으면 조용히 끝낸다(GET 의 C-7 과 같은 이유).
        if (!locals.user || !locals.session) {
            return new Response(null, { status: 204 });
        }
        if (!(await findEndSessionClient(locals, clientId))) {
            return new Response(JSON.stringify({ error: "invalid_request", error_description: translate(locals.locale, "oidc.errors.unknown_client") }), {
                status: 400,
                headers: { "Content-Type": "application/json" },
            });
        }
        return executeLogout(event, postLogoutRedirectUri, clientId, state);
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
