import type { Handle, RequestEvent } from "@sveltejs/kit";
import { ensureAuthBaseline } from "$lib/server/auth/bootstrap";
import { SESSION_COOKIE_NAME, SESSION_TOUCH_INTERVAL_MS } from "$lib/server/auth/constants";
import { getRuntimeConfig } from "$lib/server/auth/runtime";
import { clearSessionCookie, getSessionContext, touchSession } from "$lib/server/auth/session";
import { getDb, DB_DIALECT } from "$lib/server/db";
import { resolveRateLimitStore } from "$lib/server/ratelimit";
import { ensureNodeGcScheduler, maybeRunWorkersGc } from "$lib/server/db/gc";
import { LOCALE_COOKIE_NAME, resolveLocale } from "$lib/server/locale";
import { renderMessagePage } from "$lib/server/html/page-shell";
import { translate } from "$lib/i18n/server";

// CSRF: state-changing 요청에 대해 same-origin을 강제할 라우트
// ctrls H-AUTH-1: /oidc/end-session 추가 — POST 가 cookie 기반 세션을 폐기하므로
// browser-initiated CSRF 면적이 있다. 핸들러 자체 Origin 검사 + hook 의 origin
// 검사 둘 다로 defense-in-depth.
const CSRF_PROTECTED = [
    /^\/admin(\/|$)/,
    /^\/account(\/|$)/,
    /^\/(login|signup|find-id|find-password|reset-password|mfa|logout|verify-email|accept-invite)(\/|$)/,
    /^\/api\/webauthn\//,
    /^\/oidc\/end-session(\/|$)/,
];

// CSRF: 프로토콜 자체 인증으로 보호되므로 origin 검사를 건너뛸 라우트 (서버-서버 요청 또는 cookie 미사용)
// ctrls H-AUTH-1: 기존 정규식이 너무 광범위(`/oidc/` 전체)했기 때문에 정확한 endpoint
// 단위로 좁혔다. 신규로 추가될 라우트는 기본적으로 CSRF 검사를 받도록 한다.
const CSRF_SKIP = [
    // SAML 프로토콜 endpoint — 서명된 XML / SP cert 로 자체 인증
    /^\/saml\/(sso|slo|metadata)(\/|$)/,
    // OIDC 프로토콜 endpoint — client_secret/PKCE/Bearer 로 자체 인증, cookie 미사용
    /^\/oidc\/(authorize|token|userinfo|jwks)(\/|$)/,
    // 정적 스크립트 응답
    /^\/api\/skin-scripts(\/|$)/,
    // service-to-service TOTP API — Bearer token 으로 자체 인증, cookie 미사용
    /^\/api\/totp\//,
    // service-to-service users lookup API — Bearer token 으로 자체 인증
    /^\/api\/users\//,
];

// 인증/계정/관리자 등 캐시 금지 + COOP/CORP 적용 대상
//
// `/auth/oauth/*` 는 소셜 로그인 왕복이다. 콜백 응답은 세션 쿠키를 심으므로 절대
// 캐시되면 안 된다. CSRF_PROTECTED 에는 **넣지 않는다** — 콜백은 외부 프로바이더에서
// 오는 GET 이라 Origin/Referer 가 교차 출처이고, 위조 방어는 state 쿠키가 담당한다.
const SENSITIVE = [
    /^\/admin/,
    /^\/account/,
    /^\/(login|signup|find-id|find-password|reset-password|mfa|logout)/,
    /^\/auth\/oauth\//,
    /^\/oidc\/(authorize|token|userinfo|end-session)/,
    /^\/api\/webauthn/,
];

// cross-origin 으로 노출되어야 하는 공개 메타데이터 (CORP 면제)
const PUBLIC_META = [/^\/\.well-known\//, /^\/oidc\/jwks/, /^\/saml\/metadata/];

/**
 * CSRF 검사 실패 응답.
 *
 * 예전에는 Content-Type 도 없는 평문 `"CSRF check failed"` 를 돌려줬다. 대부분은 공격이거나 설정
 * 오류지만 Origin/Referer 를 모두 지우는 프라이버시 확장·프록시를 쓰는 실제 사용자도 이 분기로
 * 떨어지는데, 그 경우 브라우저에 날것의 문자열만 보였다.
 *
 * 그래서 문서 요청(`Accept: text/html`)에는 기본 UI 와 같은 카드로 안내하고, fetch/API 호출에는
 * 종전처럼 짧은 평문을 준다(`/api/webauthn/*` 이 여기 해당). 어느 쪽도 **실패 사유를 구분해서
 * 알려주지 않는다** — Origin 불일치인지 헤더 누락인지는 공격자에게 줄 필요가 없는 정보라 상태
 * 코드와 문구를 하나로 통일한다.
 */
function csrfRejection(event: RequestEvent): Response {
    const common = { "Cache-Control": "no-store", "X-Robots-Tag": "noindex" };

    if (!(event.request.headers.get("accept") ?? "").includes("text/html")) {
        return new Response("CSRF check failed", { status: 403, headers: { ...common, "Content-Type": "text/plain; charset=utf-8" } });
    }

    const locale = event.locals.locale;
    const html = renderMessagePage({
        lang: locale,
        title: translate(locale, "error_page.csrf_title"),
        message: translate(locale, "error_page.csrf_message"),
        link: { href: "/", label: translate(locale, "error_page.home") },
    });
    return new Response(html, { status: 403, headers: { ...common, "Content-Type": "text/html; charset=utf-8" } });
}

export const handle: Handle = async ({ event, resolve }) => {
    event.locals.db = undefined;
    event.locals.rateLimitStore = undefined;
    event.locals.tenant = null;
    event.locals.session = null;
    event.locals.user = null;
    event.locals.runtimeConfig = getRuntimeConfig(event.platform);
    event.locals.runtimeError = null;

    // SSR 로케일 결정: 쿠키(idp_locale) → Accept-Language → 기본 ko.
    // %lang% 치환과 +layout.server.ts(data.locale) 가 이 값을 공유해 하이드레이션 미스매치를 방지한다.
    const locale = resolveLocale(event.cookies.get(LOCALE_COOKIE_NAME), event.request.headers.get("accept-language"));
    event.locals.locale = locale;

    const path = event.url.pathname;

    // ── CSRF: 라우트별 same-origin 검사 ─────────────────────────────────────────
    if (event.request.method !== "GET" && event.request.method !== "HEAD") {
        const requireOrigin = CSRF_PROTECTED.some((r) => r.test(path)) && !CSRF_SKIP.some((r) => r.test(path));
        if (requireOrigin) {
            const origin = event.request.headers.get("origin");
            if (origin) {
                try {
                    if (new URL(origin).host !== event.url.host) {
                        return csrfRejection(event);
                    }
                } catch {
                    return csrfRejection(event);
                }
            } else {
                const referer = event.request.headers.get("referer");
                if (referer) {
                    try {
                        if (new URL(referer).host !== event.url.host) {
                            return csrfRejection(event);
                        }
                    } catch {
                        return csrfRejection(event);
                    }
                } else {
                    // Origin/Referer 모두 없는 state-changing 요청은 보호 라우트에서 거부
                    return csrfRejection(event);
                }
            }
        }
    }

    // baseline 쿼리가 불필요한 경로 (정적 메타데이터, 헬스체크)
    // well-known metadata must resolve the tenant too: host/path-scoped OIDC discovery
    // otherwise falls back to the default tenant and can expose the wrong issuer/JWKS.
    const skipBaseline = path === "/api/health" || path === "/favicon.ico" || path === "/robots.txt";

    // postgres/mysql(Workers) 경로에서 요청당 연 DB 연결을 응답 후 닫기 위한 정리 함수.
    // D1/sqlite/Node 전역 재사용 경로에서는 undefined.
    let disposeDb: (() => Promise<void>) | undefined;

    try {
        // DB 초기화 게이트는 방언별로 다르다:
        // - d1: platform.env.DB(D1 바인딩)가 반드시 있어야 한다(Workers 전용).
        // - postgres/mysql/sqlite: 연결 정보를 platform.env(HYPERDRIVE/DATABASE_URL) 또는
        //   process.env 에서 getDb 가 해석한다. 없으면 getDb 가 throw → catch 에서 runtimeError.
        const shouldInitDb = DB_DIALECT === "d1" ? Boolean(event.platform?.env?.DB) : true;
        if (shouldInitDb) {
            const handle = await getDb(event.platform);
            const db = handle.db;
            disposeDb = handle.dispose;
            event.locals.db = db;
            // 레이트 리밋 저장소: Workers=DB(요청당 db), Node=프로세스 전역 in-memory.
            event.locals.rateLimitStore = resolveRateLimitStore(event.platform, db);

            // 만료 데이터 GC 실행 경로 (요청 처리와 완전히 격리 — 실패해도 무영향):
            // - Workers: 요청의 ~1% 에서 ctx.waitUntil 로 백그라운드 발사(응답 지연 0).
            // - Node: 최초 1회 setInterval(1시간) 스케줄러 기동(중복 가드 내장).
            // adapter-cloudflare 는 커스텀 worker 엔트리 없이 scheduled() Cron 을 노출할 수
            // 없어(생성된 _worker.js 는 fetch 만 export) 빌드 침습을 피해 확률적 GC 를 택했다.
            if (typeof event.platform?.ctx?.waitUntil === "function") {
                maybeRunWorkersGc(event.platform);
            } else {
                ensureNodeGcScheduler();
            }

            event.locals.tenant = skipBaseline ? null : await ensureAuthBaseline(db, event.platform, event.url);

            const sessionToken = event.cookies.get(SESSION_COOKIE_NAME);

            if (sessionToken) {
                const sessionContext = event.locals.tenant ? await getSessionContext(db, sessionToken, event.locals.tenant.id) : null;

                if (sessionContext) {
                    event.locals.session = sessionContext.session;
                    event.locals.user = sessionContext.user;

                    if (Date.now() - sessionContext.session.lastSeenAt.getTime() >= SESSION_TOUCH_INTERVAL_MS) {
                        const now = new Date();
                        await touchSession(db, sessionContext.session.id, now);
                        event.locals.session.lastSeenAt = now;
                    }
                } else {
                    clearSessionCookie(event.cookies, event.url);
                }
            }
        }
    } catch (error) {
        event.locals.runtimeError = error instanceof Error ? error.message : "인증 컨텍스트 초기화 중 오류가 발생했습니다.";
        console.error(event.locals.runtimeError, error);
    }

    let response: Response;
    try {
        response = await resolve(event, {
            // app.html 의 %lang% 를 실제 SSR 로케일로 치환 (<html lang>).
            transformPageChunk: ({ html }) => html.replace("%lang%", locale),
        });
    } finally {
        // 요청당 연 postgres/mysql 연결 정리. Workers 는 waitUntil 로 응답을 막지 않고
        // 백그라운드에서 닫는다. Node 경로엔 dispose 가 없으므로 no-op.
        if (disposeDb) {
            const wait = event.platform?.ctx?.waitUntil?.bind(event.platform.ctx);
            const closing = disposeDb().catch((e) => console.error("DB dispose 실패", e));
            if (wait) wait(closing);
        }
    }

    // ── 보안 헤더 ──────────────────────────────────────────────────────────────
    // Clickjacking 방지
    response.headers.set("X-Frame-Options", "DENY");
    response.headers.set("X-Content-Type-Options", "nosniff");

    // Referrer 정책
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");

    // HSTS (HTTPS 강제, 1년)
    response.headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

    // Permissions Policy — 불필요한 브라우저 기능 비활성화 + FLoC/Topics 차단
    response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), interest-cohort=(), browsing-topics=()");

    // 민감 라우트 캐시 금지
    if (SENSITIVE.some((r) => r.test(path))) {
        response.headers.set("Cache-Control", "no-store, private");
        response.headers.set("Pragma", "no-cache");
    }

    // COOP/CORP — 공개 메타데이터(JWKS, SAML metadata, .well-known) 제외하고 same-origin 강제
    if (!PUBLIC_META.some((r) => r.test(path))) {
        response.headers.set("Cross-Origin-Opener-Policy", "same-origin");
        response.headers.set("Cross-Origin-Resource-Policy", "same-origin");
    }

    // CSP는 svelte.config.js csp.mode='hash' 로 관리 (unsafe-inline 없는 해시 기반)

    return response;
};
