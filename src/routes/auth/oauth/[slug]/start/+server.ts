/**
 * 소셜 로그인 시작점. 로그인 페이지의 프로바이더 버튼이 이 URL 로 링크한다.
 *
 * GET 인 이유: 프로바이더로 나가는 top-level 내비게이션이고, 커스텀 스킨에서도 단순
 * `<a>` 로 쓸 수 있어야 한다. 로그인 CSRF(피해자를 공격자 계정으로 로그인시키기)는
 * state 쿠키가 막는다 — 콜백에서 쿠키와 쿼리의 state 가 일치해야만 진행된다.
 */

import { error, redirect } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { requireDbContext } from "$lib/server/auth/guards";
import { getRuntimeConfig } from "$lib/server/auth/runtime";
import { sanitizeRedirectTarget } from "$lib/server/auth/redirect";
import { checkRateLimit } from "$lib/server/ratelimit";
import { getRequestMetadata } from "$lib/server/audit";
import { buildAuthorizationUrl, buildRedirectUri, deriveCodeChallenge, randomToken, resolveEndpoints } from "$lib/server/oauth/client";
import { loadProviderBySlug } from "$lib/server/oauth/provider-store";
import { setOAuthStateCookie } from "$lib/server/oauth/state";

export const GET: RequestHandler = async (event) => {
    const slug = event.params.slug;
    if (!slug) throw error(404, "Not found");

    if (!event.locals.db || !event.locals.tenant) {
        throw error(503, event.locals.runtimeError ?? "데이터베이스가 준비되지 않았습니다.");
    }
    const { db, tenant, rateLimitStore } = requireDbContext(event.locals);

    const config = getRuntimeConfig(event.platform);
    if (!config.signingKeySecret) {
        // state 쿠키에 서명할 수 없으면 CSRF 방어가 성립하지 않는다. 진행 불가.
        throw error(503, "IDP_SIGNING_KEY_SECRET 이 설정되지 않아 소셜 로그인을 사용할 수 없습니다.");
    }

    // authorize 리다이렉트 남용(외부 프로바이더로의 트래픽 증폭) 방지.
    const meta = getRequestMetadata(event);
    const rl = await checkRateLimit(rateLimitStore, `oauth:start:${meta.ipKey}`, { windowMs: 15 * 60 * 1000, limit: 30 });
    if (!rl.allowed) throw error(429, "요청이 너무 잦습니다. 잠시 후 다시 시도해 주세요.");

    const provider = await loadProviderBySlug(db, tenant.id, slug);
    if (!provider) throw error(404, "사용할 수 없는 로그인 방식입니다.");

    const endpoints = await resolveEndpoints(provider.preset, provider.config).catch((e: unknown) => {
        console.warn(`[oauth] ${slug} 엔드포인트 해석 실패:`, (e as Error).message);
        throw error(502, "로그인 제공자 설정을 확인할 수 없습니다.");
    });

    const state = randomToken();
    // OIDC 프로바이더에만 nonce 를 실어 보낸다(OAuth2 전용은 무시하거나 오류를 낸다).
    const nonce = provider.preset.kind === "oidc" ? randomToken() : undefined;
    const codeVerifier = provider.preset.supportsPkce ? randomToken(48) : undefined;
    const codeChallenge = codeVerifier ? await deriveCodeChallenge(codeVerifier) : undefined;

    const redirectTo = sanitizeRedirectTarget(event.url.searchParams.get("redirectTo"));
    const skinHint = event.url.searchParams.get("skinHint");

    await setOAuthStateCookie(event.cookies, event.url, { slug, state, nonce, codeVerifier, redirectTo, skinHint }, config.signingKeySecret);

    const authorizationUrl = buildAuthorizationUrl({
        preset: provider.preset,
        config: provider.config,
        endpoints,
        clientId: provider.clientId,
        redirectUri: buildRedirectUri(event.url.origin, slug),
        state,
        nonce,
        codeChallenge,
        forceReauth: event.url.searchParams.get("forceAuthn") === "true",
    });

    throw redirect(302, authorizationUrl);
};
