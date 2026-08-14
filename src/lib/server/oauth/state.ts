/**
 * OAuth 왕복 상태(state / nonce / PKCE verifier)를 담는 단기 서명 쿠키.
 *
 * 서버측 저장소 대신 쿠키를 쓰는 이유는 `auth/mfa.ts` 와 같다 — Workers 환경에서
 * 추가 테이블·GC 없이 동작하고, 요청 하나로 끝나는 왕복이라 수명이 짧다.
 *
 * 재생 방어는 두 겹이다:
 *   1. 쿠키의 state 와 콜백 쿼리의 state 가 일치해야 한다 (CSRF / 로그인 강제 방어).
 *   2. 검증 직후 쿠키를 삭제한다 (같은 code 로 두 번 진입 불가).
 *
 * 페이로드는 서명만 되고 암호화되지 않으므로 시크릿을 담지 않는다. code_verifier 는
 * 그 자체로 비밀이 아니라 **일회용 난수**이고, 쿠키가 httpOnly 라 스크립트가 못 읽는다.
 */

import type { Cookies } from "@sveltejs/kit";
import { dev } from "$app/environment";
import { signPayload, verifyPayload } from "$lib/server/auth/signed-token";

export const OAUTH_STATE_COOKIE = "idp_oauth_state";

/** authorize 리다이렉트 왕복에 넉넉하되, 방치된 상태가 오래 살지 않을 만큼. */
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

export interface OAuthStateClaims {
    /** 프로바이더 slug. 콜백 라우트 파라미터와 일치해야 한다. */
    slug: string;
    /** CSRF 방어용 난수. 콜백 쿼리의 state 와 대조한다. */
    state: string;
    /** OIDC nonce. OAuth2 전용 프로바이더에서는 사용하지 않는다. */
    nonce?: string;
    /** PKCE code_verifier. 프로바이더가 PKCE 를 지원할 때만 존재. */
    codeVerifier?: string;
    /** 로그인 완료 후 돌아갈 내부 경로. 저장 전 sanitize 된 값만 넣는다. */
    redirectTo: string | null;
    /** 커스텀 스킨 유지용. */
    skinHint: string | null;
}

function cookieOptions(url: URL) {
    return {
        path: "/",
        httpOnly: true,
        // 콜백은 외부 프로바이더에서 오는 top-level GET 이므로 Lax 여야 쿠키가 실린다.
        // Strict 로 두면 콜백에서 쿠키가 사라져 플로우가 성립하지 않는다.
        sameSite: "lax" as const,
        // ctrls M-COOKIE-1 과 동일 — 프로덕션에서는 관측 protocol 과 무관하게 Secure 강제.
        secure: !dev || url.protocol === "https:",
        maxAge: OAUTH_STATE_TTL_MS / 1000,
    };
}

/** state 쿠키를 심는다. */
export async function setOAuthStateCookie(cookies: Cookies, url: URL, claims: OAuthStateClaims, signingKeySecret: string): Promise<void> {
    const token = await signPayload(claims, signingKeySecret, OAUTH_STATE_TTL_MS);
    cookies.set(OAUTH_STATE_COOKIE, token, cookieOptions(url));
}

/**
 * state 쿠키를 읽고 검증한다. 유효하지 않으면 null.
 *
 * 성공 여부와 무관하게 **호출 즉시 쿠키를 삭제**한다. 실패한 시도가 쿠키를 남겨두면
 * 공격자가 같은 상태로 재시도할 여지가 생긴다.
 */
export async function consumeOAuthStateCookie(cookies: Cookies, url: URL, signingKeySecret: string): Promise<OAuthStateClaims | null> {
    const token = cookies.get(OAUTH_STATE_COOKIE);
    clearOAuthStateCookie(cookies, url);
    if (!token) return null;

    const claims = await verifyPayload<OAuthStateClaims>(token, signingKeySecret);
    if (!claims || typeof claims.slug !== "string" || typeof claims.state !== "string") return null;
    return claims;
}

export function clearOAuthStateCookie(cookies: Cookies, url: URL): void {
    cookies.delete(OAUTH_STATE_COOKIE, { path: "/", secure: !dev || url.protocol === "https:" });
}
