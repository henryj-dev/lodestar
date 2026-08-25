/**
 * OAuth2 / OIDC authorization-code 플로우의 프로토콜 계층.
 *
 * 라우트(`/auth/oauth/[slug]/{start,callback}`)는 여기 있는 세 함수만 쓰면 된다:
 *   1. `resolveEndpoints` — discovery 또는 프리셋으로 엔드포인트 확정
 *   2. `buildAuthorizationUrl` — authorize 리다이렉트 URL 조립
 *   3. `exchangeCode` — code → 토큰 교환
 */

import { b64uEncode } from "$lib/server/crypto/keys";
import { getJson, postForm } from "./http";
import { getPreset, resolveDiscoveryUrl, resolveScopes } from "./registry";
import type { OAuthProviderConfig, ProviderPreset, ResolvedEndpoints, TokenResponse } from "./types";

/** discovery 문서 캐시 TTL. 엔드포인트는 거의 바뀌지 않으므로 넉넉히 잡는다. */
const DISCOVERY_CACHE_TTL_MS = 60 * 60 * 1000;

interface DiscoveryDoc {
    issuer?: string;
    authorization_endpoint?: string;
    token_endpoint?: string;
    userinfo_endpoint?: string;
    jwks_uri?: string;
}

const discoveryCache = new Map<string, { doc: DiscoveryDoc; fetchedAt: number }>();

/** 테스트 및 설정 변경 대응용. */
export function invalidateDiscoveryCache(url?: string): void {
    if (url) discoveryCache.delete(url);
    else discoveryCache.clear();
}

async function fetchDiscovery(url: string): Promise<DiscoveryDoc> {
    const cached = discoveryCache.get(url);
    if (cached && Date.now() - cached.fetchedAt < DISCOVERY_CACHE_TTL_MS) return cached.doc;

    const doc = await getJson<DiscoveryDoc>(url);
    discoveryCache.set(url, { doc, fetchedAt: Date.now() });
    return doc;
}

/**
 * 프리셋 + 설정 + (있다면) discovery 를 합쳐 최종 엔드포인트를 만든다.
 * 우선순위: 관리자 설정 > discovery > 프리셋 리터럴.
 */
export async function resolveEndpoints(preset: ProviderPreset, config: OAuthProviderConfig): Promise<ResolvedEndpoints> {
    let doc: DiscoveryDoc = {};
    const discoveryUrl = resolveDiscoveryUrl(preset, config);
    if (discoveryUrl) {
        doc = await fetchDiscovery(discoveryUrl);
    }

    const authorizationUrl = config.authorizationUrl ?? doc.authorization_endpoint ?? preset.authorizationUrl;
    const tokenUrl = config.tokenUrl ?? doc.token_endpoint ?? preset.tokenUrl;

    if (!authorizationUrl) throw new Error(`${preset.label}: authorization 엔드포인트를 확인할 수 없습니다.`);
    if (!tokenUrl) throw new Error(`${preset.label}: token 엔드포인트를 확인할 수 없습니다.`);

    const jwksUri = doc.jwks_uri;
    if (jwksUri !== undefined) {
        try {
            const parsedJwksUri = new URL(jwksUri);
            if (parsedJwksUri.protocol !== "https:" && parsedJwksUri.protocol !== "http:") throw new Error("unsupported scheme");
        } catch {
            throw new Error("OIDC discovery의 jwks_uri가 절대 URL이 아닙니다.");
        }
    }

    return {
        issuer: config.issuer ?? doc.issuer,
        authorizationUrl,
        tokenUrl,
        userinfoUrl: config.userinfoUrl ?? doc.userinfo_endpoint ?? preset.userinfoUrl,
        jwksUri,
    };
}

/** 암호학적 난수를 base64url 문자열로. state / nonce / code_verifier 생성에 쓴다. */
export function randomToken(bytes = 32): string {
    return b64uEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** PKCE S256 challenge 계산. */
export async function deriveCodeChallenge(verifier: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return b64uEncode(new Uint8Array(digest));
}

export interface AuthorizationUrlParams {
    preset: ProviderPreset;
    config: OAuthProviderConfig;
    endpoints: ResolvedEndpoints;
    clientId: string;
    redirectUri: string;
    state: string;
    nonce?: string;
    codeChallenge?: string;
    /** OIDC prompt=login 강제(재인증). SAML ForceAuthn / OIDC prompt=login 전달용. */
    forceReauth?: boolean;
}

/** authorize 리다이렉트 URL 을 조립한다. */
export function buildAuthorizationUrl(params: AuthorizationUrlParams): string {
    const { preset, config, endpoints, clientId, redirectUri, state, nonce, codeChallenge, forceReauth } = params;

    const url = new URL(endpoints.authorizationUrl);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("state", state);

    const scopes = resolveScopes(preset, config);
    if (scopes.length > 0) url.searchParams.set("scope", scopes.join(" "));

    // nonce 는 OIDC 전용. OAuth2 전용 프로바이더에 보내면 무시되거나 오류가 날 수 있다.
    if (nonce && preset.kind === "oidc") url.searchParams.set("nonce", nonce);

    if (codeChallenge && preset.supportsPkce) {
        url.searchParams.set("code_challenge", codeChallenge);
        url.searchParams.set("code_challenge_method", "S256");
    }

    if (forceReauth && preset.kind === "oidc") url.searchParams.set("prompt", "login");

    for (const [k, v] of Object.entries(preset.extraAuthParams ?? {})) {
        url.searchParams.set(k, v);
    }

    return url.toString();
}

export interface ExchangeCodeParams {
    preset: ProviderPreset;
    endpoints: ResolvedEndpoints;
    clientId: string;
    clientSecret: string;
    code: string;
    redirectUri: string;
    /** 프로바이더가 PKCE 를 지원할 때만 전송된다. */
    codeVerifier?: string;
    /** 네이버는 토큰 교환에도 state 를 요구한다. */
    state?: string;
}

interface RawTokenResponse {
    access_token?: string;
    id_token?: string;
    token_type?: string;
    scope?: string;
}

/** authorization code 를 토큰으로 교환한다. */
export async function exchangeCode(params: ExchangeCodeParams): Promise<TokenResponse> {
    const { preset, endpoints, clientId, clientSecret, code, redirectUri, codeVerifier, state } = params;

    const form: Record<string, string> = {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        client_secret: clientSecret,
    };
    if (codeVerifier && preset.supportsPkce) form.code_verifier = codeVerifier;
    if (state) form.state = state;

    // GitHub 은 Accept 헤더가 없으면 form-urlencoded 본문을 돌려준다. `http.ts` 가
    // 항상 accept: application/json 을 보내므로 별도 분기는 필요 없다.
    const raw = await postForm<RawTokenResponse>(endpoints.tokenUrl, form);

    if (!raw.access_token) {
        throw new Error(`${preset.label}: 토큰 응답에 access_token 이 없습니다.`);
    }

    return {
        accessToken: raw.access_token,
        idToken: raw.id_token,
        tokenType: raw.token_type,
        scope: raw.scope,
    };
}

/**
 * 콜백 URL 을 만든다. 프로바이더 콘솔에 등록하는 Redirect URI 와 **정확히** 같아야 한다
 * (네이버/카카오는 완전 일치를 요구한다).
 */
export function buildRedirectUri(origin: string, slug: string): string {
    return `${origin}/auth/oauth/${encodeURIComponent(slug)}/callback`;
}

/** slug 로 프리셋을 찾아 설정과 함께 돌려주는 편의 함수. */
export function loadPreset(config: OAuthProviderConfig): ProviderPreset {
    const preset = getPreset(config.providerType);
    if (!preset) throw new Error(`알 수 없는 프로바이더 타입: ${config.providerType}`);
    return preset;
}
