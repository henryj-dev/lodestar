/**
 * upstream OIDC 프로바이더가 발급한 id_token 검증.
 *
 * `crypto/keys.ts` 의 `verifyIdToken` 은 **KeyStone 이 직접 발급한** 토큰을 DB 의
 * signing_keys 로 검증한다. 여기서는 반대 방향 — 외부 프로바이더의 원격 JWKS 로
 * 검증한다.
 *
 * authorization code 를 TLS 로 토큰 엔드포인트에 직접 교환했으므로 OIDC Core 3.1.3.7
 * 은 서명 검증을 생략해도 된다고 허용하지만(§6), IdP 제품으로서 서명까지 검증한다.
 * 토큰 엔드포인트 응답이 중간에서 바뀌는 상황(잘못 구성된 프록시, 사내 TLS 종료 등)
 * 까지 방어 범위에 넣기 위해서다.
 */

import { b64uDecode } from "$lib/server/crypto/keys";
import { timingSafeEqual } from "$lib/server/auth/signed-token";
import { getJson } from "$lib/server/oauth/http";

/** 시계 오차 허용치. exp/iat 검사에 양방향으로 적용한다. */
const CLOCK_SKEW_MS = 60 * 1000;

/** JWKS 캐시 TTL. 키 회전 반영과 요청당 fetch 회피 사이의 절충. */
const JWKS_CACHE_TTL_MS = 10 * 60 * 1000;
const JWKS_CACHE_MAX_ENTRIES = 32;

interface JwksCacheEntry {
    keys: JsonWebKey[];
    fetchedAt: number;
}

const jwksCache = new Map<string, JwksCacheEntry>();

/** 테스트 및 키 회전 대응용 캐시 무효화. */
export function invalidateJwksCache(jwksUri?: string): void {
    if (jwksUri) jwksCache.delete(jwksUri);
    else jwksCache.clear();
}

/** Exposed for bounded-cache regression tests and operational diagnostics. */
export function getJwksCacheSize(): number {
    return jwksCache.size;
}

async function fetchJwks(jwksUri: string): Promise<JsonWebKey[]> {
    const cached = jwksCache.get(jwksUri);
    if (cached && Date.now() - cached.fetchedAt < JWKS_CACHE_TTL_MS) return cached.keys;

    const body = await getJson<{ keys?: JsonWebKey[] }>(jwksUri);
    if (!Array.isArray(body.keys)) throw new Error("JWKS 응답에 keys 배열이 없습니다.");

    // Keep attacker-controlled discovery/JWKS URLs from growing the isolate cache without bound.
    if (jwksCache.size >= JWKS_CACHE_MAX_ENTRIES) {
        const oldest = jwksCache.keys().next().value as string | undefined;
        if (oldest) jwksCache.delete(oldest);
    }
    jwksCache.set(jwksUri, { keys: body.keys, fetchedAt: Date.now() });
    return body.keys;
}

interface JwtHeader {
    alg?: string;
    kid?: string;
}

/** 지원 서명 알고리즘 → WebCrypto import/verify 파라미터. */
const ALG_PARAMS: Record<string, { importAlg: RsaHashedImportParams | EcKeyImportParams; verifyAlg: AlgorithmIdentifier | RsaPssParams | EcdsaParams }> = {
    RS256: { importAlg: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verifyAlg: { name: "RSASSA-PKCS1-v1_5" } },
    RS384: { importAlg: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, verifyAlg: { name: "RSASSA-PKCS1-v1_5" } },
    RS512: { importAlg: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, verifyAlg: { name: "RSASSA-PKCS1-v1_5" } },
    ES256: { importAlg: { name: "ECDSA", namedCurve: "P-256" }, verifyAlg: { name: "ECDSA", hash: "SHA-256" } },
    ES384: { importAlg: { name: "ECDSA", namedCurve: "P-384" }, verifyAlg: { name: "ECDSA", hash: "SHA-384" } },
};

export interface VerifyUpstreamIdTokenOptions {
    jwksUri: string;
    /** 기대 issuer. 정확히 일치해야 한다. */
    issuer: string;
    /** 기대 audience — 우리 client_id. */
    audience: string;
    /** authorize 요청에 실었던 nonce. 지정 시 반드시 일치해야 한다. */
    nonce?: string;
}

/**
 * id_token 을 검증하고 클레임을 반환한다. 실패 시 예외를 던진다(호출부가 사유를 로깅할 수 있도록).
 *
 * 검증 항목: alg 화이트리스트 · JWKS 서명 · iss · aud · azp · exp · iat · nonce.
 */
export async function verifyUpstreamIdToken(idToken: string, options: VerifyUpstreamIdTokenOptions): Promise<Record<string, unknown>> {
    const parts = idToken.split(".");
    if (parts.length !== 3) throw new Error("id_token 형식이 올바르지 않습니다.");

    const [headerB64, payloadB64, sigB64] = parts;
    const header = JSON.parse(new TextDecoder().decode(b64uDecode(headerB64))) as JwtHeader;

    // alg 화이트리스트. `none` 및 HMAC 계열(HS*)을 명시적으로 배제해
    // alg confusion(공개키를 HMAC 비밀키로 사용) 공격을 차단한다.
    const algParams = header.alg ? ALG_PARAMS[header.alg] : undefined;
    if (!algParams) throw new Error(`지원하지 않는 id_token 서명 알고리즘: ${header.alg ?? "(없음)"}`);

    const jwks = await fetchJwks(options.jwksUri);
    // kid 가 있으면 해당 키만, 없으면 알고리즘이 맞는 키를 순회한다(일부 프로바이더는 kid 를 생략).
    const candidates = header.kid ? jwks.filter((k) => (k as { kid?: string }).kid === header.kid) : jwks.filter((k) => !k.alg || k.alg === header.alg);
    if (candidates.length === 0) throw new Error("id_token 의 kid 에 해당하는 JWKS 키를 찾을 수 없습니다.");

    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signature = b64uDecode(sigB64);

    let verified = false;
    for (const jwk of candidates) {
        try {
            const key = await crypto.subtle.importKey("jwk", jwk, algParams.importAlg, false, ["verify"]);
            if (await crypto.subtle.verify(algParams.verifyAlg, key, signature, signingInput)) {
                verified = true;
                break;
            }
        } catch {
            // 이 키로는 import/verify 불가 — 다음 후보로.
        }
    }
    if (!verified) throw new Error("id_token 서명 검증에 실패했습니다.");

    const claims = JSON.parse(new TextDecoder().decode(b64uDecode(payloadB64))) as Record<string, unknown>;
    const now = Date.now();

    if (typeof claims.iss !== "string" || !timingSafeEqual(claims.iss, options.issuer)) {
        throw new Error(`id_token issuer 불일치 (기대: ${options.issuer})`);
    }

    // aud 는 문자열 또는 배열. 배열이면 우리 client_id 가 포함되어야 한다.
    const aud = claims.aud;
    const audOk = typeof aud === "string" ? timingSafeEqual(aud, options.audience) : Array.isArray(aud) && aud.some((a) => typeof a === "string" && timingSafeEqual(a, options.audience));
    if (!audOk) throw new Error("id_token audience 불일치");

    // aud 가 복수면 azp 가 필수이고 우리 client_id 여야 한다 (OIDC Core 3.1.3.7 §4).
    if (Array.isArray(aud) && aud.length > 1) {
        if (typeof claims.azp !== "string" || !timingSafeEqual(claims.azp, options.audience)) {
            throw new Error("복수 audience id_token 의 azp 가 client_id 와 일치하지 않습니다.");
        }
    }

    if (typeof claims.exp !== "number" || claims.exp * 1000 + CLOCK_SKEW_MS < now) {
        throw new Error("id_token 이 만료되었습니다.");
    }
    if (typeof claims.iat === "number" && claims.iat * 1000 - CLOCK_SKEW_MS > now) {
        throw new Error("id_token 의 iat 가 미래입니다.");
    }

    if (options.nonce !== undefined) {
        if (typeof claims.nonce !== "string" || !timingSafeEqual(claims.nonce, options.nonce)) {
            throw new Error("id_token nonce 불일치");
        }
    }

    return claims;
}
