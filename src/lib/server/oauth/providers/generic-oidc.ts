/**
 * 표준 OIDC 어댑터. Microsoft Entra ID, Google, 그 밖의 discovery 를 제공하는
 * 모든 프로바이더가 이 하나를 공유한다.
 *
 * 프로필 출처는 id_token 클레임이다. 서명·iss·aud·exp·nonce 를 `jwt.ts` 에서 검증한 뒤
 * 클레임을 매핑한다. id_token 이 없으면(비표준 구성) userinfo 엔드포인트로 폴백한다.
 */

import { getJson } from "../http";
import { verifyUpstreamIdToken } from "../jwt";
import type { NormalizedProfile, ProfileContext, ProviderPreset, TokenResponse } from "../types";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Microsoft 의 `common`/`organizations` discovery 는 issuer 를 리터럴이 아니라
 * `https://login.microsoftonline.com/{tenantid}/v2.0` 템플릿으로 돌려준다.
 * 실제 검증은 토큰의 `tid` 를 끼워 넣은 값으로 해야 한다.
 */
function resolveExpectedIssuer(templateIssuer: string, idToken: string): string {
    if (!templateIssuer.includes("{tenantid}")) return templateIssuer;

    // tid 를 읽기 위한 서명 전 파싱. 여기서 얻은 값은 issuer 조립에만 쓰이고,
    // 그 issuer 로 서명 검증을 통과해야만 신뢰된다(=단독으로는 신뢰 근거가 아니다).
    try {
        const payload = JSON.parse(atob(idToken.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))) as { tid?: unknown };
        // tid 는 디렉터리 GUID 다. 경로 조작을 막기 위해 GUID 형식만 허용한다.
        if (typeof payload.tid === "string" && /^[0-9a-f-]{36}$/i.test(payload.tid)) {
            return templateIssuer.replace("{tenantid}", payload.tid);
        }
    } catch {
        // 파싱 실패 → 치환 없이 진행하면 아래 issuer 검증에서 실패한다.
    }
    return templateIssuer;
}

/** OIDC 표준 클레임을 KeyStone 프로필로 매핑한다. */
function mapClaims(claims: Record<string, unknown>): NormalizedProfile {
    const sub = claims.sub;
    if (typeof sub !== "string" || !sub) {
        throw new Error("OIDC 응답에 sub 클레임이 없습니다.");
    }

    // email 클레임이 없는 프로바이더가 많다. Entra 는 preferred_username 에 UPN 을 넣는데
    // 이것이 이메일 형식일 때만 폴백으로 쓴다.
    let email: string | null = typeof claims.email === "string" ? claims.email : null;
    if (!email && typeof claims.preferred_username === "string" && EMAIL_REGEX.test(claims.preferred_username)) {
        email = claims.preferred_username;
    }

    // 프로바이더가 email_verified=true 를 **명시**한 경우에만 검증된 것으로 본다.
    // 클레임 부재는 "검증됨" 이 아니다.
    const emailVerified = Boolean(email && claims.email_verified === true);

    const givenName = typeof claims.given_name === "string" ? claims.given_name : undefined;
    const familyName = typeof claims.family_name === "string" ? claims.family_name : undefined;
    const name = typeof claims.name === "string" ? claims.name : undefined;

    return {
        subject: sub,
        email: email?.toLowerCase() ?? null,
        emailVerified,
        displayName: name ?? ([givenName, familyName].filter(Boolean).join(" ") || undefined),
        givenName,
        familyName,
        avatarUrl: typeof claims.picture === "string" ? claims.picture : undefined,
        suggestedUsername: typeof claims.preferred_username === "string" ? claims.preferred_username : undefined,
        raw: { sub, name, preferred_username: claims.preferred_username },
    };
}

async function fetchProfile(tokens: TokenResponse, ctx: ProfileContext): Promise<NormalizedProfile> {
    const resolved = ctx.resolved;

    if (tokens.idToken) {
        if (!resolved?.jwksUri) {
            throw new Error("OIDC 프로바이더의 jwks_uri 를 확인할 수 없어 id_token 을 검증할 수 없습니다.");
        }
        const templateIssuer = ctx.config.issuer ?? resolved.issuer;
        if (!templateIssuer) {
            throw new Error("OIDC 프로바이더의 issuer 를 확인할 수 없습니다.");
        }

        const claims = await verifyUpstreamIdToken(tokens.idToken, {
            jwksUri: resolved.jwksUri,
            issuer: resolveExpectedIssuer(templateIssuer, tokens.idToken),
            audience: ctx.clientId,
            nonce: ctx.nonce,
        });
        return mapClaims(claims);
    }

    // id_token 미제공 — userinfo 폴백. 이 경로는 nonce 로 재생을 막을 수 없으므로
    // state 검증(콜백 단계)이 유일한 방어선이 된다.
    const userinfoUrl = ctx.config.userinfoUrl ?? resolved?.userinfoUrl;
    if (!userinfoUrl) {
        throw new Error("id_token 도 userinfo 엔드포인트도 없어 프로필을 얻을 수 없습니다.");
    }
    const claims = await getJson<Record<string, unknown>>(userinfoUrl, { authorization: `Bearer ${tokens.accessToken}` });
    return mapClaims(claims);
}

/** 자체 호스팅 등 임의 OIDC 프로바이더용. discoveryUrl 을 관리자가 직접 입력한다. */
export const genericOidcPreset: ProviderPreset = {
    id: "oidc",
    label: "OpenID Connect",
    kind: "oidc",
    supportsPkce: true,
    defaultScopes: ["openid", "profile", "email"],
    fetchProfile,
};

export const microsoftPreset: ProviderPreset = {
    id: "microsoft",
    label: "Microsoft",
    kind: "oidc",
    supportsPkce: true,
    defaultScopes: ["openid", "profile", "email"],
    // {directoryTenant} 는 registry 에서 설정값으로 치환된다 (기본 common).
    discoveryUrl: "https://login.microsoftonline.com/{directoryTenant}/v2.0/.well-known/openid-configuration",
    fetchProfile,
};

export const googlePreset: ProviderPreset = {
    id: "google",
    label: "Google",
    kind: "oidc",
    supportsPkce: true,
    defaultScopes: ["openid", "profile", "email"],
    discoveryUrl: "https://accounts.google.com/.well-known/openid-configuration",
    fetchProfile,
};
