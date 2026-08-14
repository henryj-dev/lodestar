/**
 * GitHub OAuth2 어댑터.
 *
 * 특이사항:
 *  - OIDC 가 아니라 순수 OAuth2 → id_token 이 없고 REST API 로 프로필을 읽는다.
 *  - `/user` 의 `email` 은 사용자가 이메일을 비공개로 두면 **null** 이다.
 *    검증된 주 이메일을 얻으려면 `/user/emails` 를 따로 호출해야 한다(`user:email` 스코프).
 *  - User-Agent 헤더가 없으면 403 을 준다 (`http.ts` 에서 항상 붙인다).
 *  - PKCE 미지원.
 */

import { getJson } from "../http";
import type { NormalizedProfile, ProviderPreset, TokenResponse } from "../types";

interface GithubUser {
    id: number;
    login: string;
    name: string | null;
    email: string | null;
    avatar_url: string | null;
}

interface GithubEmail {
    email: string;
    primary: boolean;
    verified: boolean;
}

async function fetchProfile(tokens: TokenResponse): Promise<NormalizedProfile> {
    const auth = { authorization: `Bearer ${tokens.accessToken}` };
    const user = await getJson<GithubUser>("https://api.github.com/user", auth);

    if (user.id === undefined || user.id === null) {
        throw new Error("GitHub 응답에 사용자 id 가 없습니다.");
    }

    // 검증된 주 이메일을 우선한다. 스코프가 없거나 조회에 실패하면 `/user` 의 값으로
    // 폴백하되, 그 값은 검증 여부를 알 수 없으므로 emailVerified=false 로 남긴다.
    let email: string | null = null;
    let emailVerified = false;
    try {
        const emails = await getJson<GithubEmail[]>("https://api.github.com/user/emails", auth);
        const primary = Array.isArray(emails) ? emails.find((e) => e.primary && e.verified) : undefined;
        // 주 이메일이 미검증이면 검증된 아무 주소나 사용한다.
        const fallbackVerified = Array.isArray(emails) ? emails.find((e) => e.verified) : undefined;
        const chosen = primary ?? fallbackVerified;
        if (chosen) {
            email = chosen.email;
            emailVerified = true;
        }
    } catch {
        // user:email 스코프 미승인 등 — 아래 폴백으로 진행한다.
    }

    if (!email && user.email) {
        email = user.email;
        emailVerified = false;
    }

    return {
        subject: String(user.id),
        email: email?.toLowerCase() ?? null,
        emailVerified,
        displayName: user.name ?? user.login,
        suggestedUsername: user.login,
        avatarUrl: user.avatar_url ?? undefined,
        raw: { id: user.id, login: user.login, name: user.name },
    };
}

export const githubPreset: ProviderPreset = {
    id: "github",
    label: "GitHub",
    kind: "oauth2",
    supportsPkce: false,
    defaultScopes: ["read:user", "user:email"],
    authorizationUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    userinfoUrl: "https://api.github.com/user",
    fetchProfile,
};
