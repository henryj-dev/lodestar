/**
 * 카카오 로그인 어댑터.
 *
 * 특이사항:
 *  - `id` 가 **숫자**로 내려온다. `identities.subject` 는 문자열이므로 변환이 필수다.
 *    (JS number 정밀도 문제를 피하려면 문자열화 시점이 중요하지만, 카카오 id 는
 *     안전 정수 범위 안이라 JSON.parse 단계에서 손실되지 않는다.)
 *  - 이메일은 `kakao_account.email` 이고, `account_email` 스코프가 필요하다.
 *    이 스코프는 **비즈 앱 검수**를 통과해야 쓸 수 있어서 기본 스코프에 넣지 않았다.
 *    미승인 스코프를 요청하면 authorize 단계에서 하드 실패(KOE205 등)하기 때문이다.
 *    검수 완료 후 관리자가 스코프에 `account_email` 을 추가하면 이메일이 프리필된다.
 *  - 이메일 신뢰도는 `is_email_valid` + `is_email_verified` 두 플래그를 **모두** 봐야 한다.
 *  - PKCE 지원.
 */

import { getJson } from "../http";
import type { NormalizedProfile, ProviderPreset, TokenResponse } from "../types";

interface KakaoMeResponse {
    id?: number | string;
    kakao_account?: {
        email?: string;
        is_email_valid?: boolean;
        is_email_verified?: boolean;
        profile?: {
            nickname?: string;
            profile_image_url?: string;
        };
    };
    properties?: {
        nickname?: string;
        profile_image?: string;
    };
}

async function fetchProfile(tokens: TokenResponse): Promise<NormalizedProfile> {
    const body = await getJson<KakaoMeResponse>("https://kapi.kakao.com/v2/user/me", {
        authorization: `Bearer ${tokens.accessToken}`,
    });

    if (body.id === undefined || body.id === null || body.id === "") {
        throw new Error("카카오 응답에 사용자 id 가 없습니다.");
    }

    const account = body.kakao_account;
    const email = account?.email?.toLowerCase() ?? null;
    // 두 플래그가 모두 true 일 때만 검증된 것으로 취급한다. 하나라도 빠지면 미검증.
    const emailVerified = Boolean(email && account?.is_email_valid === true && account?.is_email_verified === true);

    const nickname = account?.profile?.nickname ?? body.properties?.nickname;

    return {
        subject: String(body.id),
        email,
        emailVerified,
        displayName: nickname,
        avatarUrl: account?.profile?.profile_image_url ?? body.properties?.profile_image,
        raw: { id: String(body.id), nickname },
    };
}

export const kakaoPreset: ProviderPreset = {
    id: "kakao",
    label: "카카오",
    kind: "oauth2",
    supportsPkce: true,
    // account_email 은 비즈 앱 검수가 필요해 기본값에서 제외한다(위 주석 참고).
    defaultScopes: ["profile_nickname"],
    authorizationUrl: "https://kauth.kakao.com/oauth/authorize",
    tokenUrl: "https://kauth.kakao.com/oauth/token",
    userinfoUrl: "https://kapi.kakao.com/v2/user/me",
    fetchProfile,
};
