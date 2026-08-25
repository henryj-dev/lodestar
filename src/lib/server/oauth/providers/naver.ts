/**
 * 네이버 로그인 어댑터.
 *
 * 특이사항:
 *  - 순수 OAuth2. id_token 없음, PKCE 미지원.
 *  - userinfo 응답이 `{ resultcode, message, response: { ... } }` 로 **한 겹 중첩**된다.
 *  - 이메일·닉네임 등은 네이버 개발자센터에서 항목별 제공 동의를 받아야 내려온다.
 *    승인 전이거나 사용자가 동의를 거부하면 **필드 자체가 없다.**
 *  - 이메일 검증 여부를 알려주는 필드가 없다. 네이버가 가입 시 이메일을 확인하더라도
 *    프로토콜상 단언이 없으므로 `emailVerified=false` 로 보수적으로 처리한다
 *    (→ 연합 가입 시 Lodestar 이 자체 인증 메일을 보낸다).
 */

import { getJson } from "../http";
import type { NormalizedProfile, ProviderPreset, TokenResponse } from "../types";

interface NaverMeResponse {
    resultcode?: string;
    message?: string;
    response?: {
        id?: string;
        email?: string;
        nickname?: string;
        name?: string;
        profile_image?: string;
    };
}

async function fetchProfile(tokens: TokenResponse): Promise<NormalizedProfile> {
    const body = await getJson<NaverMeResponse>("https://openapi.naver.com/v1/nid/me", {
        authorization: `Bearer ${tokens.accessToken}`,
    });

    // resultcode 가 "00" 이 아니면 실패다. HTTP 200 으로 내려오므로 직접 확인해야 한다.
    if (body.resultcode && body.resultcode !== "00") {
        throw new Error(`네이버 프로필 조회 실패: ${body.message ?? body.resultcode}`);
    }

    const profile = body.response;
    if (!profile?.id) {
        throw new Error("네이버 응답에 사용자 id 가 없습니다.");
    }

    return {
        subject: profile.id,
        email: profile.email?.toLowerCase() ?? null,
        // 네이버는 이메일 검증 단언을 제공하지 않는다. 보수적으로 미검증 처리.
        emailVerified: false,
        displayName: profile.nickname ?? profile.name,
        avatarUrl: profile.profile_image,
        raw: { id: profile.id, nickname: profile.nickname },
    };
}

export const naverPreset: ProviderPreset = {
    id: "naver",
    label: "네이버",
    kind: "oauth2",
    supportsPkce: false,
    // 네이버는 authorize 요청의 scope 파라미터를 쓰지 않는다(제공 항목은 콘솔에서 설정).
    defaultScopes: [],
    authorizationUrl: "https://nid.naver.com/oauth2.0/authorize",
    tokenUrl: "https://nid.naver.com/oauth2.0/token",
    userinfoUrl: "https://openapi.naver.com/v1/nid/me",
    fetchProfile,
};
