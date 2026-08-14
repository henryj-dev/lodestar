/**
 * 프로바이더 어댑터의 응답 정규화 검증.
 *
 * 각 프로바이더는 응답 구조가 제각각이고(네이버는 중첩, 카카오는 숫자 id, 깃허브는
 * 이메일이 별도 엔드포인트), 특히 **emailVerified 를 언제 true 로 볼 것인가**가
 * 계정 연결 정책의 입력이라 오판하면 곧바로 보안 문제가 된다.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { githubPreset } from "$lib/server/oauth/providers/github";
import { kakaoPreset } from "$lib/server/oauth/providers/kakao";
import { naverPreset } from "$lib/server/oauth/providers/naver";
import { suggestUsername } from "$lib/server/oauth/provision";
import type { ProfileContext } from "$lib/server/oauth/types";

const CTX: ProfileContext = { config: { providerType: "test" }, clientId: "test-client" };
const TOKENS = { accessToken: "test-access-token" };

/** URL 별 JSON 응답을 돌려주는 fetch 스텁. */
function stubFetch(routes: Record<string, unknown>) {
    return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
        const match = Object.keys(routes).find((k) => url.startsWith(k));
        if (!match) throw new Error(`스텁되지 않은 URL: ${url}`);
        return new Response(JSON.stringify(routes[match]), { status: 200, headers: { "content-type": "application/json" } });
    });
}

afterEach(() => {
    vi.restoreAllMocks();
});

describe("GitHub 어댑터", () => {
    it("검증된 주 이메일을 /user/emails 에서 가져온다", async () => {
        stubFetch({
            "https://api.github.com/user/emails": [
                { email: "secondary@example.com", primary: false, verified: true },
                { email: "primary@example.com", primary: true, verified: true },
            ],
            "https://api.github.com/user": { id: 12345, login: "octocat", name: "The Octocat", email: null, avatar_url: "https://x/y.png" },
        });

        const profile = await githubPreset.fetchProfile(TOKENS, CTX);

        expect(profile.subject).toBe("12345");
        expect(profile.email).toBe("primary@example.com");
        expect(profile.emailVerified).toBe(true);
        expect(profile.suggestedUsername).toBe("octocat");
    });

    it("주 이메일이 미검증이면 검증된 다른 주소를 쓴다", async () => {
        stubFetch({
            "https://api.github.com/user/emails": [
                { email: "unverified@example.com", primary: true, verified: false },
                { email: "verified@example.com", primary: false, verified: true },
            ],
            "https://api.github.com/user": { id: 1, login: "u", name: null, email: null, avatar_url: null },
        });

        const profile = await githubPreset.fetchProfile(TOKENS, CTX);
        expect(profile.email).toBe("verified@example.com");
        expect(profile.emailVerified).toBe(true);
    });

    it("emails 조회가 실패하면 /user 의 이메일로 폴백하되 미검증으로 남긴다", async () => {
        vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
            const url = typeof input === "string" ? input : (input as Request).url;
            if (url.startsWith("https://api.github.com/user/emails")) {
                return new Response("Forbidden", { status: 403 });
            }
            return new Response(JSON.stringify({ id: 7, login: "u", name: null, email: "Fallback@Example.com", avatar_url: null }), {
                status: 200,
                headers: { "content-type": "application/json" },
            });
        });

        const profile = await githubPreset.fetchProfile(TOKENS, CTX);
        expect(profile.email).toBe("fallback@example.com");
        // 검증 근거가 없으므로 절대 true 가 되면 안 된다.
        expect(profile.emailVerified).toBe(false);
    });

    it("검증된 이메일이 하나도 없고 /user 이메일도 없으면 null", async () => {
        stubFetch({
            "https://api.github.com/user/emails": [{ email: "a@example.com", primary: true, verified: false }],
            "https://api.github.com/user": { id: 9, login: "u", name: null, email: null, avatar_url: null },
        });

        const profile = await githubPreset.fetchProfile(TOKENS, CTX);
        expect(profile.email).toBeNull();
        expect(profile.emailVerified).toBe(false);
    });
});

describe("네이버 어댑터", () => {
    it("response 아래 중첩된 프로필을 풀어낸다", async () => {
        stubFetch({
            "https://openapi.naver.com/v1/nid/me": {
                resultcode: "00",
                message: "success",
                response: { id: "naver-user-1", email: "User@Naver.com", nickname: "닉네임", profile_image: "https://x/p.png" },
            },
        });

        const profile = await naverPreset.fetchProfile(TOKENS, CTX);
        expect(profile.subject).toBe("naver-user-1");
        expect(profile.email).toBe("user@naver.com");
        expect(profile.displayName).toBe("닉네임");
    });

    it("이메일 검증 단언이 없으므로 항상 미검증으로 처리한다", async () => {
        stubFetch({
            "https://openapi.naver.com/v1/nid/me": { resultcode: "00", response: { id: "n1", email: "a@naver.com" } },
        });

        const profile = await naverPreset.fetchProfile(TOKENS, CTX);
        expect(profile.emailVerified).toBe(false);
    });

    it("resultcode 가 00 이 아니면 HTTP 200 이라도 실패로 본다", async () => {
        stubFetch({
            "https://openapi.naver.com/v1/nid/me": { resultcode: "024", message: "Authentication failed" },
        });

        await expect(naverPreset.fetchProfile(TOKENS, CTX)).rejects.toThrow(/네이버 프로필 조회 실패/);
    });
});

describe("카카오 어댑터", () => {
    it("숫자 id 를 문자열 subject 로 바꾼다", async () => {
        stubFetch({
            "https://kapi.kakao.com/v2/user/me": {
                id: 1234567890,
                kakao_account: { profile: { nickname: "카카오유저" } },
            },
        });

        const profile = await kakaoPreset.fetchProfile(TOKENS, CTX);
        expect(profile.subject).toBe("1234567890");
        expect(typeof profile.subject).toBe("string");
    });

    it("is_email_valid 와 is_email_verified 가 모두 true 여야 검증으로 인정한다", async () => {
        stubFetch({
            "https://kapi.kakao.com/v2/user/me": {
                id: 1,
                kakao_account: { email: "a@kakao.com", is_email_valid: true, is_email_verified: true },
            },
        });
        expect((await kakaoPreset.fetchProfile(TOKENS, CTX)).emailVerified).toBe(true);
    });

    it("두 플래그 중 하나라도 빠지면 미검증이다", async () => {
        for (const account of [
            { email: "a@kakao.com", is_email_valid: true, is_email_verified: false },
            { email: "a@kakao.com", is_email_valid: false, is_email_verified: true },
            { email: "a@kakao.com" },
        ]) {
            stubFetch({ "https://kapi.kakao.com/v2/user/me": { id: 1, kakao_account: account } });
            expect((await kakaoPreset.fetchProfile(TOKENS, CTX)).emailVerified).toBe(false);
            vi.restoreAllMocks();
        }
    });
});

describe("suggestUsername", () => {
    it("username 규칙에 맞게 정규화한다", () => {
        expect(suggestUsername("The Octocat")).toBe("the_octocat");
        expect(suggestUsername("user.name+tag")).toBe("user_name_tag");
    });

    it("규칙을 만족시킬 수 없으면 undefined 를 돌려준다", () => {
        // 한글만 있는 닉네임은 전부 _ 로 치환된 뒤 trim 되어 빈 문자열이 된다.
        expect(suggestUsername("닉네임")).toBeUndefined();
        // 3자 미만
        expect(suggestUsername("ab")).toBeUndefined();
        expect(suggestUsername(undefined)).toBeUndefined();
    });
});
