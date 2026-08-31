import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { env } from "$env/dynamic/private";
import type { DB } from "$lib/server/db";

// 이메일 인증 링크에 skinHint 가 실려야 인증 화면도 가입을 시작한 클라이언트의 스킨으로 렌더된다
// (find-password → reset-password 와 같은 방식). 링크에 없으면 verify_email 스킨은 영영 적용되지
// 않으므로, 링크 조립을 직접 확인한다.
//
// 메일 발송 함수만 갈아끼워 URL 을 가로챈다. $lib/server/email 의 나머지(generateToken 등)는 실제
// 구현을 그대로 쓴다.
const captured = vi.hoisted(() => ({ urls: [] as string[] }));

vi.mock("$lib/server/email", async (importOriginal) => {
    const actual = await importOriginal<typeof import("$lib/server/email")>();
    return {
        ...actual,
        sendEmailVerificationEmail: async (_to: string, verifyUrl: string) => {
            captured.urls.push(verifyUrl);
        },
    };
});

const { issueEmailVerification } = await import("$lib/server/auth/email-verification");

const mutEnv = env as Record<string, string | undefined>;

function makeDb() {
    return {
        insert: () => ({ values: async () => undefined }),
    } as unknown as DB;
}

beforeEach(() => {
    captured.urls.length = 0;
    mutEnv.IDP_ISSUER_URL = "https://idp.test.example";
});

afterEach(() => {
    delete mutEnv.IDP_ISSUER_URL;
    vi.restoreAllMocks();
});

describe("issueEmailVerification — 인증 링크", () => {
    it("skinHint 를 주면 링크에 함께 실린다", async () => {
        await issueEmailVerification(makeDb(), "user-1", "a@test.example", "ko", undefined, "oidc:abc-123");

        expect(captured.urls).toHaveLength(1);
        const url = new URL(captured.urls[0]);
        expect(url.origin + url.pathname).toBe("https://idp.test.example/verify-email");
        expect(url.searchParams.get("skinHint")).toBe("oidc:abc-123");
        expect(url.searchParams.get("token")).toMatch(/^[0-9a-f]{64}$/);
    });

    it("skinHint 가 없으면 token 만 실린다 (계정 화면 재발송 경로)", async () => {
        await issueEmailVerification(makeDb(), "user-1", "a@test.example", "ko", undefined);

        const url = new URL(captured.urls[0]);
        expect(url.searchParams.get("skinHint")).toBeNull();
        expect([...url.searchParams.keys()]).toEqual(["token"]);
    });

    it("빈 문자열 skinHint 는 붙이지 않는다", async () => {
        await issueEmailVerification(makeDb(), "user-1", "a@test.example", "ko", undefined, "");

        expect(new URL(captured.urls[0]).searchParams.get("skinHint")).toBeNull();
    });

    it("토큰은 URL 인코딩되어 실린다", async () => {
        await issueEmailVerification(makeDb(), "user-1", "a@test.example", "ko", undefined, "oidc:a b");

        // URLSearchParams 가 공백을 인코딩한다 — 링크가 깨지지 않아야 한다.
        expect(captured.urls[0]).toContain("skinHint=oidc%3Aa+b");
    });
});
