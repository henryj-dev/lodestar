/**
 * 연합 회원가입 pending 링크 (계획서 §2.8).
 *
 * 외부 IdP 인증은 끝났지만 매칭되는 Lodestar 계정이 없을 때, 가입 폼(`/signup?federated=1`)
 * 으로 외부 프로필을 넘기기 위한 단기 서명 쿠키다.
 *
 * ── 왜 쿠키인가 (폼 hidden 필드가 아니라) ────────────────────────────────────────
 * 프리필 값을 폼으로 왕복시키면 사용자가 그 값을 **편집해서 제출할 수 있다**. 공격자가
 * 자기 소셜 계정으로 로그인한 뒤 email 을 `admin@회사.com` 으로 바꿔 제출하면 그 이메일을
 * 가진 신원을 획득한다. 즉 프리필은 편의 기능이 아니라 **신뢰 경계**다.
 *
 * 따라서 `provider` / `subject` / `emailVerified` 는 오직 이 토큰에서만 읽어야 하고,
 * 폼 입력은 사용자가 정당하게 고를 수 있는 값(username, 미검증 이메일, 비밀번호)에만 쓴다.
 *
 * 서명만 되고 암호화되지 않으므로 시크릿을 담지 않는다. 특히 LDAP 경로에서 사용자의
 * 디렉터리 비밀번호를 절대 넣지 않는다.
 */

import type { Cookies } from "@sveltejs/kit";
import { dev } from "$app/environment";
import { signPayload, verifyPayload } from "./signed-token";

export const PENDING_LINK_COOKIE = "idp_pending_link";

/** 가입 폼을 채우는 데 충분하되, 방치된 신원이 오래 살지 않을 만큼. */
const PENDING_LINK_TTL_MS = 15 * 60 * 1000;

export interface PendingLinkClaims {
    /** 발급 시점의 테넌트. 소비 시 현재 테넌트와 일치해야 한다. */
    tenantId: string;
    /** `identities.provider` 로 저장될 값 — 예: `oauth:naver`, `ldap:<providerId>`. */
    provider: string;
    /** `identities.subject` 로 저장될 외부 불변 식별자. */
    subject: string;
    /** 프로바이더 표시명. 가입 폼 안내 문구에 쓴다. */
    providerLabel: string;

    email: string | null;
    /** 프로바이더가 소유를 **단언**한 경우에만 true. 이메일 필드 잠금 여부를 결정한다. */
    emailVerified: boolean;

    displayName?: string;
    givenName?: string;
    familyName?: string;
    suggestedUsername?: string;

    /** LDAP 연합 가입은 비밀번호 설정 단계를 제공하지 않는다(인증은 디렉터리가 담당). */
    allowPassword: boolean;
    /** username 을 사용자가 고칠 수 있는지. LDAP 은 디렉터리 값 고정. */
    allowUsernameEdit: boolean;

    /** 가입 완료 후 돌아갈 내부 경로. 저장 전 sanitize 된 값만 넣는다. */
    redirectTo: string | null;
    skinHint: string | null;
}

function cookieOptions(url: URL) {
    return {
        path: "/",
        httpOnly: true,
        sameSite: "lax" as const,
        secure: !dev || url.protocol === "https:",
        maxAge: PENDING_LINK_TTL_MS / 1000,
    };
}

export async function setPendingLinkCookie(cookies: Cookies, url: URL, claims: PendingLinkClaims, signingKeySecret: string): Promise<void> {
    const token = await signPayload(claims, signingKeySecret, PENDING_LINK_TTL_MS);
    cookies.set(PENDING_LINK_COOKIE, token, cookieOptions(url));
}

/**
 * 쿠키를 읽고 검증한다 — **삭제하지 않는다.**
 *
 * 가입 폼은 검증 실패(중복 username 등)로 여러 번 다시 그려질 수 있어서, load 와 실패한
 * 액션에서 토큰이 살아 있어야 한다. 계정 생성에 성공한 시점에만 `clearPendingLinkCookie`
 * 로 명시적으로 소비한다.
 */
export async function readPendingLink(cookies: Cookies, signingKeySecret: string): Promise<PendingLinkClaims | null> {
    const token = cookies.get(PENDING_LINK_COOKIE);
    if (!token) return null;

    const claims = await verifyPayload<PendingLinkClaims>(token, signingKeySecret);
    if (!claims) return null;

    // 구조 검증 — 서명이 유효해도 형식이 어긋난 토큰(구버전 등)은 거부한다.
    if (typeof claims.tenantId !== "string" || !claims.tenantId) return null;
    if (typeof claims.provider !== "string" || !claims.provider) return null;
    if (typeof claims.subject !== "string" || !claims.subject) return null;

    return claims;
}

export function clearPendingLinkCookie(cookies: Cookies, url: URL): void {
    cookies.delete(PENDING_LINK_COOKIE, { path: "/", secure: !dev || url.protocol === "https:" });
}
