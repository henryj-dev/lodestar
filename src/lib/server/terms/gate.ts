/**
 * 약관 게이트 — 루트 레이아웃(브라우징)과 프로토콜 엔드포인트(SSO)가 공유한다.
 *
 * ── 왜 두 곳인가 ───────────────────────────────────────────────────────────────
 *
 * 이 저장소는 admin ACR 게이트에서 이미 같은 판단을 했다: `+layout.server.ts` 의 load 는
 * **form-action POST 에서 돌지 않으므로** 레이아웃 한 곳만으로는 게이트가 되지 않는다.
 *
 *   - 레이아웃(T1-A): 로그인 경로가 다섯 개(비밀번호·MFA·소셜·패스키·초대)인데 각 완료 지점에
 *     인터셉트를 심으면 하나를 빠뜨리는 순간 구멍이 된다. 레이아웃에서 한 번 보면 **모든 진입
 *     경로**가 덮이고, 새 약관이 발행됐을 때 기존 세션도 다음 이동에서 걸린다.
 *   - 프로토콜(T1-B): `/oidc/authorize` · `/saml/sso` 는 레이아웃을 타지 않는다. 앱별 약관은
 *     어차피 그 앱으로 SSO 할 때만 대상이므로 게이트 체인 안에서 판정한다.
 *
 * ── 예외 경로 ─────────────────────────────────────────────────────────────────
 *
 * 약관 화면 자체와 인증·로그아웃 흐름은 막지 않는다. 막으면 사용자가 약관을 볼 수도, 빠져나갈
 * 수도 없는 상태에 갇힌다.
 */
import { redirect } from "@sveltejs/kit";
import type { DB } from "$lib/server/db";
import { evaluateTerms, listApplicableTerms, type TermsClientType } from "$lib/server/terms";
import type { Locale } from "$lib/i18n/core";

/** `/terms` 가 쓰는 쿼리 파라미터 이름 — 게이트와 화면이 공유한다. */
export const TERMS_PARAM = {
    redirectTo: "redirectTo",
    clientType: "clientType",
    clientRefId: "clientRefId",
    skinHint: "skinHint",
} as const;

/**
 * 약관 인터셉트를 적용하지 않는 경로.
 *
 * `/terms` 자체(무한 왕복), 인증 흐름(로그인해야 동의도 받을 수 있다), 로그아웃(빠져나갈 길),
 * 프로토콜·API(레이아웃을 타지 않거나 JSON 을 기대한다), 정적 자산.
 */
const TERMS_EXEMPT = [
    /^\/terms(\/|$)/,
    /^\/(login|logout|signup|mfa|find-id|find-password|reset-password|verify-email|accept-invite)(\/|$)/,
    /^\/auth\//,
    /^\/oidc\//,
    /^\/saml\//,
    /^\/api\//,
    /^\/\.well-known\//,
    /^\/consent(\/|$)/,
    /^\/favicon\.ico$/,
    /^\/robots\.txt$/,
];

export function isTermsExemptPath(pathname: string): boolean {
    return TERMS_EXEMPT.some((re) => re.test(pathname));
}

export interface TermsGateInput {
    db: DB;
    tenantId: string;
    userId: string;
    locale: Locale;
    /** 지정하면 이 앱에 매핑된 약관도 대상에 넣는다(T1-B). 없으면 전역 약관만(T1-A). */
    client?: { clientType: TermsClientType; clientRefId: string };
}

/** 진행을 막는 약관이 있는지. 화면에 올릴 목록까지 함께 돌려준다. */
export async function evaluateTermsGate(input: TermsGateInput) {
    const items = await listApplicableTerms(input.db, input.tenantId, { locale: input.locale, client: input.client });
    if (items.length === 0) return { blocked: false as const, pending: [], blocking: [] };

    const state = await evaluateTerms(input.db, input.tenantId, input.userId, items);
    return { blocked: state.blocking.length > 0, pending: state.pending, blocking: state.blocking };
}

export function buildTermsUrl(params: { origin: string; resumeUrl: string; client?: { clientType: TermsClientType; clientRefId: string }; skinHint?: string | null }): string {
    const url = new URL("/terms", params.origin);
    url.searchParams.set(TERMS_PARAM.redirectTo, params.resumeUrl);
    if (params.client) {
        url.searchParams.set(TERMS_PARAM.clientType, params.client.clientType);
        url.searchParams.set(TERMS_PARAM.clientRefId, params.client.clientRefId);
    }
    if (params.skinHint) url.searchParams.set(TERMS_PARAM.skinHint, params.skinHint);
    return url.toString();
}

/** 약관 화면으로 302. 게이트 호출부에서 `throw` 로 쓴다. */
export function redirectToTerms(params: Parameters<typeof buildTermsUrl>[0]): never {
    throw redirect(302, buildTermsUrl(params));
}
