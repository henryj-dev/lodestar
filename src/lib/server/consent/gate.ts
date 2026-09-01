/**
 * 동의 게이트 — OIDC `/oidc/authorize` 와 SAML `/saml/sso` 가 공유한다.
 *
 * 두 프로토콜의 게이트 체인은 이미 같은 모양이다(로그인 → 재인증 → 이메일 인증 → 서비스 배정).
 * 동의도 같은 자리에 같은 방식으로 끼운다: 못 미치면 `/consent` 로 보내고, 사용자가 승인하면
 * **원래 요청 URL 로 되돌아와 체인을 처음부터 다시 통과**한다. 상태를 서버에 따로 쌓지 않아
 * (쿠키·펜딩 테이블 없음) 재시도·뒤로가기·탭 중복에 강하다.
 *
 * SAML 은 POST 바인딩이라 URL 만으로 재개할 수 없는데, 이미 로그인 왕복을 위해 동일
 * AuthnRequest 를 Redirect 바인딩으로 재인코딩한 `loginRedirectTo` 를 만들어 두므로 그것을
 * 그대로 쓴다.
 */
import { redirect } from "@sveltejs/kit";
import type { DB } from "$lib/server/db";
import { decideConsent, getActiveConsent, parseScopeList, type ConsentClientType, type ConsentDecision } from "$lib/server/consent";

/** `/consent` 가 요구하는 쿼리 파라미터 이름 — 화면과 게이트가 공유한다. */
export const CONSENT_PARAM = {
    clientType: "clientType",
    clientRefId: "clientRefId",
    redirectTo: "redirectTo",
    skinHint: "skinHint",
} as const;

export interface ConsentGateInput {
    db: DB;
    tenantId: string;
    userId: string;
    clientType: ConsentClientType;
    /** oidcClients.id 또는 samlSps.id */
    clientRefId: string;
    /** 이번 요청이 내보내려는 항목 (OIDC=스코프, SAML=허용 속성). */
    requested: readonly string[];
    /** 클라이언트가 "거부 가능" 으로 설정한 항목. */
    optional: readonly string[];
    /** `prompt=consent` 등 강제 재동의. */
    forceConsent?: boolean;
}

export interface ConsentGateResult {
    decision: ConsentDecision;
    /** 화면을 띄워야 하는가. false 면 `effectiveScopes` 로 진행한다. */
    needsConsent: boolean;
}

/** 저장된 동의를 읽어 판정한다. 리다이렉트하지 않고 결과만 돌려준다. */
export async function evaluateConsent(input: ConsentGateInput): Promise<ConsentGateResult> {
    const existing = await getActiveConsent(input.db, {
        tenantId: input.tenantId,
        userId: input.userId,
        clientType: input.clientType,
        clientRefId: input.clientRefId,
    });

    const decision = decideConsent({
        requested: input.requested,
        optional: input.optional,
        granted: parseScopeList(existing?.grantedScopes),
        forceConsent: input.forceConsent,
    });

    return { decision, needsConsent: !decision.satisfied };
}

/**
 * `/consent` 로 보낼 URL 을 만든다.
 *
 * `resumeUrl` 은 승인 후 되돌아올 곳(path+query) 이다 — 원래 요청 그대로여야 체인을 다시 통과할 수
 * 있다. 화면이 표시할 항목 목록은 URL 에 담지 않는다: 되돌아온 뒤 서버가 다시 계산하므로 여기서
 * 넘겨도 신뢰할 수 없고, 사용자가 고칠 수 있는 값을 화면 근거로 삼을 이유도 없다.
 */
export function buildConsentUrl(params: { origin: string; clientType: ConsentClientType; clientRefId: string; resumeUrl: string; skinHint?: string | null }): string {
    const url = new URL("/consent", params.origin);
    url.searchParams.set(CONSENT_PARAM.clientType, params.clientType);
    url.searchParams.set(CONSENT_PARAM.clientRefId, params.clientRefId);
    url.searchParams.set(CONSENT_PARAM.redirectTo, params.resumeUrl);
    if (params.skinHint) url.searchParams.set(CONSENT_PARAM.skinHint, params.skinHint);
    return url.toString();
}

/** 동의 화면으로 302. 게이트 호출부에서 `throw` 로 쓴다. */
export function redirectToConsent(params: Parameters<typeof buildConsentUrl>[0]): never {
    throw redirect(302, buildConsentUrl(params));
}
