import { redirect } from "@sveltejs/kit";
import type { LayoutServerLoad } from "./$types";
import { evaluateTermsGate, isTermsExemptPath, buildTermsUrl } from "$lib/server/terms/gate";
import { normalizeLocale } from "$lib/i18n/core";

/**
 * hooks.server.ts 에서 결정한 SSR 로케일을 클라이언트로 전달한다.
 * +layout.svelte 가 이 값으로 setLocale() 을 렌더 전에 적용해 하이드레이션 미스매치를 방지한다.
 *
 * 그리고 **전역 필수 약관 인터셉트(T1-A)** 가 여기 있다. 로그인 완료 지점이 다섯 개
 * (비밀번호·MFA·소셜·패스키·초대)인데 각각에 인터셉트를 심으면 하나를 빠뜨리는 순간 구멍이
 * 되므로, 모든 진입 경로가 지나가는 이 자리에서 한 번 본다. 새 약관이 발행됐을 때 기존 세션도
 * 다음 이동에서 걸린다.
 *
 * load 는 form-action POST 에서 돌지 않으므로 이것만으로는 게이트가 아니다 — 프로토콜 경로는
 * `/oidc/authorize` · `/saml/sso` 안에서 따로 판정한다(T1-B). admin ACR 게이트가 같은 이유로
 * 두 곳에 있는 것과 같은 구조다.
 */
export const load: LayoutServerLoad = async ({ locals, url }) => {
    if (locals.user && locals.db && locals.tenant && !isTermsExemptPath(url.pathname)) {
        const gate = await evaluateTermsGate({
            db: locals.db,
            tenantId: locals.tenant.id,
            userId: locals.user.id,
            locale: normalizeLocale(locals.user.locale ?? locals.locale),
        });
        if (gate.blocked) {
            throw redirect(303, buildTermsUrl({ origin: url.origin, resumeUrl: url.pathname + url.search }));
        }
    }

    return { locale: locals.locale };
};
