import { fail, redirect } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { requireDbContext } from "$lib/server/auth/guards";
import { sanitizeRedirectTarget } from "$lib/server/auth/redirect";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { listApplicableTerms, evaluateTerms, recordTermDecisions, renderTermsBody, type TermsClientType, type TermsItem } from "$lib/server/terms";
import { TERMS_PARAM } from "$lib/server/terms/gate";
import { escapeHtml, replacePlaceholders, resolveSkinByHint } from "$lib/server/skin/resolver";
import { translate } from "$lib/i18n/server";
import { normalizeLocale } from "$lib/i18n/core";

/**
 * 약관 동의 화면.
 *
 * 전역 약관(T1-A)과 앱별 약관(T1-B)이 같은 화면을 쓴다 — 대상 목록만 다르다. 앱 컨텍스트는
 * 쿼리로 오고, 없으면 전역 약관만 대상이 된다.
 *
 * 본문은 마크다운 부분집합을 서버에서 렌더한다. `renderTermsBody` 가 **이스케이프를 먼저 하고**
 * 서식을 얹으므로 원본 HTML 이 살아남을 수 없다 — 그래서 `{@html}` 로 넣어도 안전하다.
 */

function readTarget(url: URL): { resumeUrl: string; client?: { clientType: TermsClientType; clientRefId: string }; skinHint: string | null } {
    const resumeUrl = sanitizeRedirectTarget(url.searchParams.get(TERMS_PARAM.redirectTo)) ?? "/";
    const rawType = url.searchParams.get(TERMS_PARAM.clientType);
    const clientRefId = url.searchParams.get(TERMS_PARAM.clientRefId);
    const clientType: TermsClientType | null = rawType === "oidc" || rawType === "saml" ? rawType : null;
    const client = clientType && clientRefId ? { clientType, clientRefId } : undefined;
    return { resumeUrl, client, skinHint: url.searchParams.get(TERMS_PARAM.skinHint) };
}

async function resolveSkin(locals: App.Locals, platform: App.Platform | undefined, skinHint: string | null, flashMsg = ""): Promise<string | null> {
    if (!locals.db || !locals.tenant) return null;
    const raw = await resolveSkinByHint(locals.db, platform, locals.tenant.id, skinHint, "terms");
    if (!raw) return null;
    return replacePlaceholders(raw, {
        IDP_FORM_ACTION: "",
        IDP_REDIRECT_TO: "",
        IDP_SKIN_HINT: escapeHtml(skinHint ?? ""),
        IDP_FLASH_MSG: escapeHtml(flashMsg),
    });
}

/** 화면에 넘길 형태 — 본문은 렌더된 HTML 로 바꿔 보낸다. */
function toView(items: TermsItem[]) {
    return items.map((i) => ({
        key: i.key,
        version: i.version,
        locale: i.locale,
        title: i.title,
        bodyHtml: renderTermsBody(i.body),
        required: i.required,
    }));
}

export const load: PageServerLoad = async ({ locals, url, platform }) => {
    if (!locals.user) {
        throw redirect(303, `/login?redirectTo=${encodeURIComponent(url.pathname + url.search)}`);
    }
    const { db, tenant } = requireDbContext(locals);
    const target = readTarget(url);
    const locale = normalizeLocale(locals.user.locale ?? locals.locale);

    const items = await listApplicableTerms(db, tenant.id, { locale, client: target.client });
    const state = await evaluateTerms(db, tenant.id, locals.user.id, items);

    // 물어볼 것이 없으면 되돌려보낸다 — 화면에 직접 들어온 경우 포함.
    if (state.pending.length === 0) throw redirect(303, target.resumeUrl);

    return {
        terms: toView(state.pending),
        redirectTo: target.resumeUrl,
        skinHint: target.skinHint,
        skinHtml: await resolveSkin(locals, platform, target.skinHint),
    };
};

export const actions: Actions = {
    default: async (event) => {
        const { locals, url, request, platform } = event;
        if (!locals.user) throw redirect(303, "/login");
        const { db, tenant } = requireDbContext(locals);
        const locale = locals.locale;
        const userLocale = normalizeLocale(locals.user.locale ?? locals.locale);
        const target = readTarget(url);

        // 대상 목록은 서버에서 다시 계산한다 — 제출된 값만 믿고 기록하면 아직 발행되지 않은 항목이나
        // 다른 앱의 약관에 동의한 것으로 만들 수 있다.
        const items = await listApplicableTerms(db, tenant.id, { locale: userLocale, client: target.client });
        const state = await evaluateTerms(db, tenant.id, locals.user.id, items);
        if (state.pending.length === 0) throw redirect(303, target.resumeUrl);

        const formData = await request.formData();
        const checked = new Set(formData.getAll("termsKey").map(String));

        // 필수 항목이 하나라도 빠지면 기록하지 않고 오류로 되돌린다.
        const missingRequired = state.pending.filter((i) => i.required && !checked.has(i.key));
        if (missingRequired.length > 0) {
            return fail(400, {
                error: translate(locale, "terms.err_required_missing"),
                skinHtml: await resolveSkin(locals, platform, target.skinHint, translate(locale, "terms.err_required_missing")),
            });
        }

        await recordTermDecisions(
            db,
            tenant.id,
            locals.user.id,
            state.pending.map((i) => ({ key: i.key, version: i.version, locale: i.locale, agreed: checked.has(i.key) })),
        );

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: locals.user.id,
            actorId: locals.user.id,
            spOrClientId: target.client?.clientRefId ?? null,
            kind: "terms_agreed",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: {
                agreed: state.pending.filter((i) => checked.has(i.key)).map((i) => `${i.key}@${i.version}`),
                declined: state.pending.filter((i) => !checked.has(i.key)).map((i) => `${i.key}@${i.version}`),
            },
        });

        throw redirect(303, target.resumeUrl);
    },
};
