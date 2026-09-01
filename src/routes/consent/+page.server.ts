import { fail, redirect } from "@sveltejs/kit";
import { and, eq } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireDbContext } from "$lib/server/auth/guards";
import { sanitizeRedirectTarget } from "$lib/server/auth/redirect";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { getActiveConsent, parseScopeList, recordConsent, type ConsentClientType } from "$lib/server/consent";
import { CONSENT_PARAM } from "$lib/server/consent/gate";
import { decideConsent } from "$lib/server/consent";
import { oidcClients, samlSps } from "$lib/server/db/schema";
import { escapeHtml, replacePlaceholders, resolveSkinByHint } from "$lib/server/skin/resolver";
import { translate } from "$lib/i18n/server";
import type { DB } from "$lib/server/db";

/**
 * 첫 사용 동의 화면.
 *
 * 게이트(`/oidc/authorize`, `/saml/sso`)가 못 미칠 때 여기로 보내고, 승인하면 **원래 요청 URL 로
 * 되돌려보내** 체인을 처음부터 다시 통과시킨다. 서버에 펜딩 상태를 쌓지 않으므로 재시도·뒤로가기·
 * 탭 중복에 강하다.
 *
 * 표시할 항목은 URL 에서 받지 않고 **여기서 다시 계산한다.** 사용자가 고칠 수 있는 값을 화면의
 * 근거로 삼을 수 없기 때문이다. `redirectTo` 는 원래 요청 그대로이므로 그 안의 scope 를 읽어
 * 클라이언트 등록 범위와 교차시킨다.
 */

interface ClientInfo {
    name: string;
    /** 이 요청이 내보내려는 항목. OIDC=요청 스코프 ∩ 등록 스코프, SAML=SP 의 허용 속성. */
    requested: string[];
    /** 거부 가능 항목. */
    optional: string[];
}

/** SAML SP 가 allowedAttributes 를 지정하지 않았을 때 실제로 나가는 기본 속성. */
const SAML_DEFAULT_ATTRIBUTES = ["email", "username", "displayName"];

async function loadClientInfo(db: DB, tenantId: string, clientType: ConsentClientType, clientRefId: string, resumeUrl: string): Promise<ClientInfo | null> {
    if (clientType === "oidc") {
        const [client] = await db
            .select({ name: oidcClients.name, scopes: oidcClients.scopes, optionalScopes: oidcClients.optionalScopes })
            .from(oidcClients)
            .where(and(eq(oidcClients.tenantId, tenantId), eq(oidcClients.id, clientRefId), eq(oidcClients.enabled, true)))
            .limit(1);
        if (!client) return null;

        // 원래 요청의 scope 를 읽어 등록 범위와 교차한다(요청을 그대로 믿지 않는다).
        let requestedScope: string;
        try {
            requestedScope = new URL(resumeUrl, "https://placeholder.invalid").searchParams.get("scope") ?? "";
        } catch {
            requestedScope = "";
        }
        const allowed = parseScopeList(client.scopes);
        const requested = parseScopeList(requestedScope).filter((s) => allowed.includes(s));
        const optionalSet = parseScopeList(client.optionalScopes);
        return { name: client.name, requested, optional: requested.filter((s) => optionalSet.includes(s)) };
    }

    const [sp] = await db
        .select({ name: samlSps.name, allowedAttributes: samlSps.allowedAttributes })
        .from(samlSps)
        .where(and(eq(samlSps.tenantId, tenantId), eq(samlSps.id, clientRefId), eq(samlSps.enabled, true)))
        .limit(1);
    if (!sp) return null;

    // SAML 은 스코프가 없다 — SP 에 실제로 나가는 속성 목록이 동의 대상이다.
    let attributes: string[] = SAML_DEFAULT_ATTRIBUTES;
    if (sp.allowedAttributes) {
        try {
            const parsed = JSON.parse(sp.allowedAttributes) as unknown;
            if (Array.isArray(parsed)) attributes = parsed.filter((a): a is string => typeof a === "string");
        } catch {
            // 깨진 값은 기본 속성으로 취급 — 조용히 넓히지 않는다.
        }
    }
    // SAML 에는 "선택 속성" 개념이 없다(SP 가 요구하는 것을 부분 제공하면 SP 가 깨진다).
    return { name: sp.name, requested: attributes, optional: [] };
}

/**
 * 동의 대상을 읽는다. **URL 우선, 폼 본문 보조.**
 *
 * URL 을 우선하는 이유: 화면에 보여준 대상과 기록되는 동의가 같은 출처에서 나와야
 * 어긋날 수 없다. 폼 본문을 보조로 두는 이유: 폼 액션이 쿼리스트링을 잃는 실수 하나로
 * 전체 흐름이 조용히 `/` 로 새기 때문이다(승인은 되는데 서비스로 돌아가지 못한다).
 * 어느 쪽에서 읽든 `resumeUrl` 은 sanitize 를 통과해야 하고, 승인 범위는 그 URL 이
 * 요청한 scope 로 한정되므로 보조 경로가 권한을 넓히지는 못한다.
 */
function readTarget(url: URL, form?: FormData): { clientType: ConsentClientType; clientRefId: string; resumeUrl: string; skinHint: string | null } | null {
    const pick = (key: string): string | null => url.searchParams.get(key) ?? (form ? (form.get(key) as string | null) : null);

    const clientType = pick(CONSENT_PARAM.clientType);
    const clientRefId = pick(CONSENT_PARAM.clientRefId);
    const resumeUrl = sanitizeRedirectTarget(pick(CONSENT_PARAM.redirectTo));
    if ((clientType !== "oidc" && clientType !== "saml") || !clientRefId || !resumeUrl) return null;
    return { clientType, clientRefId, resumeUrl, skinHint: pick(CONSENT_PARAM.skinHint) };
}

async function resolveSkin(
    locals: App.Locals,
    platform: App.Platform | undefined,
    skinHint: string | null,
    vars: { clientName: string; required: string[]; optional: string[]; flashMsg?: string },
): Promise<string | null> {
    if (!locals.db || !locals.tenant) return null;
    const raw = await resolveSkinByHint(locals.db, platform, locals.tenant.id, skinHint, "consent");
    if (!raw) return null;
    return replacePlaceholders(raw, {
        IDP_FORM_ACTION: "",
        IDP_REDIRECT_TO: "",
        IDP_SKIN_HINT: escapeHtml(skinHint ?? ""),
        IDP_CLIENT_NAME: escapeHtml(vars.clientName),
        IDP_REQUIRED_SCOPES: escapeHtml(vars.required.join(" ")),
        IDP_OPTIONAL_SCOPES: escapeHtml(vars.optional.join(" ")),
        IDP_FLASH_MSG: escapeHtml(vars.flashMsg ?? ""),
    });
}

export const load: PageServerLoad = async ({ locals, url, platform }) => {
    if (!locals.user) {
        // 로그인 후 이 화면으로 되돌아오게 한다(쿼리 포함).
        throw redirect(303, `/login?redirectTo=${encodeURIComponent(url.pathname + url.search)}`);
    }
    const { db, tenant } = requireDbContext(locals);

    const target = readTarget(url);
    if (!target) throw redirect(303, "/");

    const info = await loadClientInfo(db, tenant.id, target.clientType, target.clientRefId, target.resumeUrl);
    if (!info) throw redirect(303, "/");

    const existing = await getActiveConsent(db, {
        tenantId: tenant.id,
        userId: locals.user.id,
        clientType: target.clientType,
        clientRefId: target.clientRefId,
    });
    const decision = decideConsent({
        requested: info.requested,
        optional: info.optional,
        granted: parseScopeList(existing?.grantedScopes),
        // 화면에 직접 들어온 경우에도 필요 여부를 다시 판정한다. 이미 충족이면 되돌려보낸다.
        forceConsent: false,
    });

    if (decision.satisfied) throw redirect(303, target.resumeUrl);

    return {
        clientName: info.name,
        clientType: target.clientType,
        clientRefId: target.clientRefId,
        redirectTo: target.resumeUrl,
        skinHint: target.skinHint,
        // C3-A: 새로 묻는 것과 이미 승인된 것을 나눠 넘긴다.
        requiredScopes: decision.required,
        optionalScopes: decision.optional,
        newlyRequested: decision.newlyRequested,
        alreadyGranted: decision.alreadyGranted,
        isReconsent: decision.alreadyGranted.length > 0,
        skinHtml: await resolveSkin(locals, platform, target.skinHint, { clientName: info.name, required: decision.required, optional: decision.optional }),
    };
};

export const actions: Actions = {
    /** 승인 — 필수 전체 + 사용자가 체크한 선택 항목을 기록하고 원래 요청으로 되돌아간다. */
    approve: async (event) => {
        const { locals, url, request, platform } = event;
        if (!locals.user) throw redirect(303, "/login");
        const { db, tenant } = requireDbContext(locals);
        const locale = locals.locale;

        // 폼을 먼저 읽는다 — 쿼리스트링이 없을 때 대상을 본문에서 찾기 위해서다.
        const formData = await request.formData();
        const target = readTarget(url, formData);
        if (!target) throw redirect(303, "/");

        const info = await loadClientInfo(db, tenant.id, target.clientType, target.clientRefId, target.resumeUrl);
        if (!info) throw redirect(303, "/");

        const checkedOptional = formData.getAll("optionalScope").map(String);

        const consentTarget = { tenantId: tenant.id, userId: locals.user.id, clientType: target.clientType, clientRefId: target.clientRefId };
        const existing = await getActiveConsent(db, consentTarget);
        const previouslyGranted = parseScopeList(existing?.grantedScopes);

        const required = info.requested.filter((s) => !info.optional.includes(s));
        const approvedOptional = info.optional.filter((s) => checkedOptional.includes(s));
        const presented = new Set([...required, ...info.optional]);

        // 이번 화면에 오른 항목은 사용자의 결정을 따르고, 오르지 않은 기존 승인은 유지한다.
        // (이렇게 하지 않으면 좁은 범위를 요청한 다음 요청에서 기존 동의가 깎여 재동의가 반복된다.)
        const approved = [...previouslyGranted.filter((s) => !presented.has(s)), ...required, ...approvedOptional];

        if (required.length === 0 && approvedOptional.length === 0 && previouslyGranted.length === 0) {
            return fail(400, { error: translate(locale, "consent.err_nothing_to_grant") });
        }

        await recordConsent(db, consentTarget, approved);

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: locals.user.id,
            spOrClientId: target.clientRefId,
            kind: "consent_granted",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { clientType: target.clientType, granted: approved, declinedOptional: info.optional.filter((s) => !checkedOptional.includes(s)) },
        });

        void platform; // 스킨 캐시 무효화 대상 없음 — 시그니처 일관성 유지용.
        throw redirect(303, target.resumeUrl);
    },

    /**
     * 거부 — 원래 요청으로 되돌아가되 `consent=denied` 를 실어 보낸다.
     *
     * 프로토콜 오류 응답(OIDC `access_denied`, SAML `RequestDenied`)은 게이트가 만든다.
     * redirect_uri / ACS URL 검증이 이미 그쪽에 있으므로 검증을 두 곳에 두지 않는다.
     */
    deny: async (event) => {
        const { locals, url, request } = event;
        if (!locals.user) throw redirect(303, "/login");
        const { db, tenant } = requireDbContext(locals);

        const target = readTarget(url, await request.formData());
        if (!target) throw redirect(303, "/");

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: locals.user.id,
            spOrClientId: target.clientRefId,
            kind: "consent_denied",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { clientType: target.clientType },
        });

        const separator = target.resumeUrl.includes("?") ? "&" : "?";
        throw redirect(303, `${target.resumeUrl}${separator}consent=denied`);
    },
};
