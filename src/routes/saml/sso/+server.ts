/**
 * SAML 2.0 SSO 엔드포인트.
 *
 * 지원 흐름:
 *   1. SP-initiated / HTTP-Redirect 바인딩
 *      GET /saml/sso?SAMLRequest=<base64(deflate(XML))>&RelayState=...&SigAlg=...&Signature=...
 *   2. SP-initiated / HTTP-POST 바인딩
 *      POST /saml/sso  (body: SAMLRequest=<base64(XML)>, RelayState=...)
 *   3. IdP-initiated (unsolicited)
 *      GET /saml/sso?sp=<entityId>[&RelayState=...]  (SAMLRequest 없음)
 *
 * 공통 처리: AuthnRequest 파싱 → 로그인 확인 → 서비스 권한 게이트 → SAML Response 생성 →
 *            ACS 로 HTTP-POST auto-submit 폼 전송.
 */

import { error, redirect } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { and, eq, gt } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import type { Session, Tenant, User } from "$lib/server/db/schema";
import { requireDbContext } from "$lib/server/auth/guards";
import { getRuntimeConfig } from "$lib/server/auth/runtime";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit";
import { checkRateLimit } from "$lib/server/ratelimit";
import { getActiveSigningKey } from "$lib/server/crypto/keys";
import { acrMeetsMfa, acrSatisfies } from "$lib/server/auth/constants";
import { sessionAuthTime } from "$lib/server/auth/session";
import { hasTotpCredential } from "$lib/server/auth/users";
import { samlAuthnRequestIds } from "$lib/server/db/schema";
import type { ParsedAuthnRequest } from "$lib/server/saml/parse-authn-request";
import { parseAuthnRequest, parseAuthnRequestPost, verifySamlRedirectSignature, encodeRedirectBindingSamlRequest } from "$lib/server/saml/parse-authn-request";
import { verifyEnvelopedXmlSignature } from "$lib/server/saml/verify-xml-signature";
import { buildSignedSamlErrorResponse, buildSignedSamlResponse } from "$lib/server/saml/response";
import { findSp, recordSamlSession, type SamlSpRecord } from "$lib/server/saml/sp";
import { getUserMembership } from "$lib/server/org/membership";
import { getActiveAssignment, listActiveEntitlements, parseAssignmentAttributes } from "$lib/server/access/service-permissions";
import { evaluateConsent, redirectToConsent } from "$lib/server/consent/gate";
import { evaluateTermsGate, redirectToTerms } from "$lib/server/terms/gate";
import { normalizeLocale } from "$lib/i18n/core";
import { renderPageShell } from "$lib/server/html/page-shell";
import { translate } from "$lib/i18n/server";
import type { Locale } from "$lib/i18n/core";

// attributesJson(관리 화면 자유 입력)이 덮어쓰면 안 되는 SAML 속성.
// Role/RoleLabel/Entitlements 는 SP 가 인가 판정에 쓰는 값이라, 자유 입력으로 위조할 수 있으면
// 권한 모델 자체가 무의미해진다. OIDC 의 RESERVED_ID_TOKEN_CLAIMS 와 같은 목적이다.
const RESERVED_SAML_ATTRS = new Set(["Role", "RoleLabel", "Entitlements"]);

const SAML_AUTHN_REQUEST_TTL_MS = 10 * 60 * 1000; // 10분

function htmlEscape(s: string): string {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/**
 * ACS 로 SAMLResponse 를 실어 보내는 HTTP-POST auto-submit 폼 응답.
 *
 * 정상 흐름에서는 onload 가 즉시 제출해 한순간만 보이지만, 그 한순간도 기본 UI 와 같은 카드로
 * 보이도록 renderPageShell 을 쓴다(로그인 화면 바로 다음에 오는 화면이다).
 *
 * JS 가 꺼진 브라우저에서는 auto-submit 이 동작하지 않는데, 기존에는 화면에 아무것도 없어서 SSO
 * 가 그대로 멈췄다. `<noscript>` 로 수동 제출 버튼을 노출해 사용자가 흐름을 이어갈 수 있게 한다.
 */
function renderAutoSubmitForm(acsUrl: string, samlResponseB64: string, relayState: string | null, locale: Locale): Response {
    const relayStateInput = relayState ? `<input type="hidden" name="RelayState" value="${htmlEscape(relayState)}">` : "";
    const t = (key: string) => htmlEscape(translate(locale, key));
    const html = renderPageShell({
        lang: htmlEscape(locale),
        title: t("saml.sso_progress.title"),
        bodyAttributes: `onload="document.getElementById('samlForm').submit()"`,
        body:
            `<div class="card">` +
            `<h1>${t("saml.sso_progress.title")}</h1>` +
            `<p class="status" role="status"><span class="spinner" aria-hidden="true"></span>` +
            `<span>${t("saml.sso_progress.subtitle")}</span></p>` +
            `<form id="samlForm" method="POST" action="${htmlEscape(acsUrl)}">` +
            `<input type="hidden" name="SAMLResponse" value="${samlResponseB64}">${relayStateInput}` +
            `<noscript><div class="actions">` +
            `<button class="btn btn-primary" type="submit">${t("saml.sso_progress.manual_submit")}</button>` +
            `</div></noscript>` +
            `</form></div>`,
    });
    // 서명된 assertion 이 실린 HTML 이므로 캐시에 남기지 않는다.
    return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", Pragma: "no-cache" } });
}

/**
 * 이 SP 에 실제로 나가는 속성 목록 — 동의 대상이다.
 *
 * allowedAttributes 가 없으면 email/username/displayName 만 나가므로(README 의 per-SP 속성 필터)
 * 그 기본값을 쓴다. 깨진 JSON 은 조용히 넓히지 않고 기본값으로 취급한다.
 */
function resolveConsentAttributes(sp: SamlSpRecord): string[] {
    const DEFAULTS = ["email", "username", "displayName"];
    if (!sp.allowedAttributes) return DEFAULTS;
    try {
        const parsed = JSON.parse(sp.allowedAttributes) as unknown;
        if (Array.isArray(parsed)) {
            const names = parsed.filter((a): a is string => typeof a === "string");
            return names.length > 0 ? names : DEFAULTS;
        }
    } catch {
        // 무시 — 기본값
    }
    return DEFAULTS;
}

/** 서명된 SAML 오류 Response 를 만들어 ACS 로 POST 하는 폼 응답. */
async function buildAndRenderSamlError(params: {
    inResponseTo: string | null;
    acsUrl: string;
    issuerUrl: string;
    subStatusCode: string;
    certPem: string;
    privateKey: CryptoKey;
    relayState: string | null;
    locale: Locale;
}): Promise<Response> {
    const errorB64 = await buildSignedSamlErrorResponse({
        inResponseTo: params.inResponseTo ?? "",
        acsUrl: params.acsUrl,
        issuerUrl: params.issuerUrl,
        subStatusCode: params.subStatusCode,
        certPem: params.certPem,
        privateKey: params.privateKey,
    });
    return renderAutoSubmitForm(params.acsUrl, errorB64, params.relayState, params.locale);
}

interface GateAndIssueParams {
    db: DB;
    tenant: Tenant;
    issuerUrl: string;
    sp: SamlSpRecord;
    user: User;
    session: Session;
    acsUrl: string;
    /** SP-initiated 면 AuthnRequest ID, IdP-initiated(unsolicited) 면 null. */
    inResponseTo: string | null;
    relayState: string | null;
    certPem: string;
    privateKey: CryptoKey;
    /**
     * 동의 화면에서 승인 후 되돌아올 곳(path+query). SP-initiated 는 로그인 왕복용으로 이미
     * 만들어 둔 loginRedirectTo(POST 바인딩은 Redirect 바인딩으로 재인코딩한 URL)를 그대로 쓰고,
     * IdP-initiated 는 현재 URL 이 곧 재개 지점이다.
     */
    consentResumeUrl: string;
}

/**
 * 공통 후반부: 서비스 권한 게이트 → (SP-initiated 한정) replay ID 소비 → attribute 매핑 →
 * NameID 결정 → SAML 세션 기록 → Response 서명/암호화 → ACS POST 폼 렌더.
 *
 * SP-initiated / IdP-initiated 세 흐름이 모두 재사용한다. inResponseTo 가 있으면 그 값을
 * Response 의 InResponseTo 로 채우고 replay ID 를 소비하며, null 이면 unsolicited 로 처리한다.
 *
 * replay ID 소비는 "Assertion 발급 직전"에 수행한다 — 로그인/forceAuthn 재진입으로 동일
 * AuthnRequest 가 되돌아오는 정상 흐름을 깨지 않으면서도, 하나의 AuthnRequest 로 두 번
 * Assertion 이 발급되는 것을 막는다.
 */
async function gateAndIssueSamlAssertion(event: Parameters<RequestHandler>[0], p: GateAndIssueParams): Promise<Response> {
    const { db, tenant, sp, user, session } = p;

    // 서비스 권한 게이트 (기본 deny). 매핑 없으면 SSO 거부.
    // 단, allowAllUsers SP 는 매핑 없이도 테넌트의 모든 사용자를 허용한다
    // (assignment 는 role/추가 attribute 부여용으로만 사용).
    const spAssignment = await getActiveAssignment(db, {
        tenantId: tenant.id,
        userId: user.id,
        serviceType: "saml",
        serviceRefId: sp.id,
    });
    if (!spAssignment && !sp.allowAllUsers) {
        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: user.id,
            actorId: user.id,
            spOrClientId: sp.entityId,
            kind: "saml_sso",
            outcome: "failure",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { error: "access_denied", reason: "no_service_assignment" },
        });
        throw error(403, translate(event.locals.locale, "saml.errors.access_denied"));
    }

    // ctrls R6: SP 가 이메일 인증을 요구하면(requireVerifiedEmail) 미인증 사용자를 거부한다.
    if (sp.requireVerifiedEmail && !user.emailVerifiedAt) {
        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: user.id,
            actorId: user.id,
            spOrClientId: sp.entityId,
            kind: "saml_sso",
            outcome: "failure",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { error: "access_denied", reason: "email_verification_required" },
        });
        throw error(403, translate(event.locals.locale, "saml.errors.email_verification_required"));
    }

    // ── 약관 (T1-B) ───────────────────────────────────────────────────────────
    // 동의보다 앞에 둔다(이용 조건 → 정보 제공 범위). SAML 에는 prompt 개념이 없으므로
    // 막히면 그냥 약관 화면으로 보내고, 동의 후 loginRedirectTo 로 재개한다.
    {
        const termsGate = await evaluateTermsGate({
            db,
            tenantId: tenant.id,
            userId: user.id,
            locale: normalizeLocale(user.locale ?? event.locals.locale),
            client: { clientType: "saml", clientRefId: sp.id },
        });
        if (termsGate.blocked) {
            redirectToTerms({
                origin: event.url.origin,
                resumeUrl: p.consentResumeUrl,
                client: { clientType: "saml", clientRefId: sp.id },
                skinHint: `saml:${sp.id}`,
            });
        }
    }

    // ── 첫 사용 동의 (C5-B: SAML 도 대상) ──────────────────────────────────────
    //
    // SAML 에는 스코프가 없다 — SP 에 실제로 나가는 속성 목록(allowedAttributes, 미지정 시 기본
    // 3종)이 동의 대상이다. SP 가 속성을 추가하면 늘어난 항목 때문에 다시 묻는다.
    //
    // SAML 에는 `prompt` 개념이 없어 강제 재동의 수단은 사용자의 철회뿐이다. 부분 제공도 두지
    // 않는다 — SP 가 요구하는 속성을 골라 빼면 SP 쪽이 깨지기 때문이다(선택 항목 없음).
    {
        const attributes = resolveConsentAttributes(sp);
        if (event.url.searchParams.get("consent") === "denied") {
            const meta = getRequestMetadata(event);
            await recordAuditEvent(db, {
                tenantId: tenant.id,
                userId: user.id,
                actorId: user.id,
                spOrClientId: sp.entityId,
                kind: "saml_sso",
                outcome: "failure",
                ip: meta.ip,
                userAgent: meta.userAgent,
                detail: { error: "access_denied", reason: "consent_denied" },
            });
            return await buildAndRenderSamlError({
                inResponseTo: p.inResponseTo,
                acsUrl: p.acsUrl,
                issuerUrl: p.issuerUrl,
                subStatusCode: "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
                certPem: p.certPem,
                privateKey: p.privateKey,
                relayState: p.relayState,
                locale: event.locals.locale,
            });
        }

        const consent = await evaluateConsent({
            db,
            tenantId: tenant.id,
            userId: user.id,
            clientType: "saml",
            clientRefId: sp.id,
            requested: attributes,
            optional: [],
        });
        if (consent.needsConsent) {
            redirectToConsent({
                origin: event.url.origin,
                clientType: "saml",
                clientRefId: sp.id,
                resumeUrl: p.consentResumeUrl,
                skinHint: `saml:${sp.id}`,
            });
        }
    }

    // Replay 가드 (SP-initiated 한정). Assertion 발급 직전에 동일 AuthnRequest ID 의
    // 재사용 여부를 확인 후 INSERT. unsolicited(inResponseTo=null)는 대응 요청이 없어 생략.
    if (p.inResponseTo) {
        const now = new Date();
        const [seen] = await db
            .select({ requestId: samlAuthnRequestIds.requestId })
            .from(samlAuthnRequestIds)
            .where(and(eq(samlAuthnRequestIds.tenantId, tenant.id), eq(samlAuthnRequestIds.requestId, p.inResponseTo), gt(samlAuthnRequestIds.expiresAt, now)))
            .limit(1);
        if (seen) {
            throw error(400, translate(event.locals.locale, "saml.errors.authn_request_replay"));
        }
        try {
            await db.insert(samlAuthnRequestIds).values({
                tenantId: tenant.id,
                requestId: p.inResponseTo,
                spEntityId: sp.entityId,
                expiresAt: new Date(Date.now() + SAML_AUTHN_REQUEST_TTL_MS),
            });
        } catch {
            // unique constraint 충돌 → replay 와 동일하게 거부
            throw error(400, translate(event.locals.locale, "saml.errors.authn_request_replay"));
        }
    }

    // Attribute 매핑 (attributeMappingJson 또는 기본값)
    type AttributeMap = Record<string, string>;
    let attrMapping: AttributeMap = {};
    if (sp.attributeMappingJson) {
        try {
            attrMapping = JSON.parse(sp.attributeMappingJson) as AttributeMap;
        } catch {
            /* 기본 매핑 사용 */
        }
    }

    // SP 별 허용 속성 목록. NULL → 기본 최소 집합. 명시된 경우만 조직정보 등이 포함된다.
    const DEFAULT_ALLOWED = ["email", "username", "displayName"] as const;
    let allowedSet: Set<string>;
    if (sp.allowedAttributes) {
        try {
            const parsed = JSON.parse(sp.allowedAttributes) as unknown;
            allowedSet = new Set(Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === "string") : DEFAULT_ALLOWED);
        } catch {
            allowedSet = new Set(DEFAULT_ALLOWED);
        }
    } else {
        allowedSet = new Set(DEFAULT_ALLOWED);
    }

    const attributes: Record<string, string | string[]> = {};
    const setAttr = (key: string, value: string | null | undefined) => {
        if (!value) return;
        if (!allowedSet.has(key)) return;
        attributes[attrMapping[key] ?? key] = value;
    };

    setAttr("email", user.email);
    setAttr("username", user.username);
    setAttr("displayName", user.displayName);
    setAttr("givenName", user.givenName);
    setAttr("familyName", user.familyName);
    setAttr("surName", user.familyName);
    setAttr("phoneNumber", user.phoneNumber);

    // 서비스 role / 추가 attributes — allowedSet 검사를 동일하게 적용.
    // allowAllUsers 경로에서는 assignment 가 없을 수 있다 → role/추가 attribute 생략.
    if (spAssignment?.role) {
        setAttr("Role", spAssignment.role.key);
        setAttr("RoleLabel", spAssignment.role.label);
    }
    // 권한(entitlement) — OIDC 의 `entitlements` 클레임과 같은 값이다.
    //
    // 이름은 `Entitlements`(PascalCase) 로 둔다. 이 파일의 다른 서비스 속성(`Role`/`RoleLabel`)이
    // 그 관례를 쓰고 있고, SAML SP 는 OIDC 클레임이 아니라 이 표기를 기대한다.
    // 목록이므로 **하나의 Attribute 에 여러 AttributeValue** 로 나간다(SAML 표준 표현).
    //
    // 다른 속성과 같이 allowedSet 게이트를 받는다 — SP 가 명시적으로 허용해야 나간다.
    // 그리고 attributesJson 머지 **앞**에 둔다: 뒤에 두면 대입 순서가 우연히 보호해 주는 상태가
    // 되어, 나중에 이 줄을 옮긴 사람이 위조 경로를 되살릴 수 있다(OIDC 쪽과 같은 이유).
    if (spAssignment) {
        const entitlements = await listActiveEntitlements(db, spAssignment, tenant.id);
        if (entitlements.length > 0 && allowedSet.has("Entitlements")) {
            attributes[attrMapping["Entitlements"] ?? "Entitlements"] = entitlements;
        }
    }

    const extraAttrs = spAssignment ? parseAssignmentAttributes(spAssignment.attributesJson) : {};
    for (const [k, v] of Object.entries(extraAttrs)) {
        // 예약: 인가 판정에 쓰이는 속성은 자유 입력으로 덮어쓸 수 없다(OIDC 예약 클레임과 같은 이유).
        if (RESERVED_SAML_ATTRS.has(k)) continue;
        if (typeof v === "string") {
            setAttr(k, v);
        } else if (v != null) {
            setAttr(k, String(v));
        }
    }

    // 조직 정보는 SP 가 명시적으로 허용한 경우에만 포함한다.
    const wantsOrg = allowedSet.has("department") || allowedSet.has("team") || allowedSet.has("jobTitle") || allowedSet.has("position");
    if (wantsOrg) {
        const membership = await getUserMembership(db, user.id);
        const primaryDept = membership.departments.find((d) => d.isPrimary) ?? membership.departments[0];
        const primaryTeam = membership.teams.find((t) => t.isPrimary) ?? membership.teams[0];
        if (primaryDept) {
            setAttr("department", primaryDept.name);
            setAttr("jobTitle", primaryDept.jobTitle);
            if (primaryDept.position) setAttr("position", primaryDept.position.name);
        }
        if (primaryTeam) {
            setAttr("team", primaryTeam.name);
        }
    }

    // NameID 결정
    const nameIdFormat = sp.nameIdFormat;
    const nameId = nameIdFormat === "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" ? user.id : (user.email ?? user.id);

    const sessionIndex = `_si${crypto.randomUUID().replace(/-/g, "")}`;

    await recordSamlSession(db, {
        tenantId: tenant.id,
        spId: sp.id,
        userId: user.id,
        sessionId: session.id,
        sessionIndex,
        nameId,
        nameIdFormat,
    });

    const samlResponseB64 = await buildSignedSamlResponse({
        inResponseTo: p.inResponseTo, // null 이면 unsolicited — InResponseTo 생략
        acsUrl: p.acsUrl,
        issuerUrl: p.issuerUrl,
        spEntityId: sp.entityId,
        authnContextClassRef: session.acr ?? undefined,
        // 실제 인증 시각. 발급 시각을 넣으면 오래된 세션도 방금 인증한 것처럼 보여
        // SP 가 AuthnInstant 신선도로 아무것도 판단할 수 없다. MFA step-up 으로 승격된
        // 세션은 이 값이 갱신되므로 재인증을 실제로 했는지가 SP 에 정직하게 드러난다.
        authnInstant: sessionAuthTime(session),
        nameId,
        nameIdFormat,
        sessionIndex,
        attributes,
        certPem: p.certPem,
        privateKey: p.privateKey,
        signResponse: sp.signResponse,
        encryptAssertion: sp.encryptAssertion,
        spCertPem: sp.cert,
    });

    const requestMetadata = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId: user.id,
        actorId: user.id,
        spOrClientId: sp.entityId,
        kind: "saml_sso",
        outcome: "success",
        ip: requestMetadata.ip,
        userAgent: requestMetadata.userAgent,
        detail: { spEntityId: sp.entityId, nameId, initiatedBy: p.inResponseTo ? "sp" : "idp" },
    });

    return renderAutoSubmitForm(p.acsUrl, samlResponseB64, p.relayState, event.locals.locale);
}

interface ProcessAuthnRequestParams {
    db: DB;
    tenant: Tenant;
    issuerUrl: string;
    sp: SamlSpRecord;
    authnRequest: ParsedAuthnRequest;
    acsUrl: string;
    certPem: string;
    privateKey: CryptoKey;
    /**
     * 미로그인/재인증 시 /login 으로 넘길 redirectTo (path+query). Redirect 바인딩은 현재
     * URL 그대로, POST 바인딩은 동일 AuthnRequest 를 Redirect 바인딩으로 재인코딩한 resume URL.
     */
    loginRedirectTo: string;
}

/**
 * 재인증이 필요할 때 사용자를 보낼 곳. SP 의 `reauthPolicy` 가 결정한다.
 *
 * - `full`(기본): `/login?forceAuthn=true` — 1차 인증부터 다시 받는다.
 * - `mfa_only`: `/mfa?stepUp=mfa` — 세션을 유지한 채 OTP 만 받아 세션 ACR/AMR 을 승격한다.
 *
 * 승격이 불가능한 경우(TOTP 미등록, 서명키 부재 등)는 `/mfa` 가 스스로
 * `/login?forceAuthn=true` 로 되돌리므로, 이 함수에서 사용자 크레덴셜을 조회하지 않는다.
 */
function buildSamlReauthUrl(url: URL, sp: SamlSpRecord, loginRedirectTo: string): string {
    if (sp.reauthPolicy === "mfa_only") {
        const stepUpUrl = new URL("/mfa", url);
        stepUpUrl.searchParams.set("stepUp", "mfa");
        stepUpUrl.searchParams.set("redirectTo", loginRedirectTo);
        stepUpUrl.searchParams.set("skinHint", `saml:${sp.id}`);
        return stepUpUrl.toString();
    }
    const loginUrl = new URL("/login", url);
    loginUrl.searchParams.set("redirectTo", loginRedirectTo);
    loginUrl.searchParams.set("skinHint", `saml:${sp.id}`);
    loginUrl.searchParams.set("forceAuthn", "true");
    return loginUrl.toString();
}

/**
 * SP-initiated AuthnRequest 공통 처리부 (Redirect / POST 바인딩 공유).
 * isPassive → 로그인 → forceAuthn → RequestedAuthnContext(ACR) → 게이트 → Response 발급.
 * 파싱·서명검증·바인딩별 redirectTo 만 호출부에서 다르게 준비해 넘긴다.
 */
async function processSpInitiatedAuthnRequest(event: Parameters<RequestHandler>[0], p: ProcessAuthnRequestParams): Promise<Response> {
    const { locals, url } = event;
    const { authnRequest, sp, acsUrl } = p;

    // isPassive: 사용자 인터랙션 없이 처리해야 하므로, 세션이 없으면 NoPassive 오류를 ACS 로 반환.
    if (authnRequest.isPassive && (!locals.user || !locals.session)) {
        return await buildAndRenderSamlError({
            inResponseTo: authnRequest.id,
            acsUrl,
            issuerUrl: p.issuerUrl,
            subStatusCode: "urn:oasis:names:tc:SAML:2.0:status:NoPassive",
            certPem: p.certPem,
            privateKey: p.privateKey,
            relayState: authnRequest.relayState,
            locale: event.locals.locale,
        });
    }

    // 로그인 여부 확인 → 미로그인 시 로그인 페이지로
    if (!locals.user || !locals.session) {
        const loginUrl = new URL("/login", url);
        loginUrl.searchParams.set("redirectTo", p.loginRedirectTo);
        loginUrl.searchParams.set("skinHint", `saml:${sp.id}`);
        throw redirect(302, loginUrl.toString());
    }

    // forceAuthn: SP 가 강제 재인증을 요구하면, 현재 세션 상태와 무관하게 재인증으로 보낸다.
    // 무한 루프 방지: AuthnRequest ID 를 쿠키에 기록해 두고, 동일 요청에 대한 재진입이면 통과시킨다.
    if (authnRequest.forceAuthn) {
        // ctrls LOW: AuthnRequest.id 는 공격자 제어 XML 값이라 그대로 쿠키명에 쓰면 space/;/제어문자
        // 등으로 cookie.serialize 가 throw → 500 DoS. 안전 문자만 남겨 결정론적으로 정규화한다
        // (동일 요청 재진입 시 같은 이름이 되어 loop 가드는 그대로 동작, 보안 영향 없음).
        const safeId = authnRequest.id.replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 128);
        const reauthCookieName = `saml_reauth_${safeId}`;
        const alreadyReauthed = event.cookies.get(reauthCookieName) === "1";
        if (!alreadyReauthed) {
            // 다음 요청에서 동일 AuthnRequest 가 들어오면 통과되도록 짧은 TTL 쿠키를 설정.
            event.cookies.set(reauthCookieName, "1", {
                path: "/saml/sso",
                httpOnly: true,
                sameSite: "lax",
                secure: url.protocol === "https:",
                maxAge: 600,
            });
            // reauthPolicy=mfa_only 인 SP 는 OTP 승격으로 ForceAuthn 을 충족시킨다. SAML Core
            // 3.4.1.1 의 "기존 세션에 의존하지 말 것"을 완화하는 선택이므로 SP 별 opt-in 이다.
            throw redirect(302, buildSamlReauthUrl(url, sp, p.loginRedirectTo));
        }
        // 이미 재인증을 거치고 돌아온 경우 — 쿠키 삭제 후 SSO 응답 진행
        event.cookies.delete(reauthCookieName, { path: "/saml/sso" });
    }

    // ACR 게이트. 두 가지 요구를 함께 본다.
    //   1. SP 가 요청에 담은 RequestedAuthnContext (comparison 문법 해석)
    //   2. SP 등록 설정의 requireMfa — SP 가 요청에 아무것도 담지 않아도 IdP 측에서 강제한다
    const acrUnmet = (authnRequest.requestedAuthnContext && !acrSatisfies(locals.session.acr, authnRequest.requestedAuthnContext)) || (sp.requireMfa && !acrMeetsMfa(locals.session.acr));
    if (acrUnmet) {
        // 세션이 issueInstant 이후에 인증됐다면 재인증을 이미 거쳤으나 ACR 이 여전히 부족한 것.
        // (예: MFA 미설정 사용자가 refeds/mfa 를 요구받은 경우) → NoAuthnContext 오류 반환.
        //
        // createdAt 이 아니라 authTime 을 보는 것이 중요하다. MFA step-up 은 세션 행을 유지하므로
        // createdAt 이 그대로다 — createdAt 으로 비교하면 승격을 마치고 돌아와도 "재인증 안 함" 으로
        // 판정되어 /mfa ↔ /saml/sso 를 무한 왕복한다.
        //
        // `+1초` 관용: AuthnRequest 의 IssueInstant 는 xs:dateTime 으로 오되 밀리초가 없는 경우가
        // 흔해 초 단위로 절삭된다. 관용이 없으면 "로그인 직후 같은 초에 도착한 요청"에서 세션이
        // 요청보다 나중으로 보여, 재인증을 시켜야 할 상황에 NoAuthnContext 를 반환한다.
        // 진짜 재인증을 마치고 돌아오면 인증 시각이 요청 시각보다 수 초 뒤이므로 루프 방지는
        // 그대로 동작한다.
        const isPostReauth = sessionAuthTime(locals.session).getTime() >= authnRequest.issueInstant.getTime() + 1000;
        if (isPostReauth || authnRequest.isPassive) {
            return await buildAndRenderSamlError({
                inResponseTo: authnRequest.id,
                acsUrl,
                issuerUrl: p.issuerUrl,
                subStatusCode: "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
                certPem: p.certPem,
                privateKey: p.privateKey,
                relayState: authnRequest.relayState,
                locale: event.locals.locale,
            });
        }
        // 첫 시도: 재인증(MFA 포함)을 강제한다. reauthPolicy 가 전체 로그인이냐 OTP 승격이냐를 정한다.
        throw redirect(302, buildSamlReauthUrl(url, sp, p.loginRedirectTo));
    }

    return await gateAndIssueSamlAssertion(event, {
        db: p.db,
        tenant: p.tenant,
        issuerUrl: p.issuerUrl,
        sp,
        user: locals.user,
        session: locals.session,
        acsUrl,
        inResponseTo: authnRequest.id,
        relayState: authnRequest.relayState,
        certPem: p.certPem,
        privateKey: p.privateKey,
        consentResumeUrl: p.loginRedirectTo,
    });
}

/**
 * IdP-initiated (unsolicited) SSO.
 * 로그인된 사용자가 `?sp=<entityId>` 로 SP 를 지정하면, 대응되는 AuthnRequest 없이
 * IdP 가 먼저 Assertion 을 SP 의 등록된 ACS 로 밀어 준다. InResponseTo 없음.
 */
async function handleIdpInitiated(event: Parameters<RequestHandler>[0], ctx: { db: DB; tenant: Tenant; issuerUrl: string; signingKeySecrets: string[]; spEntityId: string }): Promise<Response> {
    const { locals, url } = event;
    const { db, tenant } = ctx;

    const sp = await findSp(db, tenant.id, ctx.spEntityId);
    if (!sp) {
        throw error(403, translate(locals.locale, "saml.errors.unknown_sp", { entityId: ctx.spEntityId }));
    }

    // 미로그인 시 로그인 페이지로 (로그인 후 동일 IdP-initiated URL 로 복귀)
    if (!locals.user || !locals.session) {
        const loginUrl = new URL("/login", url);
        loginUrl.searchParams.set("redirectTo", url.pathname + url.search);
        loginUrl.searchParams.set("skinHint", `saml:${sp.id}`);
        throw redirect(302, loginUrl.toString());
    }

    // requireMfa SP 는 IdP-initiated 경로에서도 MFA 수준 세션을 요구한다. 여기를 빠뜨리면
    // SP-initiated 만 게이트되고 `?sp=<entityId>` 로 우회해 password-only Assertion 을 받을 수 있다.
    if (sp.requireMfa && !acrMeetsMfa(locals.session.acr)) {
        // AuthnRequest 가 없어 issueInstant 기준 재진입 판정(SP-initiated 의 isPostReauth)을 쓸 수
        // 없다. TOTP 미등록 사용자를 그냥 재인증으로 보내면 로그인해도 ACR 이 올라가지 않아
        // /saml/sso ↔ /login 을 무한 왕복하므로, 승격 가능성을 먼저 확인하고 불가하면 오류로 끝낸다.
        if (!(await hasTotpCredential(db, locals.user.id))) {
            throw error(403, translate(locals.locale, "saml.errors.mfa_required"));
        }
        throw redirect(302, buildSamlReauthUrl(url, sp, url.pathname + url.search));
    }

    const signingKey = await getActiveSigningKey(db, tenant.id, ctx.signingKeySecrets);
    if (!signingKey || !signingKey.certPem) {
        throw error(503, translate(locals.locale, "saml.errors.signing_key_missing"));
    }

    const relayState = url.searchParams.get("RelayState");

    return await gateAndIssueSamlAssertion(event, {
        db,
        tenant,
        issuerUrl: ctx.issuerUrl,
        sp,
        user: locals.user,
        session: locals.session,
        acsUrl: sp.acsUrl, // 요청에 ACS 가 없으므로 등록된 SP ACS 사용
        inResponseTo: null, // unsolicited — InResponseTo 생략
        relayState,
        consentResumeUrl: url.pathname + url.search,
        certPem: signingKey.certPem,
        privateKey: signingKey.privateKey,
    });
}

/**
 * 공통 진입부: rate-limit + config 검증. 통과 시 { db, tenant, config } 반환.
 * GET/POST 모두 동일한 IP당 30회/분 제한을 적용한다 (AuthnRequest 파싱·서명 검증 DoS 방지).
 */
async function ssoPreflight(event: Parameters<RequestHandler>[0]) {
    const { locals, platform } = event;
    const { db, tenant, rateLimitStore } = requireDbContext(locals);
    const config = getRuntimeConfig(platform);

    const { ipKey } = getRequestMetadata(event);
    const rl = await checkRateLimit(rateLimitStore, `saml-sso:${ipKey}`, { windowMs: 60 * 1000, limit: 30 });
    if (!rl.allowed) {
        throw error(429, translate(locals.locale, "saml.errors.rate_limited"));
    }

    if (!config.issuerUrl) throw error(503, translate(locals.locale, "saml.errors.issuer_not_set"));
    if (config.signingKeySecrets.length === 0) throw error(503, translate(locals.locale, "saml.errors.signing_key_not_set"));

    return { db, tenant, issuerUrl: config.issuerUrl, signingKeySecrets: config.signingKeySecrets };
}

/** AuthnRequest Destination 이 IdP SSO endpoint 와 일치하는지 검증 (명시된 경우만). */
function assertDestination(authnRequest: ParsedAuthnRequest, issuerUrl: string, locale: Locale): void {
    if (authnRequest.destination) {
        const expectedDestination = `${issuerUrl.replace(/\/+$/, "")}/saml/sso`;
        if (authnRequest.destination !== expectedDestination) {
            throw error(400, translate(locale, "saml.errors.destination_mismatch"));
        }
    }
}

/** AuthnRequest 의 ACS URL 이 등록된 SP ACS 와 일치하는지 검증하고 최종 ACS 를 반환. */
function resolveAcsUrl(authnRequest: ParsedAuthnRequest, sp: SamlSpRecord, locale: Locale): string {
    // AuthnRequest 에 ACS 가 명시된 경우 반드시 등록된 SP ACS 와 일치해야 한다.
    // 다른 URL 을 허용하면 공격자가 서명된 Assertion 을 자신의 서버로 가로챌 수 있다.
    if (authnRequest.acsUrl && authnRequest.acsUrl !== sp.acsUrl) {
        throw error(400, translate(locale, "saml.errors.acs_url_mismatch"));
    }
    return sp.acsUrl;
}

/**
 * GET /saml/sso
 *   - SAMLRequest 있음 → SP-initiated / HTTP-Redirect 바인딩
 *   - SAMLRequest 없고 sp 있음 → IdP-initiated (unsolicited)
 */
export const GET: RequestHandler = async (event) => {
    const { url } = event;
    const { db, tenant, issuerUrl, signingKeySecrets } = await ssoPreflight(event);

    const samlRequestB64 = url.searchParams.get("SAMLRequest");
    const relayState = url.searchParams.get("RelayState");

    // ── IdP-initiated 분기: SAMLRequest 없이 sp 파라미터만 존재 ─────────────────
    if (!samlRequestB64) {
        const spParam = url.searchParams.get("sp");
        if (spParam) {
            return await handleIdpInitiated(event, { db, tenant, issuerUrl, signingKeySecrets, spEntityId: spParam });
        }
        throw error(400, translate(event.locals.locale, "saml.errors.saml_request_missing"));
    }

    // ── SP-initiated / HTTP-Redirect 바인딩 ────────────────────────────────────
    let authnRequest: ParsedAuthnRequest;
    try {
        authnRequest = await parseAuthnRequest(samlRequestB64, relayState);
    } catch {
        throw error(400, translate(event.locals.locale, "saml.errors.saml_request_parse_failed"));
    }

    assertDestination(authnRequest, issuerUrl, event.locals.locale);

    const sp = await findSp(db, tenant.id, authnRequest.issuer);
    if (!sp) {
        throw error(403, translate(event.locals.locale, "saml.errors.unknown_sp", { entityId: authnRequest.issuer }));
    }

    // AuthnRequest 서명 검증: SP 가 서명을 요구하거나 Signature 파라미터가 있는 경우.
    // HTTP-Redirect 바인딩 서명은 URL 쿼리(SAMLRequest&RelayState&SigAlg) 에 대한 detached 서명.
    const hasSig = url.searchParams.has("Signature");
    if (sp.wantAuthnRequestsSigned || hasSig) {
        if (!sp.cert) {
            throw error(400, translate(event.locals.locale, "saml.errors.sp_cert_missing_for_authn_sig"));
        }
        const rawQuery = url.search.slice(1);
        const sigValid = await verifySamlRedirectSignature(rawQuery, sp.cert);
        if (!sigValid) {
            throw error(400, translate(event.locals.locale, "saml.errors.authn_signature_invalid"));
        }
    }

    const acsUrl = resolveAcsUrl(authnRequest, sp, event.locals.locale);

    const signingKey = await getActiveSigningKey(db, tenant.id, signingKeySecrets);
    if (!signingKey || !signingKey.certPem) {
        throw error(503, translate(event.locals.locale, "saml.errors.signing_key_missing"));
    }

    return await processSpInitiatedAuthnRequest(event, {
        db,
        tenant,
        issuerUrl,
        sp,
        authnRequest,
        acsUrl,
        certPem: signingKey.certPem,
        privateKey: signingKey.privateKey,
        loginRedirectTo: url.pathname + url.search,
    });
};

/**
 * POST /saml/sso — SP-initiated / HTTP-POST 바인딩.
 * body: SAMLRequest=<base64(XML)> (deflate 없음), RelayState=...
 */
export const POST: RequestHandler = async (event) => {
    const { url } = event;
    const { db, tenant, issuerUrl, signingKeySecrets } = await ssoPreflight(event);

    const form = await event.request.formData();
    const samlRequestB64 = typeof form.get("SAMLRequest") === "string" ? (form.get("SAMLRequest") as string) : null;
    const relayState = typeof form.get("RelayState") === "string" ? (form.get("RelayState") as string) : null;

    if (!samlRequestB64) {
        throw error(400, translate(event.locals.locale, "saml.errors.saml_request_missing"));
    }

    // HTTP-POST 바인딩: base64(XML), deflate 없음. 서명 검증·resume 재인코딩에 재사용하도록
    // XML 을 한 번만 디코드한다. 파서(parseAuthnRequestPost)와 서명 검증기가 동일한 원본
    // 문자열을 보게 해, 파싱 결과와 서명 대상이 분기되는 것을 막는다.
    let xml: string;
    try {
        const raw = atob(samlRequestB64);
        const bin = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) bin[i] = raw.charCodeAt(i);
        xml = new TextDecoder().decode(bin);
    } catch {
        throw error(400, translate(event.locals.locale, "saml.errors.saml_request_parse_failed"));
    }

    let authnRequest: ParsedAuthnRequest;
    try {
        authnRequest = await parseAuthnRequestPost(samlRequestB64, relayState);
    } catch {
        throw error(400, translate(event.locals.locale, "saml.errors.saml_request_parse_failed"));
    }

    assertDestination(authnRequest, issuerUrl, event.locals.locale);

    const sp = await findSp(db, tenant.id, authnRequest.issuer);
    if (!sp) {
        throw error(403, translate(event.locals.locale, "saml.errors.unknown_sp", { entityId: authnRequest.issuer }));
    }

    // ── 서명 검증 (HTTP-POST 바인딩) ───────────────────────────────────────────
    // POST 바인딩의 서명 AuthnRequest 는 URL 쿼리 서명이 아니라 요청 XML 내부의 enveloped
    // XML 서명(ds:Signature)이다. SP 가 서명을 요구(wantAuthnRequestsSigned)하거나 XML 에
    // 서명이 존재하면, 신뢰하는 SP 인증서(sp.cert) 공개키로만 enveloped 서명을 검증한다.
    // (KeyInfo 의 인증서는 신뢰하지 않음 — verify-xml-signature.ts 참조.)
    if (sp.wantAuthnRequestsSigned || authnRequest.hasSignature) {
        if (!sp.cert) {
            // 검증에 쓸 SP 인증서가 없으면 서명을 검증할 방법이 없다 → 거부.
            throw error(400, translate(event.locals.locale, "saml.errors.sp_cert_missing_for_authn_sig"));
        }
        const sigValid = await verifyEnvelopedXmlSignature(xml, sp.cert);
        if (!sigValid) {
            throw error(400, translate(event.locals.locale, "saml.errors.authn_signature_invalid"));
        }
    }

    const acsUrl = resolveAcsUrl(authnRequest, sp, event.locals.locale);

    const signingKey = await getActiveSigningKey(db, tenant.id, signingKeySecrets);
    if (!signingKey || !signingKey.certPem) {
        throw error(503, translate(event.locals.locale, "saml.errors.signing_key_missing"));
    }

    // 로그인/재인증 후 복귀 URL: POST body 는 GET 리다이렉트로 보존되지 않으므로, 동일
    // AuthnRequest 를 HTTP-Redirect 바인딩으로 재인코딩해 기존 GET 경로가 그대로 재개하도록 한다.
    const resumeParams = new URLSearchParams();
    resumeParams.set("SAMLRequest", await encodeRedirectBindingSamlRequest(xml));
    if (relayState) resumeParams.set("RelayState", relayState);
    const loginRedirectTo = `${url.pathname}?${resumeParams.toString()}`;

    return await processSpInitiatedAuthnRequest(event, {
        db,
        tenant,
        issuerUrl,
        sp,
        authnRequest,
        acsUrl,
        certPem: signingKey.certPem,
        privateKey: signingKey.privateKey,
        loginRedirectTo,
    });
};
