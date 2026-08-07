import { fail } from "@sveltejs/kit";
import { desc, eq, and } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireAdminContext } from "$lib/server/auth/guards";
import { adminError, requireFormId } from "$lib/server/admin/errors";
import { SAML_ATTRIBUTE_KEYS } from "$lib/server/admin/schemas";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";
import { samlSps } from "$lib/server/db/schema";
import { validateSamlUrl } from "$lib/server/validation";

export const load: PageServerLoad = async ({ locals }) => {
    const { db, tenant } = requireAdminContext(locals);
    const rows = await db
        .select({
            id: samlSps.id,
            entityId: samlSps.entityId,
            name: samlSps.name,
            acsUrl: samlSps.acsUrl,
            acsBinding: samlSps.acsBinding,
            sloUrl: samlSps.sloUrl,
            cert: samlSps.cert,
            nameIdFormat: samlSps.nameIdFormat,
            signAssertion: samlSps.signAssertion,
            signResponse: samlSps.signResponse,
            encryptAssertion: samlSps.encryptAssertion,
            wantAuthnRequestsSigned: samlSps.wantAuthnRequestsSigned,
            requireVerifiedEmail: samlSps.requireVerifiedEmail,
            allowedAttributes: samlSps.allowedAttributes,
            allowAllUsers: samlSps.allowAllUsers,
            enabled: samlSps.enabled,
            createdAt: samlSps.createdAt,
        })
        .from(samlSps)
        .where(eq(samlSps.tenantId, tenant.id))
        .orderBy(desc(samlSps.createdAt));

    return { sps: rows };
};

// 화이트리스트 본체는 `$lib/server/admin/schemas` 에 있다 — SSO 발행 경로와의 정합을
// 테스트로 고정하기 위해서다(그 파일 주석 참조).
const ATTRIBUTE_KEYS = SAML_ATTRIBUTE_KEYS;

const ALLOWED_NAMEID_FORMATS = [
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
] as const;

function parseAllowedAttributes(raw: string): string | null {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    const parts = trimmed
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0)
        .filter((s): s is (typeof ATTRIBUTE_KEYS)[number] => (ATTRIBUTE_KEYS as readonly string[]).includes(s));
    if (parts.length === 0) return null;
    return JSON.stringify([...new Set(parts)]);
}

export const actions: Actions = {
    // ── SP 생성 ────────────────────────────────────────────────────────────────
    create: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        const name = String(fd.get("name") ?? "").trim();
        const entityId = String(fd.get("entityId") ?? "").trim();
        const acsUrl = String(fd.get("acsUrl") ?? "").trim();
        const sloUrl = String(fd.get("sloUrl") ?? "").trim();
        const nameIdFormat = String(fd.get("nameIdFormat") ?? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress").trim();
        const cert = String(fd.get("cert") ?? "").trim();
        const signAssertion = fd.get("signAssertion") === "true";
        // ctrls H-SAML-1: signResponse 는 항상 true 강제. SP 가 XSW 류 공격에 노출되지
        // 않도록 IDP 가 항상 Response 자체를 서명한다. admin UI 가 false 를 보내도 무시.
        const signResponse = true;
        const wantAuthnRequestsSigned = fd.get("wantAuthnRequestsSigned") === "true";
        const requireVerifiedEmail = fd.get("requireVerifiedEmail") === "true";
        const encryptAssertion = fd.get("encryptAssertion") === "true";
        const allowedAttributes = parseAllowedAttributes(String(fd.get("allowedAttributes") ?? ""));
        // 서비스 권한 게이트 우회 opt-in — 사용자별 매핑 없이 전체 허용.
        const allowAllUsers = fd.get("allowAllUsers") === "true";

        if (!name) return fail(400, { create: true, error: adminError(locale, "name_required") });
        if (!entityId) return fail(400, { create: true, error: adminError(locale, "entity_id_required") });
        if (!acsUrl) return fail(400, { create: true, error: adminError(locale, "acs_url_required") });
        // Assertion 암호화는 SP 공개키가 있어야 가능하다.
        if (encryptAssertion && !cert) return fail(400, { create: true, error: adminError(locale, "sp_cert_required_for_encryption") });

        const acsV = validateSamlUrl(acsUrl, "ACS URL");
        if (!acsV.ok) return fail(400, { create: true, error: adminError(locale, acsV.reason.key, acsV.reason.params) });
        const sloV = validateSamlUrl(sloUrl, "SLO URL");
        if (!sloV.ok) return fail(400, { create: true, error: adminError(locale, sloV.reason.key, sloV.reason.params) });

        if (!(ALLOWED_NAMEID_FORMATS as readonly string[]).includes(nameIdFormat)) {
            return fail(400, { create: true, error: adminError(locale, "nameid_format_forbidden") });
        }

        // 중복 Entity ID 확인
        const [existing] = await db
            .select({ id: samlSps.id })
            .from(samlSps)
            .where(and(eq(samlSps.tenantId, tenant.id), eq(samlSps.entityId, entityId)))
            .limit(1);
        if (existing) return fail(409, { create: true, error: adminError(locale, "entity_id_taken") });

        await db.insert(samlSps).values({
            id: crypto.randomUUID(),
            tenantId: tenant.id,
            name,
            entityId,
            acsUrl,
            sloUrl: sloUrl || null,
            cert: cert || null,
            nameIdFormat,
            signAssertion,
            signResponse,
            wantAuthnRequestsSigned,
            requireVerifiedEmail,
            encryptAssertion,
            allowedAttributes,
            allowAllUsers,
            enabled: true,
        });

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            kind: "saml_sp_created",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { entityId, name },
        });

        return { create: true };
    },

    // ── SP 수정 ────────────────────────────────────────────────────────────────
    update: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        const id = String(fd.get("id") ?? "");
        const name = String(fd.get("name") ?? "").trim();
        const acsUrl = String(fd.get("acsUrl") ?? "").trim();
        const sloUrl = String(fd.get("sloUrl") ?? "").trim();
        const nameIdFormat = String(fd.get("nameIdFormat") ?? "").trim();
        const cert = String(fd.get("cert") ?? "").trim();
        const signAssertion = fd.get("signAssertion") === "true";
        // ctrls H-SAML-1: signResponse 는 항상 true 강제. SP 가 XSW 류 공격에 노출되지
        // 않도록 IDP 가 항상 Response 자체를 서명한다. admin UI 가 false 를 보내도 무시.
        const signResponse = true;
        const wantAuthnRequestsSigned = fd.get("wantAuthnRequestsSigned") === "true";
        const requireVerifiedEmail = fd.get("requireVerifiedEmail") === "true";
        const encryptAssertion = fd.get("encryptAssertion") === "true";
        const enabled = fd.get("enabled") === "true";
        const allowedAttributes = parseAllowedAttributes(String(fd.get("allowedAttributes") ?? ""));
        // 서비스 권한 게이트 우회 opt-in — 사용자별 매핑 없이 전체 허용.
        const allowAllUsers = fd.get("allowAllUsers") === "true";

        if (!id || !name || !acsUrl) return fail(400, { error: adminError(locale, "required_field_missing") });
        // Assertion 암호화는 SP 공개키가 있어야 가능하다.
        if (encryptAssertion && !cert) return fail(400, { error: adminError(locale, "sp_cert_required_for_encryption") });

        const acsV = validateSamlUrl(acsUrl, "ACS URL");
        if (!acsV.ok) return fail(400, { error: adminError(locale, acsV.reason.key, acsV.reason.params) });
        const sloV = validateSamlUrl(sloUrl, "SLO URL");
        if (!sloV.ok) return fail(400, { error: adminError(locale, sloV.reason.key, sloV.reason.params) });

        if (nameIdFormat && !(ALLOWED_NAMEID_FORMATS as readonly string[]).includes(nameIdFormat)) {
            return fail(400, { error: adminError(locale, "nameid_format_forbidden") });
        }

        // ctrls H-SAML-4: 보안 설정 변경을 audit 로그에 정확히 기록.
        // 특히 cert / acsUrl / wantAuthnRequestsSigned 는 침해 후 ACS hijack 시나리오의
        // 핵심 변수 — admin 권한 일시 탈취 시 ACS URL 을 attacker 서버로 바꾸면 모든
        // Assertion 이 가로채진다. forensics 가능성 확보를 위해 before/after diff 기록.
        const [before] = await db
            .select()
            .from(samlSps)
            .where(and(eq(samlSps.id, id), eq(samlSps.tenantId, tenant.id)))
            .limit(1);

        await db
            .update(samlSps)
            .set({
                name,
                acsUrl,
                sloUrl: sloUrl || null,
                cert: cert || null,
                nameIdFormat,
                signAssertion,
                signResponse,
                wantAuthnRequestsSigned,
                requireVerifiedEmail,
                encryptAssertion,
                allowedAttributes,
                allowAllUsers,
                enabled,
                updatedAt: new Date(),
            })
            .where(and(eq(samlSps.id, id), eq(samlSps.tenantId, tenant.id)));

        const meta = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            spOrClientId: before?.entityId ?? null,
            kind: "saml_sp_updated",
            outcome: "success",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: {
                spId: id,
                changed: {
                    name: before?.name !== name,
                    acsUrl: before?.acsUrl !== acsUrl,
                    sloUrl: before?.sloUrl !== (sloUrl || null),
                    certChanged: (before?.cert ?? null) !== (cert || null),
                    nameIdFormat: before?.nameIdFormat !== nameIdFormat,
                    signAssertion: before?.signAssertion !== signAssertion,
                    signResponse: before?.signResponse !== signResponse,
                    wantAuthnRequestsSigned: before?.wantAuthnRequestsSigned !== wantAuthnRequestsSigned,
                    requireVerifiedEmail: before?.requireVerifiedEmail !== requireVerifiedEmail,
                    // 권한 표면 확대 플래그 — 침해 forensics 를 위해 변경 여부 기록.
                    allowAllUsers: before?.allowAllUsers !== allowAllUsers,
                    enabled: before?.enabled !== enabled,
                },
                newAcsUrl: acsUrl,
                newSloUrl: sloUrl || null,
            },
        });

        return { update: true };
    },

    // ── SP 삭제 ────────────────────────────────────────────────────────────────
    delete: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        const idr = requireFormId(fd, locale);
        if (!idr.ok) return idr.failure;
        const id = idr.id;

        await db.delete(samlSps).where(and(eq(samlSps.id, id), eq(samlSps.tenantId, tenant.id)));

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            kind: "saml_sp_deleted",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { spId: id },
        });

        return { deleted: true };
    },
};
