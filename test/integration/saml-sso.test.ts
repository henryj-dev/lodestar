import "reflect-metadata";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { POST as ssoPOST } from "../../src/routes/saml/sso/+server";
import { actions as spListActions } from "../../src/routes/admin/saml-sps/+page.server";
import { samlSessions, samlSps } from "../../src/lib/server/db/schema";
import {
    openMemoryDb,
    seedServiceEntitlement,
    grantEntitlement,
    seedTenantAndSigningKey,
    seedUser,
    seedSamlSp,
    seedServiceAssignment,
    seedSession,
    seedMfaSession,
    makeEvent,
    makeKeyCert,
    buildAuthnRequestXml,
    encodePostBindingSamlRequest,
    decodeSamlResponse,
    verifyAssertionSignatureInResponse,
    getIdpSigningCertPem,
    catchError,
    TEST_ISSUER_URL,
    type MemoryDb,
    type KeyCert,
} from "./harness";
import type { Tenant, User, Session, SamlSp } from "../../src/lib/server/db/schema";

// SAML SP-initiated HTTP-POST 바인딩을 실 DB(libSQL :memory:) + 실 /saml/sso POST 라우트로 검증한다.
// 서명된 AuthnRequest → 서비스 권한 게이트 → 서명된 SAML Response(ACS auto-submit 폼) 발급까지 풀플로우.

const SP_ENTITY_ID = "https://sp.test.example";
const SP_ACS_URL = "https://sp.test.example/acs";
const SSO_DESTINATION = `${TEST_ISSUER_URL}/saml/sso`;

let mem: MemoryDb;
let tenant: Tenant;
let user: User;
let session: Session;
let sp: SamlSp;
let spKc: KeyCert;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    spKc = await makeKeyCert("Test SP");
    user = await seedUser(mem.db, {
        tenantId: tenant.id,
        email: "sam@test.example",
        username: "sam",
        password: "sam-password-strong",
        displayName: "Sam Example",
    });
    session = (await seedSession(mem.db, { tenantId: tenant.id, userId: user.id })).session;
    sp = await seedSamlSp(mem.db, {
        tenantId: tenant.id,
        entityId: SP_ENTITY_ID,
        acsUrl: SP_ACS_URL,
        cert: spKc.certPem,
        wantAuthnRequestsSigned: true,
        // 서명 검증(단일 Assertion 서명)을 재검증하기 위해 Response 서명은 끈다.
        signResponse: false,
    });
});

afterEach(() => mem.close());

/** 서명된 AuthnRequest 를 POST 바인딩으로 /saml/sso 에 제출한다. */
async function postAuthnRequest(args: { id: string; loggedIn: boolean; assignUser: boolean; requestUser?: User; requestSession?: Session }): Promise<Response> {
    const xml = await buildAuthnRequestXml({
        id: args.id,
        kc: spKc,
        issuer: SP_ENTITY_ID,
        destination: SSO_DESTINATION,
        acsUrl: SP_ACS_URL,
        sign: true,
    });
    const samlRequest = encodePostBindingSamlRequest(xml);
    const u = args.requestUser ?? user;
    const s = args.requestSession ?? session;
    const event = makeEvent({
        method: "POST",
        url: SSO_DESTINATION,
        form: { SAMLRequest: samlRequest },
        locals: {
            db: mem.db,
            tenant,
            user: args.loggedIn ? u : null,
            session: args.loggedIn ? s : null,
            env: mem.env,
        },
    });
    return (await ssoPOST(event)) as Response;
}

/** auto-submit 폼 HTML 에서 SAMLResponse hidden input 값을 추출한다. */
function extractSamlResponseFromForm(html: string): string {
    const m = html.match(/name="SAMLResponse" value="([^"]+)"/);
    expect(m).not.toBeNull();
    return m![1];
}

describe("SAML SP-initiated POST 바인딩", () => {
    it("로그인+권한 부여 상태에서 서명된 AuthnRequest 는 서명·audience·ACS 가 일치하는 SAML Response 를 ACS 로 발급한다", async () => {
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "saml", serviceRefId: sp.id });

        const res = await postAuthnRequest({ id: "_authnreq_ok", loggedIn: true, assignUser: true });
        expect(res.status).toBe(200);
        expect(res.headers.get("content-type")).toContain("text/html");

        const html = await res.text();
        // ACS 로 auto-submit 하는 폼이어야 한다.
        expect(html).toContain(`action="${SP_ACS_URL}"`);

        const responseXml = decodeSamlResponse(extractSamlResponseFromForm(html));
        // InResponseTo = AuthnRequest ID, Destination = ACS, Audience = SP entityId, NameID = 사용자 이메일.
        expect(responseXml).toContain(`InResponseTo="_authnreq_ok"`);
        expect(responseXml).toContain(`Destination="${SP_ACS_URL}"`);
        expect(responseXml).toContain(`<saml:Audience>${SP_ENTITY_ID}</saml:Audience>`);
        expect(responseXml).toContain(`>${user.email}</saml:NameID>`);
        expect(responseXml).toContain("urn:oasis:names:tc:SAML:2.0:status:Success");

        // IdP 서명키로 Assertion 서명을 실제 재검증한다(SP 가 하는 방식과 동일하게 문서 컨텍스트 내 검증).
        const idpCert = await getIdpSigningCertPem(mem, tenant.id);
        expect(await verifyAssertionSignatureInResponse(responseXml, idpCert)).toBe(true);
        // 다른 인증서(SP 인증서)로는 검증되지 않아야 한다(서명이 IdP 키로 되어 있음).
        expect(await verifyAssertionSignatureInResponse(responseXml, spKc.certPem)).toBe(false);

        // saml_sessions 기록이 남아야 한다.
        const sessions = await mem.db.select().from(samlSessions).where(eq(samlSessions.userId, user.id));
        expect(sessions.length).toBe(1);
        expect(sessions[0].spId).toBe(sp.id);
        expect(sessions[0].nameId).toBe(user.email);
    });

    it("Assertion 서명 후 NameID 를 변조하면 서명 검증이 실패한다(서명이 실제로 내용을 커버)", async () => {
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "saml", serviceRefId: sp.id });
        const res = await postAuthnRequest({ id: "_authnreq_tamper", loggedIn: true, assignUser: true });
        const responseXml = decodeSamlResponse(extractSamlResponseFromForm(await res.text()));
        const tampered = responseXml.replace(`>${user.email}</saml:NameID>`, `>attacker@evil.example</saml:NameID>`);
        expect(tampered).not.toBe(responseXml);
        const idpCert = await getIdpSigningCertPem(mem, tenant.id);
        // 원본은 검증 통과, 변조본은 다이제스트 불일치로 실패해야 한다.
        expect(await verifyAssertionSignatureInResponse(responseXml, idpCert)).toBe(true);
        expect(await verifyAssertionSignatureInResponse(tampered, idpCert)).toBe(false);
    });

    it("서비스 권한 매핑이 없는 SP 접근은 403 으로 거부된다(기본 deny)", async () => {
        // seedServiceAssignment 를 하지 않음 → 게이트 실패.
        const { status } = await catchError(() => postAuthnRequest({ id: "_authnreq_denied", loggedIn: true, assignUser: false }));
        expect(status).toBe(403);
        // Assertion 이 발급되지 않았으므로 saml_sessions 기록도 없어야 한다.
        const sessions = await mem.db.select().from(samlSessions).where(eq(samlSessions.userId, user.id));
        expect(sessions.length).toBe(0);
    });

    it("requireVerifiedEmail SP 는 이메일 미인증 사용자를 403 으로 거부한다(R6)", async () => {
        await mem.db.update(samlSps).set({ requireVerifiedEmail: true }).where(eq(samlSps.id, sp.id));
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "saml", serviceRefId: sp.id });
        // 강제 로직은 locals.user.emailVerifiedAt 를 본다 — 미인증 사용자로 요청.
        const unverifiedUser = { ...user, emailVerifiedAt: null };
        const { status } = await catchError(() => postAuthnRequest({ id: "_authnreq_unverified", loggedIn: true, assignUser: true, requestUser: unverifiedUser }));
        expect(status).toBe(403);
        const sessions = await mem.db.select().from(samlSessions).where(eq(samlSessions.userId, user.id));
        expect(sessions.length).toBe(0);
    });

    it("requireVerifiedEmail SP 도 이메일 인증된 사용자는 Assertion 을 발급한다(R6)", async () => {
        await mem.db.update(samlSps).set({ requireVerifiedEmail: true }).where(eq(samlSps.id, sp.id));
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "saml", serviceRefId: sp.id });
        // 기본 seedUser 는 emailVerifiedAt=now(인증됨).
        const res = await postAuthnRequest({ id: "_authnreq_verified_ok", loggedIn: true, assignUser: true });
        expect(res.status).toBe(200);
    });

    it("allowAllUsers SP 는 서비스 매핑 없이도 Assertion 을 발급한다(Role 속성은 미포함)", async () => {
        await mem.db.update(samlSps).set({ allowAllUsers: true }).where(eq(samlSps.id, sp.id));

        // seedServiceAssignment 없이 접근 → allowAllUsers 게이트 통과.
        const res = await postAuthnRequest({ id: "_authnreq_allow_all", loggedIn: true, assignUser: false });
        expect(res.status).toBe(200);

        const responseXml = decodeSamlResponse(extractSamlResponseFromForm(await res.text()));
        expect(responseXml).toContain("urn:oasis:names:tc:SAML:2.0:status:Success");
        expect(responseXml).toContain(`>${user.email}</saml:NameID>`);
        // assignment 가 없으므로 role 기반 속성은 포함되지 않아야 한다.
        expect(responseXml).not.toContain(`Name="Role"`);

        const sessions = await mem.db.select().from(samlSessions).where(eq(samlSessions.userId, user.id));
        expect(sessions.length).toBe(1);
    });

    it("동일 AuthnRequest ID 로 두 번째 Assertion 발급을 시도하면 replay 가드가 400 으로 거부한다", async () => {
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "saml", serviceRefId: sp.id });

        const first = await postAuthnRequest({ id: "_authnreq_replay", loggedIn: true, assignUser: true });
        expect(first.status).toBe(200);

        // 동일 AuthnRequest ID 재제출 → 이미 소비된 requestId → replay 거부.
        const { status } = await catchError(() => postAuthnRequest({ id: "_authnreq_replay", loggedIn: true, assignUser: true }));
        expect(status).toBe(400);

        // Assertion 은 최초 1회만 발급되어야 한다.
        const sessions = await mem.db.select().from(samlSessions).where(eq(samlSessions.userId, user.id));
        expect(sessions.length).toBe(1);
    });

    it("미로그인 상태의 SP-initiated 요청은 /login 으로 리다이렉트한다(Assertion 미발급)", async () => {
        await seedServiceAssignment(mem.db, { tenantId: tenant.id, userId: user.id, serviceType: "saml", serviceRefId: sp.id });
        // processSpInitiatedAuthnRequest 는 미로그인 시 redirect(302, /login...) 를 throw 한다.
        let redirected: { status?: number; location?: string } | null = null;
        try {
            await postAuthnRequest({ id: "_authnreq_nologin", loggedIn: false, assignUser: true });
        } catch (e) {
            redirected = e as { status?: number; location?: string };
        }
        expect(redirected?.status).toBe(302);
        expect(redirected?.location).toContain("/login");
        expect(redirected?.location).toContain("redirectTo=");
        const sessions = await mem.db.select().from(samlSessions).where(eq(samlSessions.userId, user.id));
        expect(sessions.length).toBe(0);
    });
});

// SAML 은 OIDC 의 `entitlements` 클레임과 같은 값을 `Entitlements` 속성으로 내보낸다.
// 목록이므로 하나의 <saml:Attribute> 안에 여러 <saml:AttributeValue> 로 나간다(SAML 표준 표현).
// 다른 속성과 같이 SP 의 allowedAttributes 게이트를 받는다.
describe("SAML Entitlements 속성", () => {
    async function grantEnts(keys: string[], opts: { attributesJson?: string } = {}): Promise<void> {
        const assignmentId = await seedServiceAssignment(mem.db, {
            tenantId: tenant.id,
            userId: user.id,
            serviceType: "saml",
            serviceRefId: sp.id,
            attributesJson: opts.attributesJson,
        });
        for (const [i, key] of keys.entries()) {
            const entId = await seedServiceEntitlement(mem.db, { tenantId: tenant.id, serviceType: "saml", serviceRefId: sp.id, key, displayOrder: i * 10 });
            await grantEntitlement(mem.db, { tenantId: tenant.id, assignmentId, serviceEntitlementId: entId });
        }
    }

    async function allowAttrs(list: string[]): Promise<void> {
        await mem.db
            .update(samlSps)
            .set({ allowedAttributes: JSON.stringify(list) })
            .where(eq(samlSps.id, sp.id));
    }

    it("SP 가 허용하면 값마다 AttributeValue 로 나간다", async () => {
        await allowAttrs(["email", "Entitlements"]);
        await grantEnts(["site.read", "plan.approve"]);

        const res = await postAuthnRequest({ id: "_ent_ok", loggedIn: true, assignUser: true });
        const xml = decodeSamlResponse(extractSamlResponseFromForm(await res.text()));

        expect(xml).toContain('Name="Entitlements"');
        expect(xml).toContain(">site.read<");
        expect(xml).toContain(">plan.approve<");
        // 하나의 Attribute 안에 두 값 — Attribute 가 두 번 나오면 안 된다.
        expect(xml.match(/Name="Entitlements"/g)).toHaveLength(1);
    });

    it("SP 허용 목록에 없으면 나가지 않는다", async () => {
        await allowAttrs(["email"]); // Entitlements 미포함
        await grantEnts(["site.read"]);

        const res = await postAuthnRequest({ id: "_ent_gated", loggedIn: true, assignUser: true });
        const xml = decodeSamlResponse(extractSamlResponseFromForm(await res.text()));

        expect(xml).not.toContain("Entitlements");
        expect(xml).not.toContain("site.read");
    });

    it("권한이 0개면 속성 자체가 없다", async () => {
        await allowAttrs(["email", "Entitlements"]);
        await grantEnts([]);

        const res = await postAuthnRequest({ id: "_ent_none", loggedIn: true, assignUser: true });
        const xml = decodeSamlResponse(extractSamlResponseFromForm(await res.text()));

        expect(xml).not.toContain('Name="Entitlements"');
    });

    // ── 관리자 폼 경로 회귀 방어 ─────────────────────────────────────────────
    //
    // 위 테스트들은 allowedAttributes 를 DB 에 **직접** 써서 관리자 폼 검증을 건너뛴다.
    // 그 사각지대 때문에, 발행 로직·정의 UI·안내 문구가 다 있는데도 화이트리스트
    // (SAML_ATTRIBUTE_KEYS)에 "Entitlements" 가 없어 관리자가 저장할 수 없고 → 속성이
    // 영원히 나가지 못하는 상태가 한동안 유지됐다. 아래 두 테스트가 그 경로를 고정한다.
    /**
     * 관리자 SP 수정 폼을 실제로 제출한다. 실 화면과 같이 기존 값(cert 등)을 그대로 다시
     * 실어 보낸다 — 빈 문자열로 보내면 그 필드가 지워지는 것이 정상 동작이다.
     */
    async function submitAllowedAttrsForm(raw: string): Promise<void> {
        const admin = await seedUser(mem.db, { tenantId: tenant.id, email: `admin-${raw.length}-${Date.now()}@test.example`, role: "admin" });
        const adminSession = (await seedMfaSession(mem.db, { tenantId: tenant.id, userId: admin.id })).session;
        const [current] = await mem.db.select().from(samlSps).where(eq(samlSps.id, sp.id)).limit(1);
        const event = makeEvent({
            method: "POST",
            url: `${TEST_ISSUER_URL}/admin/saml-sps`,
            form: {
                id: sp.id,
                name: current.name,
                acsUrl: current.acsUrl,
                sloUrl: current.sloUrl ?? "",
                nameIdFormat: current.nameIdFormat ?? "",
                cert: current.cert ?? "",
                wantAuthnRequestsSigned: current.wantAuthnRequestsSigned ? "true" : "false",
                signAssertion: current.signAssertion ? "true" : "false",
                allowedAttributes: raw,
                enabled: "true",
            },
            locals: { db: mem.db, tenant, user: admin, session: adminSession, env: mem.env },
        });
        await spListActions.update!(event as Parameters<NonNullable<typeof spListActions.update>>[0]);
    }

    it("관리자 폼으로 저장한 allowedAttributes 에 Entitlements 가 살아남는다", async () => {
        await submitAllowedAttrsForm("email,Role,RoleLabel,Entitlements");

        const [row] = await mem.db.select({ allowedAttributes: samlSps.allowedAttributes }).from(samlSps).where(eq(samlSps.id, sp.id)).limit(1);
        expect(JSON.parse(row.allowedAttributes!)).toEqual(["email", "Role", "RoleLabel", "Entitlements"]);
    });

    it("관리자 폼으로 허용한 뒤 실제로 Assertion 에 Entitlements 가 실린다 (끝단 연결)", async () => {
        await submitAllowedAttrsForm("email,Entitlements");
        await grantEnts(["site.read"]);

        const res = await postAuthnRequest({ id: "_ent_admin_e2e", loggedIn: true, assignUser: true });
        const xml = decodeSamlResponse(extractSamlResponseFromForm(await res.text()));

        expect(xml).toContain('Name="Entitlements"');
        expect(xml).toContain(">site.read<");
    });

    it("화이트리스트에 없는 키는 관리자 폼에서 걸러진다 (기존 동작 유지)", async () => {
        await submitAllowedAttrsForm("email,Entitlements,NotAnAttribute");

        const [row] = await mem.db.select({ allowedAttributes: samlSps.allowedAttributes }).from(samlSps).where(eq(samlSps.id, sp.id)).limit(1);
        expect(JSON.parse(row.allowedAttributes!)).toEqual(["email", "Entitlements"]);
    });

    it("attributesJson 으로 Entitlements/Role 을 위조할 수 없다", async () => {
        await allowAttrs(["email", "Entitlements", "Role", "harmless"]);
        await grantEnts(["site.read"], { attributesJson: JSON.stringify({ Entitlements: "plan.approve_own", Role: "admin", harmless: "kept" }) });

        const res = await postAuthnRequest({ id: "_ent_forge", loggedIn: true, assignUser: true });
        const xml = decodeSamlResponse(extractSamlResponseFromForm(await res.text()));

        expect(xml).toContain(">site.read<");
        expect(xml).not.toContain("plan.approve_own");
        expect(xml).not.toContain(">admin<");
        expect(xml).toContain(">kept<"); // 예약되지 않은 키는 그대로
    });
});
