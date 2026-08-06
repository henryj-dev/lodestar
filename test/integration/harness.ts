/**
 * Phase 11 통합 테스트 하네스.
 *
 * 목적: mock 이 아닌 **실제 DB**(libSQL `:memory:`) 위에 **실제 drizzle 스키마 마이그레이션**을
 * 적용하고, 실제 서버 모듈(auth/oidc/route 핸들러)을 직접 구동해 풀플로우를 검증한다.
 *
 * 핵심 구성:
 *  1. openMemoryDb(): libSQL `:memory:` 클라이언트 + drizzle 인스턴스를 만들고
 *     `drizzle/sqlite/*.sql` 을 journal 순서대로 적용한다(scripts/lib/db.ts 의 executeMultiple 패턴).
 *  2. makeEvent(): 라우트 핸들러(+server.ts / +page.server.ts)가 기대하는 RequestEvent/locals 를
 *     최소 구성으로 조립한다(db·tenant·session·user·runtimeConfig·platform·cookies·locale).
 *  3. 시드 유틸: 테넌트/서명키/유저/OIDC 클라이언트/서비스 할당/세션.
 *
 * 격리: 케이스마다 새 인메모리 DB(= 새 tenantId)를 만든다. 서명키/JWKS/baseline 은
 * globalThis 캐시를 쓰므로 tenantId 가 달라 케이스 간 오염이 없다(추가로 서명키 캐시는
 * invalidate 유틸을 노출한다).
 */

import "reflect-metadata";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { eq } from "drizzle-orm";
import * as x509 from "@peculiar/x509";
import { X509Certificate } from "@peculiar/x509";
import type { RequestEvent } from "@sveltejs/kit";
import type { DB } from "$lib/server/db";
import {
    credentials,
    identityProviders,
    oidcClients,
    samlSps,
    serviceEntitlements,
    sessions,
    tenants,
    userServiceAssignments,
    userServiceEntitlements,
    users,
    type IdentityProvider,
    type SamlSp,
    type Session,
    type Tenant,
    type User,
} from "$lib/server/db/schema";
import { ensureDefaultTenant, ensureSigningKey } from "$lib/server/auth/bootstrap";
import { getRuntimeConfig, type RuntimeConfig } from "$lib/server/auth/runtime";
import { hashPassword } from "$lib/server/auth/password";
import { hashClientSecret } from "$lib/server/oidc/client";
import { createSessionRecord } from "$lib/server/auth/session";
import { b64uEncode, getActiveSigningKey } from "$lib/server/crypto/keys";
import { DbRateLimitStore } from "$lib/server/ratelimit";
import { ensureXmlEngine, xmldsigjs, XMLSerializer } from "$lib/server/saml/xml-setup";

// ── 테스트용 마스터 시크릿 / issuer ────────────────────────────────────────────────
// 실 서명·암호화 경로가 이 값을 사용한다. platform.env 로 주입해 getRuntimeConfig 가 읽는다.
export const TEST_SIGNING_SECRET = "test-signing-secret-current-abcdefghijklmnopqrstuvwxyz-0123456789";
export const TEST_SIGNING_SECRET_PREVIOUS = "test-signing-secret-previous-ABCDEFGHIJKLMNOPQRSTUVWXYZ-9876543210";
export const TEST_ISSUER_URL = "https://idp.test.example";

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const migrationsDir = join(projectRoot, "drizzle", "sqlite");

interface JournalEntry {
    idx: number;
    tag: string;
}

/** _journal.json 을 읽어 마이그레이션 태그를 idx 오름차순으로 반환한다. */
function migrationTags(): string[] {
    const journalPath = join(migrationsDir, "meta", "_journal.json");
    const journal = JSON.parse(readFileSync(journalPath, "utf-8")) as { entries: JournalEntry[] };
    return [...journal.entries].sort((a, b) => a.idx - b.idx).map((e) => e.tag);
}

export interface MemoryDb {
    db: DB;
    client: Client;
    /** platform.env 로 넘길 환경. getRuntimeConfig 가 읽는다. */
    env: Record<string, string>;
    close(): void;
}

/**
 * libSQL `:memory:` DB 를 만들고 실제 마이그레이션(SQL)을 순서대로 적용한다.
 * executeMultiple 은 `;` 로 구분된 여러 문장을 한 번에 실행한다(마이그레이션 파일 통째 적용).
 */
export async function openMemoryDb(envOverrides: Record<string, string> = {}): Promise<MemoryDb> {
    const client = createClient({ url: ":memory:" });
    for (const tag of migrationTags()) {
        const sqlText = readFileSync(join(migrationsDir, `${tag}.sql`), "utf-8");
        await client.executeMultiple(sqlText);
    }
    // 앱 런타임과 동일하게 FK 제약을 활성화한다(마이그레이션 DDL 적용 이후).
    await client.execute("PRAGMA foreign_keys = ON");

    const db = drizzle(client, { schema: { tenants, users, credentials, sessions, oidcClients, userServiceAssignments } }) as unknown as DB;

    const env: Record<string, string> = {
        IDP_ISSUER_URL: TEST_ISSUER_URL,
        IDP_SIGNING_KEY_SECRET: TEST_SIGNING_SECRET,
        IDP_DEFAULT_TENANT_NAME: "Test Tenant",
        ...envOverrides,
    };

    return {
        db,
        client,
        env,
        close() {
            client.close();
        },
    };
}

// ── 테스트용 platform / RequestEvent ────────────────────────────────────────────────

/** getRuntimeConfig 가 읽는 최소 platform. ctx 는 없음(=Node 경로, waitUntil 미노출). */
export function makePlatform(env: Record<string, string>): App.Platform {
    return { env } as unknown as App.Platform;
}

/** Map 기반 최소 Cookies 스텁. 라우트가 set/get/delete 하는 세션·MFA 쿠키를 담는다. */
export function makeCookies(initial: Record<string, string> = {}) {
    const store = new Map<string, string>(Object.entries(initial));
    return {
        get: (name: string) => store.get(name),
        getAll: () => Array.from(store.entries()).map(([name, value]) => ({ name, value })),
        set: (name: string, value: string) => {
            store.set(name, value);
        },
        delete: (name: string) => {
            store.delete(name);
        },
        serialize: () => "",
        _store: store,
    };
}

export interface MakeEventOptions {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    /** application/x-www-form-urlencoded 폼 본문(POST 액션/토큰 엔드포인트용). */
    /** 값에 배열을 주면 같은 이름으로 반복 전송된다(체크박스 그룹 → formData.getAll). */
    form?: Record<string, string | string[]>;
    /** JSON 본문(service API 등 request.json() 을 쓰는 핸들러용). form 과 함께 쓰지 않는다. */
    json?: unknown;
    locals: {
        db: DB;
        tenant: Tenant | null;
        user?: User | null;
        session?: Session | null;
        locale?: string;
        env: Record<string, string>;
    };
    cookies?: ReturnType<typeof makeCookies>;
}

/**
 * 실제 라우트 핸들러가 소비하는 RequestEvent 를 조립한다.
 * 핸들러가 실제로 접근하는 필드(request/url/locals/platform/cookies/getClientAddress)만 채운다.
 *
 * 반환 타입은 `RequestEvent<never, never>` 로 둔다. 각 라우트 핸들러는 `./$types` 로
 * RouteId/RouteParams 가 좁혀진 `RequestEvent<RouteParams, "/oidc/token">` 등을 파라미터로
 * 받는데, `never` 는 모든 리터럴에 대입 가능하므로 어떤 라우트 핸들러에도 그대로 넘길 수 있다.
 */
export function makeEvent(opts: MakeEventOptions): RequestEvent<never, never> {
    const method = opts.method ?? "GET";
    const url = new URL(opts.url ?? "https://idp.test.example/");
    const headers = new Headers(opts.headers ?? {});

    let body: BodyInit | undefined;
    if (opts.form) {
        const params = new URLSearchParams();
        for (const [k, v] of Object.entries(opts.form)) {
            if (Array.isArray(v)) for (const item of v) params.append(k, item);
            else params.append(k, v);
        }
        body = params;
        if (!headers.has("content-type")) headers.set("content-type", "application/x-www-form-urlencoded");
    } else if (opts.json !== undefined) {
        body = JSON.stringify(opts.json);
        if (!headers.has("content-type")) headers.set("content-type", "application/json");
    }
    const request = new Request(url.toString(), { method, headers, body });

    const platform = makePlatform(opts.locals.env);
    const runtimeConfig: RuntimeConfig = getRuntimeConfig(platform);
    const cookies = opts.cookies ?? makeCookies();

    const locals: App.Locals = {
        db: opts.locals.db,
        // 테스트 DB(요청별 격리)로 DbRateLimitStore 를 주입 — 프로덕션 Workers 경로와 동일.
        rateLimitStore: new DbRateLimitStore(opts.locals.db),
        tenant: opts.locals.tenant,
        user: opts.locals.user ?? null,
        session: opts.locals.session ?? null,
        runtimeConfig,
        runtimeError: null,
        locale: (opts.locals.locale ?? "ko") as App.Locals["locale"],
    };

    return {
        request,
        url,
        locals,
        platform,
        cookies,
        params: {},
        route: { id: null },
        getClientAddress: () => "127.0.0.1",
        setHeaders: () => {},
        isDataRequest: false,
        isSubRequest: false,
        fetch: globalThis.fetch,
    } as unknown as RequestEvent<never, never>;
}

// ── 시드 유틸 ────────────────────────────────────────────────────────────────────

/** 기본 테넌트 + 활성 서명키(실 RSA 키·cert)를 생성한다. */
export async function seedTenantAndSigningKey(mem: MemoryDb): Promise<Tenant> {
    const platform = makePlatform(mem.env);
    const config = getRuntimeConfig(platform);
    const tenant = await ensureDefaultTenant(mem.db, platform);
    await ensureSigningKey(mem.db, tenant, config.signingKeySecrets, config.issuerUrl);
    return tenant;
}

export interface SeedUserOptions {
    tenantId: string;
    email: string;
    username?: string | null;
    password?: string;
    role?: "admin" | "user";
    status?: "active" | "disabled" | "locked" | "deletion_pending";
    emailVerifiedAt?: Date | null;
    displayName?: string;
    deletionScheduledAt?: Date | null;
}

/** 유저를 생성하고, password 가 주어지면 password credential 도 함께 생성한다. */
export async function seedUser(db: DB, opts: SeedUserOptions): Promise<User> {
    const id = crypto.randomUUID();
    await db.insert(users).values({
        id,
        tenantId: opts.tenantId,
        email: opts.email.toLowerCase(),
        username: opts.username === undefined ? opts.email.split("@")[0] : opts.username,
        displayName: opts.displayName ?? "Test User",
        role: opts.role ?? "user",
        status: opts.status ?? "active",
        emailVerifiedAt: opts.emailVerifiedAt === undefined ? new Date() : opts.emailVerifiedAt,
        deletionScheduledAt: opts.deletionScheduledAt ?? null,
    });

    if (opts.password) {
        await db.insert(credentials).values({
            id: crypto.randomUUID(),
            userId: id,
            type: "password",
            secret: await hashPassword(opts.password),
            label: "비밀번호",
        });
    }

    const [row] = await db.select().from(users).where(eq(users.id, id)).limit(1);
    return row!;
}

export interface SeedOidcClientOptions {
    tenantId: string;
    clientId: string;
    secret?: string;
    redirectUris: string[];
    scopes?: string;
    grantTypes?: string;
    tokenEndpointAuthMethod?: "client_secret_basic" | "client_secret_post" | "none";
    requirePkce?: boolean;
    requireVerifiedEmail?: boolean;
    allowAllUsers?: boolean;
}

export async function seedOidcClient(db: DB, opts: SeedOidcClientOptions): Promise<typeof oidcClients.$inferSelect> {
    const id = crypto.randomUUID();
    await db.insert(oidcClients).values({
        id,
        tenantId: opts.tenantId,
        clientId: opts.clientId,
        clientSecretHash: opts.secret ? await hashClientSecret(opts.secret) : null,
        name: opts.clientId,
        redirectUris: JSON.stringify(opts.redirectUris),
        scopes: opts.scopes ?? "openid profile email offline_access",
        grantTypes: opts.grantTypes ?? "authorization_code,refresh_token",
        tokenEndpointAuthMethod: opts.tokenEndpointAuthMethod ?? "client_secret_basic",
        requirePkce: opts.requirePkce ?? true,
        requireVerifiedEmail: opts.requireVerifiedEmail ?? false,
        allowAllUsers: opts.allowAllUsers ?? false,
        enabled: true,
    });
    const [row] = await db.select().from(oidcClients).where(eq(oidcClients.id, id)).limit(1);
    return row!;
}

/**
 * 유저에게 서비스(OIDC/SAML) 접근 권한을 부여한다(기본 deny 를 통과시키기 위함).
 * 생성된 assignment id 를 돌려준다 — entitlement 부여가 이 id 를 FK 로 참조한다.
 */
export async function seedServiceAssignment(db: DB, args: { tenantId: string; userId: string; serviceType: "oidc" | "saml"; serviceRefId: string; attributesJson?: string }): Promise<string> {
    const id = crypto.randomUUID();
    await db.insert(userServiceAssignments).values({
        id,
        tenantId: args.tenantId,
        userId: args.userId,
        serviceType: args.serviceType,
        serviceRefId: args.serviceRefId,
        attributesJson: args.attributesJson ?? null,
    });
    return id;
}

/** 서비스가 정의하는 권한(entitlement) 키를 하나 만든다. 생성된 id 를 돌려준다. */
export async function seedServiceEntitlement(
    db: DB,
    args: { tenantId: string; serviceType: "oidc" | "saml"; serviceRefId: string; key: string; label?: string; displayOrder?: number },
): Promise<string> {
    const id = crypto.randomUUID();
    await db.insert(serviceEntitlements).values({
        id,
        tenantId: args.tenantId,
        serviceType: args.serviceType,
        serviceRefId: args.serviceRefId,
        key: args.key,
        label: args.label ?? args.key,
        displayOrder: args.displayOrder ?? 0,
    });
    return id;
}

/** 배정에 권한을 부여한다. expiresAt 을 과거로 주면 만료된 부여를 만들 수 있다. */
export async function grantEntitlement(db: DB, args: { tenantId: string; assignmentId: string; serviceEntitlementId: string; expiresAt?: Date }): Promise<void> {
    await db.insert(userServiceEntitlements).values({
        id: crypto.randomUUID(),
        tenantId: args.tenantId,
        assignmentId: args.assignmentId,
        serviceEntitlementId: args.serviceEntitlementId,
        expiresAt: args.expiresAt ?? null,
    });
}

/** 실제 createSessionRecord 로 세션을 만들고 raw 토큰 + Session row 를 돌려준다. */
export async function seedSession(db: DB, args: { tenantId: string; userId: string }): Promise<{ session: Session; sessionToken: string }> {
    const { sessionToken, sessionId } = await createSessionRecord(db, {
        tenantId: args.tenantId,
        userId: args.userId,
        amr: ["pwd"],
        acr: "urn:mace:incommon:iap:silver",
    });
    const [session] = await db.select().from(sessions).where(eq(sessions.id, sessionId)).limit(1);
    return { session: session!, sessionToken };
}

// ── 헬퍼: PKCE / redirect 파싱 ─────────────────────────────────────────────────────

/** S256 code_challenge 를 계산한다(실 라우트/pkce.ts 와 동일 알고리즘). */
export async function pkceChallengeS256(verifier: string): Promise<string> {
    const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return b64uEncode(hash);
}

/** throw 된 SvelteKit redirect 를 잡아 Location 을 반환한다. redirect 가 아니면 재throw. */
export async function catchRedirect(fn: () => unknown): Promise<{ status: number; location: string }> {
    try {
        await fn();
    } catch (e) {
        const r = e as { status?: number; location?: string };
        if (typeof r.status === "number" && typeof r.location === "string") {
            return { status: r.status, location: r.location };
        }
        throw e;
    }
    throw new Error("redirect 가 발생하지 않았습니다.");
}

/** throw 된 SvelteKit error() 를 잡아 { status, body } 를 반환한다. error 가 아니면 재throw. */
export async function catchError(fn: () => unknown): Promise<{ status: number; body: unknown }> {
    try {
        await fn();
    } catch (e) {
        const r = e as { status?: number; body?: unknown };
        if (typeof r.status === "number" && "body" in (e as object)) {
            return { status: r.status, body: r.body };
        }
        throw e;
    }
    throw new Error("error() 가 발생하지 않았습니다.");
}

// ── 쿠키 체이닝 헬퍼 ───────────────────────────────────────────────────────────────
// 같은 브라우저(쿠키 저장소)로 여러 라우트를 연속 호출하는 흐름(login → mfa, POST/saml/sso →
// 로그인 후 재개)을 재현하기 위해, 하나의 makeCookies 인스턴스를 여러 makeEvent 에 재사용한다.

/** 동일 쿠키 저장소를 여러 makeEvent 에 재사용하는 세션(브라우저) 헬퍼. */
export function makeCookieJar(initial: Record<string, string> = {}) {
    const cookies = makeCookies(initial);
    return {
        cookies,
        /** 현재 저장소에 담긴 쿠키명→값 스냅샷. */
        snapshot: () => Object.fromEntries(cookies._store.entries()) as Record<string, string>,
        /** 특정 쿠키 값 조회(없으면 undefined). */
        get: (name: string) => cookies.get(name),
        /** 저장된 쿠키가 하나라도 있는지. */
        has: (name: string) => cookies._store.has(name),
    };
}

// ── SAML 서명 fixture (saml-verify-xml-signature.test.ts 에서 승격·공용화) ─────────────

const SAML_RSA_ALG: RsaHashedKeyGenParams = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
};

export interface KeyCert {
    keys: CryptoKeyPair;
    certPem: string;
    certB64: string;
}

/** 자체서명 RSA 키/인증서 쌍을 만든다(SP AuthnRequest 서명·SP cert 등록용). */
export async function makeKeyCert(cn: string): Promise<KeyCert> {
    x509.cryptoProvider.set(crypto as Crypto);
    const keys = (await crypto.subtle.generateKey(SAML_RSA_ALG, true, ["sign", "verify"])) as CryptoKeyPair;
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: "01",
        name: `CN=${cn}`,
        notBefore: new Date("2020-01-01T00:00:00Z"),
        notAfter: new Date("2035-01-01T00:00:00Z"),
        signingAlgorithm: SAML_RSA_ALG,
        keys,
    });
    const certPem = cert.toString("pem");
    const certB64 = certPem
        .replace(/-----BEGIN CERTIFICATE-----/, "")
        .replace(/-----END CERTIFICATE-----/, "")
        .replace(/\s+/g, "");
    return { keys, certPem, certB64 };
}

export interface SignAuthnRequestOptions {
    id: string;
    kc: KeyCert;
    issuer: string;
    destination: string;
    acsUrl: string;
    /** true 이면 enveloped ds:Signature 를 붙인다. false 면 서명 없는 XML 을 반환한다. */
    sign?: boolean;
    forceAuthn?: boolean;
}

/**
 * SP-initiated AuthnRequest XML 을 만든다. sign=true 면 SP 개인키로 enveloped ds:Signature 를
 * <saml:Issuer> 바로 뒤에 삽입한다(response.ts 서명 생성과 동일 방식). IssueInstant 는 현재
 * 시각(±5분 skew 검증 통과)을 쓴다.
 */
export async function buildAuthnRequestXml(opts: SignAuthnRequestOptions): Promise<string> {
    ensureXmlEngine();
    const issueInstant = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const forceAuthnAttr = opts.forceAuthn ? ` ForceAuthn="true"` : "";
    const fullXml =
        `<samlp:AuthnRequest` +
        ` xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
        ` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
        ` ID="${opts.id}" Version="2.0" IssueInstant="${issueInstant}"` +
        forceAuthnAttr +
        ` Destination="${opts.destination}"` +
        ` AssertionConsumerServiceURL="${opts.acsUrl}">` +
        `<saml:Issuer>${opts.issuer}</saml:Issuer>` +
        `</samlp:AuthnRequest>`;

    if (!opts.sign) return fullXml;

    const doc = xmldsigjs.Parse(fullXml);
    const rootEl = doc.documentElement as Element & { setIdAttribute?: (name: string, flag: boolean) => void };
    rootEl.setIdAttribute?.("ID", true);

    const signedXml = new xmldsigjs.SignedXml();
    signedXml.XmlSignature.SignedInfo.CanonicalizationMethod.Algorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    await signedXml.Sign({ name: "RSASSA-PKCS1-v1_5" }, opts.kc.keys.privateKey, doc, {
        x509: [opts.kc.certB64],
        references: [{ uri: `#${opts.id}`, hash: "SHA-256", transforms: ["enveloped", "exc-c14n"] }],
    });

    const sigNode = signedXml.XmlSignature.GetXml();
    if (sigNode) {
        const issuerEls = rootEl.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer");
        const issuerEl = issuerEls[0];
        if (issuerEl?.nextSibling) {
            rootEl.insertBefore(sigNode, issuerEl.nextSibling);
        } else {
            rootEl.appendChild(sigNode);
        }
    }
    return xmldsigjs.Stringify(doc).replace(/^<\?xml[^?]*\?>\s*/i, "");
}

/** HTTP-POST 바인딩용 SAMLRequest 파라미터 값(base64(XML), deflate 없음)을 만든다. */
export function encodePostBindingSamlRequest(xml: string): string {
    const bytes = new TextEncoder().encode(xml);
    const binary = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
    return btoa(binary);
}

/** base64(SAMLResponse) 를 디코드해 XML 문자열로 돌려준다(auto-submit 폼 검증용). */
export function decodeSamlResponse(b64: string): string {
    const raw = atob(b64);
    const bin = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bin[i] = raw.charCodeAt(i);
    return new TextDecoder().decode(bin);
}

/**
 * SAML Response XML 에서 서명된 <saml:Assertion> 을 자족적 문서로 추출한다.
 * (직렬화 검사·디버깅용. 서명 재검증은 verifyAssertionSignatureInResponse 를 쓴다.)
 */
export function extractSignedAssertionXml(responseXml: string): string | null {
    ensureXmlEngine();
    const doc = xmldsigjs.Parse(responseXml);
    const assertionEls = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
    const assertionEl = assertionEls[0];
    if (!assertionEl) return null;
    assertionEl.setAttribute("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion");
    assertionEl.setAttribute("xmlns:xs", "http://www.w3.org/2001/XMLSchema");
    assertionEl.setAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
    const serializer = new XMLSerializer();
    return serializer.serializeToString(assertionEl as unknown as Parameters<typeof serializer.serializeToString>[0]);
}

const XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
const SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

/**
 * SAML Response XML 안의 <saml:Assertion> enveloped 서명을 주어진 인증서 공개키로 **in-place**
 * 검증한다. Response 문서 컨텍스트 안에서 검증하므로(추출/재직렬화 없이) 서명 시점과 동일한
 * exc-c14n 네임스페이스 컨텍스트를 본다 — SP 가 실제로 수행하는 검증과 동일한 방식.
 * 서명 불일치·변조·형식 위반 시 false 를 반환한다.
 */
export async function verifyAssertionSignatureInResponse(responseXml: string, certPem: string): Promise<boolean> {
    try {
        if (!certPem) return false;
        ensureXmlEngine();
        const doc = xmldsigjs.Parse(responseXml);
        const assertionEl = doc.getElementsByTagNameNS(SAML_ASSERTION_NS, "Assertion")[0] as (Element & { setIdAttribute?: (n: string, f: boolean) => void }) | undefined;
        if (!assertionEl) return false;
        assertionEl.setIdAttribute?.("ID", true);
        const sigEl = assertionEl.getElementsByTagNameNS(XMLDSIG_NS, "Signature")[0];
        if (!sigEl || sigEl.parentNode !== assertionEl) return false;
        const cert = new X509Certificate(certPem);
        const publicKey = await crypto.subtle.importKey("spki", cert.publicKey.rawData, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, true, ["verify"]);
        const signedXml = new xmldsigjs.SignedXml(doc);
        signedXml.LoadXml(sigEl);
        return await signedXml.Verify(publicKey);
    } catch {
        return false;
    }
}

// ── SAML SP / LDAP provider 시드 ──────────────────────────────────────────────────

export interface SeedSamlSpOptions {
    tenantId: string;
    entityId: string;
    acsUrl: string;
    name?: string;
    cert?: string | null;
    nameIdFormat?: string;
    signResponse?: boolean;
    signAssertion?: boolean;
    encryptAssertion?: boolean;
    wantAuthnRequestsSigned?: boolean;
    requireVerifiedEmail?: boolean;
    allowedAttributes?: string[] | null;
    attributeMappingJson?: string | null;
    allowAllUsers?: boolean;
    enabled?: boolean;
}

/** SAML SP(Service Provider) 레코드를 삽입한다. */
export async function seedSamlSp(db: DB, opts: SeedSamlSpOptions): Promise<SamlSp> {
    const id = crypto.randomUUID();
    await db.insert(samlSps).values({
        id,
        tenantId: opts.tenantId,
        entityId: opts.entityId,
        name: opts.name ?? opts.entityId,
        acsUrl: opts.acsUrl,
        cert: opts.cert ?? null,
        nameIdFormat: opts.nameIdFormat ?? "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        signResponse: opts.signResponse ?? true,
        signAssertion: opts.signAssertion ?? true,
        encryptAssertion: opts.encryptAssertion ?? false,
        wantAuthnRequestsSigned: opts.wantAuthnRequestsSigned ?? false,
        requireVerifiedEmail: opts.requireVerifiedEmail ?? false,
        allowedAttributes: opts.allowedAttributes === undefined ? null : opts.allowedAttributes ? JSON.stringify(opts.allowedAttributes) : null,
        attributeMappingJson: opts.attributeMappingJson ?? null,
        allowAllUsers: opts.allowAllUsers ?? false,
        enabled: opts.enabled ?? true,
    });
    const [row] = await db.select().from(samlSps).where(eq(samlSps.id, id)).limit(1);
    return row!;
}

export interface SeedIdentityProviderOptions {
    tenantId: string;
    kind?: "ldap" | "oidc" | "saml" | "oauth2";
    name?: string;
    /** config_json 에 직렬화될 provider 설정(LDAP 는 LdapProviderConfig). */
    config?: Record<string, unknown>;
    enabled?: boolean;
}

/** identity_providers 레코드(기본 LDAP)를 삽입한다. */
export async function seedIdentityProvider(db: DB, opts: SeedIdentityProviderOptions): Promise<IdentityProvider> {
    const id = crypto.randomUUID();
    await db.insert(identityProviders).values({
        id,
        tenantId: opts.tenantId,
        kind: opts.kind ?? "ldap",
        name: opts.name ?? "Test LDAP",
        configJson: opts.config ? JSON.stringify(opts.config) : null,
        enabled: opts.enabled ?? true,
    });
    const [row] = await db.select().from(identityProviders).where(eq(identityProviders.id, id)).limit(1);
    return row!;
}

/** 현재 활성 IdP 서명키의 인증서(PEM)를 반환한다(SAML Response 서명 검증용). */
export async function getIdpSigningCertPem(mem: MemoryDb, tenantId: string): Promise<string> {
    const config = getRuntimeConfig(makePlatform(mem.env));
    const key = await getActiveSigningKey(mem.db, tenantId, config.signingKeySecrets);
    if (!key?.certPem) throw new Error("활성 IdP 서명키 인증서가 없습니다.");
    return key.certPem;
}
