import { dev } from "$app/environment";
import { and, eq } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { signingKeys, type Tenant, tenants } from "$lib/server/db/schema";
import { DEFAULT_TENANT_SLUG } from "./constants";
import { getRuntimeConfig, type RuntimeConfig } from "./runtime";
import { generateRsaSigningKey, generateSelfSignedCert, tryWithSecrets, unwrapPrivateKey, wrapPrivateKey } from "$lib/server/crypto/keys";

function isUniqueConstraintError(error: unknown): boolean {
    return error instanceof Error && /unique constraint failed/i.test(error.message);
}

export async function ensureDefaultTenant(db: DB, platform: App.Platform | undefined): Promise<Tenant> {
    const [existingTenant] = await db.select().from(tenants).where(eq(tenants.slug, DEFAULT_TENANT_SLUG)).limit(1);

    if (existingTenant) {
        return existingTenant;
    }

    try {
        await db.insert(tenants).values({
            id: crypto.randomUUID(),
            slug: DEFAULT_TENANT_SLUG,
            name: getRuntimeConfig(platform).defaultTenantName,
            status: "active",
        });
    } catch (error) {
        if (!isUniqueConstraintError(error)) {
            throw error;
        }
    }

    const [tenant] = await db.select().from(tenants).where(eq(tenants.slug, DEFAULT_TENANT_SLUG)).limit(1);

    if (!tenant) {
        throw new Error("기본 tenant 를 초기화하지 못했습니다.");
    }

    return tenant;
}

export async function ensureSigningKey(db: DB, tenant: Tenant, signingKeySecrets: string[], issuerUrl?: string): Promise<void> {
    // SAML KeyDescriptor 용 CN
    let cn = "idp";
    if (issuerUrl) {
        try {
            cn = new URL(issuerUrl).hostname;
        } catch {
            cn = issuerUrl;
        }
    }

    const [existing] = await db
        .select()
        .from(signingKeys)
        .where(and(eq(signingKeys.tenantId, tenant.id), eq(signingKeys.active, true)))
        .limit(1);

    // 키가 있지만 cert_pem 이 없는 경우 (M1 → M2 업그레이드): backfill
    if (existing) {
        if (!existing.certPem) {
            // 무보호 예외 지점: 무중단 회전 창에서 previous 로 래핑된 키도 복호되도록 fallback.
            const privateKey = await tryWithSecrets(signingKeySecrets, (s) => unwrapPrivateKey(existing.privateJwkEncrypted, s));
            const publicJwk = JSON.parse(existing.publicJwk) as JsonWebKey;
            const publicKey = await crypto.subtle.importKey("jwk", publicJwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, true, ["verify"]);
            const certPem = await generateSelfSignedCert(publicKey, privateKey, cn);
            await db.update(signingKeys).set({ certPem }).where(eq(signingKeys.id, existing.id));
        }
        return;
    }

    const { kid, publicKey, privateKey, publicJwk } = await generateRsaSigningKey();
    // 발급/암호화는 항상 current(=secrets[0])만 사용한다. previous fallback 금지.
    const privateJwkEncrypted = await wrapPrivateKey(privateKey, signingKeySecrets[0]);
    const certPem = await generateSelfSignedCert(publicKey, privateKey, cn);

    await db.insert(signingKeys).values({
        id: crypto.randomUUID(),
        tenantId: tenant.id,
        kid,
        use: "sig",
        alg: "RS256",
        publicJwk: JSON.stringify(publicJwk),
        privateJwkEncrypted,
        certPem,
        active: true,
    });
}

/**
 * S5 fail-fast: 프로덕션 필수 환경변수 검증.
 *
 * `IDP_ISSUER_URL` / `IDP_SIGNING_KEY_SECRET` 는 프로덕션에서 반드시 설정되어야
 * 한다. 미설정이면 토큰 발급 시점(ensureSigningKey 조용한 스킵, resolveIssuerUrl
 * Host fallback)이 아니라 요청 초기(ensureAuthBaseline) 에 명확한 오류로 실패시켜
 * 오구성을 즉시 드러낸다.
 *
 * dev 에서는 로컬 DX(변수 없이 구동) 보존을 위해 검증을 건너뛴다.
 *
 * 검증 결과는 성공 시 1회만 계산되도록 캐시한다(설정은 isolate 수명 내 불변).
 * 실패 시 캐시하지 않으므로 요청마다 재검증되어 fail-closed 를 유지한다.
 */
let requiredConfigValidated = false;
function assertRequiredConfig(config: RuntimeConfig): void {
    if (dev || requiredConfigValidated) return;

    const missing: string[] = [];
    if (!config.issuerUrl) missing.push("IDP_ISSUER_URL");
    if (!config.signingKeySecret) missing.push("IDP_SIGNING_KEY_SECRET");

    if (missing.length > 0) {
        throw new Error(`프로덕션 필수 환경변수가 설정되지 않았습니다: ${missing.join(", ")}. 배포 환경 변수/시크릿을 확인해 주세요.`);
    }

    requiredConfigValidated = true;
}

const BASELINE_TTL_MS = 5 * 60 * 1000; // 5분

interface BaselineCache {
    tenant: Tenant;
    expiresAt: number;
}

// Workers isolate 레벨 tenant별 캐시 — 멀티테넌트 요청이 서로의 baseline을 재사용하지 않는다.
const g = globalThis as typeof globalThis & { __idpBaselineCache?: Map<string, BaselineCache> };

function runtimeString(platform: App.Platform | undefined, key: string): string | undefined {
    const platformValue = (platform?.env as Record<string, unknown> | undefined)?.[key];
    if (typeof platformValue === "string" && platformValue.length > 0) return platformValue;
    const nodeValue = typeof process !== "undefined" ? process.env[key] : undefined;
    return nodeValue && nodeValue.length > 0 ? nodeValue : undefined;
}

/**
 * Tenant 식별 규칙:
 * - 명시적 경로: `/t/<slug>/...`
 * - 서브도메인: `IDP_TENANT_BASE_DOMAIN=example.com`이면 `<slug>.example.com`
 * 둘이 동시에 주어지면 반드시 같은 slug여야 하며, 불일치 시 fail-closed 한다.
 */
export function resolveTenantSlug(url: URL, platform?: App.Platform): string {
    const pathMatch = /^\/t\/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)(?:\/|$)/i.exec(url.pathname);
    const pathSlug = pathMatch?.[1]?.toLowerCase();

    const baseDomain = runtimeString(platform, "IDP_TENANT_BASE_DOMAIN")
        ?.toLowerCase()
        .replace(/^\.+|\.+$/g, "");
    let hostSlug: string | undefined;
    if (baseDomain && url.hostname.toLowerCase().endsWith(`.${baseDomain}`)) {
        const prefix = url.hostname.slice(0, -(baseDomain.length + 1));
        if (prefix && !prefix.includes(".")) hostSlug = prefix.toLowerCase();
    }

    if (pathSlug && hostSlug && pathSlug !== hostSlug) {
        throw new Error(`tenant 경로와 호스트의 tenant가 일치하지 않습니다: ${pathSlug} != ${hostSlug}`);
    }
    return pathSlug ?? hostSlug ?? DEFAULT_TENANT_SLUG;
}

export async function ensureAuthBaseline(db: DB, platform: App.Platform | undefined, requestUrl?: URL) {
    const now = Date.now();
    const tenantSlug = requestUrl ? resolveTenantSlug(requestUrl, platform) : DEFAULT_TENANT_SLUG;
    const cache = g.__idpBaselineCache ?? (g.__idpBaselineCache = new Map<string, BaselineCache>());
    const cached = cache.get(tenantSlug);

    if (cached && cached.expiresAt > now) {
        return cached.tenant;
    }

    const config = getRuntimeConfig(platform);
    // 프로덕션 필수값 검증 — DB 작업 전에 요청 초기에 fail-fast.
    assertRequiredConfig(config);
    let [tenant] = await db.select().from(tenants).where(eq(tenants.slug, tenantSlug)).limit(1);
    if (!tenant && tenantSlug === DEFAULT_TENANT_SLUG) {
        tenant = await ensureDefaultTenant(db, platform);
    }
    if (!tenant || tenant.status !== "active") {
        throw new Error(`요청한 tenant를 찾을 수 없거나 비활성 상태입니다: ${tenantSlug}`);
    }
    if (config.signingKeySecrets.length > 0) {
        await ensureSigningKey(db, tenant, config.signingKeySecrets, config.issuerUrl);
    }

    cache.set(tenantSlug, { tenant, expiresAt: now + BASELINE_TTL_MS });
    return tenant;
}
