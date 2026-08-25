import { dev } from "$app/environment";
import { error } from "@sveltejs/kit";

export interface RuntimeConfig {
    defaultTenantName: string;
    issuerUrl?: string;
    /**
     * 마스터 서명/암호화 시크릿의 **current** 값(=`signingKeySecrets[0]`).
     * 발급/암호화(토큰 서명, private key 래핑, 시크릿·TOTP 암호화, 쿠키·audit 서명)는
     * **반드시 이 값(current)만** 사용한다. 미설정이면 undefined.
     */
    signingKeySecret?: string;
    /**
     * 무중단 회전용 시크릿 목록. `[current]` 또는 `[current, previous]`.
     * **복호/검증 경로만** 이 배열을 current→previous 순차로 시도한다(`tryWithSecrets`).
     * 미설정이면 빈 배열. `IDP_SIGNING_KEY_SECRET_PREVIOUS` 로 previous 를 주입한다.
     */
    signingKeySecrets: string[];
    /**
     * stardust dispatcher 가 idp 의 /api/totp/* 를 호출할 때 사용하는 service token.
     * Authorization: Bearer <token> 헤더로 검증. 단일 fixed token (rotation 은 수동).
     * 미설정이면 /api/totp/* 라우트 503 반환 (개발 안전).
     */
    dispatcherServiceToken?: string;
    /** Tenant issuer strategy: shared (legacy), host, or path. */
    tenantIssuerMode: "shared" | "host" | "path";
    tenantBaseDomain?: string;
}

type EnvLookup = Record<string, unknown>;

function readString(env: EnvLookup | undefined, key: string): string | undefined {
    const value = env?.[key];
    return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function getRuntimeConfig(platform: App.Platform | undefined): RuntimeConfig {
    const platformEnv = platform?.env as EnvLookup | undefined;
    // Cloudflare 에서는 platform.env, 순수 Node(adapter-node)에서는 process.env 로 설정을 읽는다.
    const nodeEnv = typeof process !== "undefined" ? (process.env as EnvLookup) : undefined;
    const getString = (key: string): string | undefined => readString(platformEnv, key) ?? readString(nodeEnv, key);

    // 무중단 회전: current(=IDP_SIGNING_KEY_SECRET) 를 [0], previous 를 [1] 로 둔다.
    // - current 미설정이면 secrets 는 빈 배열(previous 단독으로는 발급/검증하지 않는다).
    // - previous 가 current 와 동일하거나 미설정이면 length 1 → 기존과 동일 동작(회귀 0).
    const signingKeyCurrent = getString("IDP_SIGNING_KEY_SECRET");
    const signingKeyPrevious = getString("IDP_SIGNING_KEY_SECRET_PREVIOUS");
    const signingKeySecrets = signingKeyCurrent ? (signingKeyPrevious && signingKeyPrevious !== signingKeyCurrent ? [signingKeyCurrent, signingKeyPrevious] : [signingKeyCurrent]) : [];

    return {
        defaultTenantName: getString("IDP_DEFAULT_TENANT_NAME") ?? "Default Tenant",
        issuerUrl: getString("IDP_ISSUER_URL")?.trim().replace(/\/$/, ""),
        signingKeySecret: signingKeyCurrent,
        signingKeySecrets,
        dispatcherServiceToken: getString("DISPATCHER_SERVICE_TOKEN"),
        tenantIssuerMode: getString("IDP_TENANT_ISSUER_MODE") === "host" || getString("IDP_TENANT_ISSUER_MODE") === "path" ? (getString("IDP_TENANT_ISSUER_MODE") as "host" | "path") : "shared",
        tenantBaseDomain: getString("IDP_TENANT_BASE_DOMAIN")
            ?.toLowerCase()
            .replace(/^\.+|\.+$/g, ""),
    };
}

/**
 * ctrls C-10 후속 sweep: issuer URL 결정 헬퍼.
 *
 * IDP_ISSUER_URL 환경변수가 설정되어 있으면 그 값을 사용.
 *
 * S5 fail-closed:
 * - production(`!dev`): 미설정이면 요청 Host 로 fallback 하지 않고 503 오류로 즉시
 *   차단한다. Host 헤더 주입으로 iss 클레임/SAML Issuer 가 오염되는 것을 막는다.
 *   (부트스트랩 경로에서 요청 초기 검증도 하지만, discovery 등 baseline 을
 *    건너뛰는 라우트를 위한 최종 방어선.)
 * - dev: 로컬 DX 보존을 위해 요청 origin fallback + 1회 warn 유지.
 *
 * production 에서 fallback 을 허용했을 때의 호스트 주입 영향:
 * - discovery/token/userinfo: 발급 토큰의 iss 가 attacker 도메인 — RP 가
 *   strict iss 검증하면 거부 (대부분의 RP) → self-DoS. RP 가 느슨하면
 *   attacker 도메인 신뢰로 이어질 수 있음.
 * - end-session expectedIssuer: legitimate id_token_hint 의 iss 불일치 →
 *   verifyIdToken 실패 → self-DoS.
 * - SAML SLO/logout: SAML 메시지의 Issuer 가 attacker 도메인 — 마찬가지로
 *   SP 의 strict 검증으로 거부 → self-DoS.
 */
let warnedMissingIssuer = false;
export function resolveIssuerUrl(runtimeConfig: RuntimeConfig | undefined, fallbackOrigin: string, tenantSlug?: string): string {
    const baseIssuer = runtimeConfig?.issuerUrl;
    if (tenantSlug && runtimeConfig?.tenantIssuerMode === "path") {
        return `${(baseIssuer ?? fallbackOrigin).replace(/\/+$/, "")}/t/${encodeURIComponent(tenantSlug)}`;
    }
    if (tenantSlug && runtimeConfig?.tenantIssuerMode === "host") {
        const base = new URL(baseIssuer ?? fallbackOrigin);
        const domain = runtimeConfig.tenantBaseDomain ?? base.hostname;
        if (tenantSlug !== "default") base.hostname = `${tenantSlug}.${domain}`;
        return base.toString().replace(/\/$/, "");
    }
    if (baseIssuer) return baseIssuer;
    if (!dev) {
        // production fail-closed: Host 주입을 신뢰하지 않는다.
        throw error(503, "IDP_ISSUER_URL 이 설정되지 않았습니다. 프로덕션에서는 필수 설정입니다.");
    }
    if (!warnedMissingIssuer) {
        warnedMissingIssuer = true;
        console.warn("[runtime] IDP_ISSUER_URL 미설정 — 요청 Host 기반 origin fallback. 운영에서는 반드시 명시할 것.");
    }
    return fallbackOrigin.replace(/\/+$/, "");
}
