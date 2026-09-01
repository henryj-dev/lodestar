import type { DB } from "$lib/server/db";
import { clientSkins } from "$lib/server/db/schema";
import { and, eq } from "drizzle-orm";
import { sanitizeSkinHtml } from "./sanitize";
import { getSkinCacheStore } from "./storage";
import { assertResolvedHostAllowed } from "$lib/server/validation";

const CACHE_PREFIX = "skins/";

// ctrls C-14: SSRF 하드닝 — fetch 시간/응답 크기 한도 + 호스트명 화이트리스트.
const BLOCKED_HOSTNAMES = new Set(["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"]);
const BLOCKED_INTERNAL_HOSTS = new Set([
    "metadata.google.internal",
    "metadata.goog",
    "metadata.azure.com",
    "instance-data.ec2.internal",
    "100.100.100.200", // alibaba metadata
]);
const FETCH_TIMEOUT_MS = 5_000;
const MAX_SKIN_BYTES = 512 * 1024; // 512KB — login 페이지 HTML 로 충분히 큰 한도

export function escapeHtml(str: string): string {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// ctrls H-FRONT-3: placeholder 값에 위험한 URL scheme 토큰이 포함되면 빈 문자열로
// 치환한다. skin 작성자가 placeholder 를 href/src/action 같은 URL 컨텍스트에 넣었을
// 때 escapeHtml 만으로는 javascript: / vbscript: / data:text/html 등 scheme 기반
// XSS 를 막을 수 없다 (HTML escape 는 < > " ' & 만 변환).
// 본 함수는 보수적으로 위험 패턴이 들어간 값을 통째 비워 skin 컨텍스트와 무관하게
// 안전하게 만든다. 정상 텍스트/이메일/짧은 식별자에는 영향 없음.
//
// 주의: 트레일링 `\s*:` 는 **스킴 이름만 적힌 대안**(javascript/vbscript)에만 붙인다. 예전 패턴은
// `(?:javascript|vbscript|data\s*:\s*text\/html|data\s*:\s*application)\s*:` 였는데, data 대안은
// 이미 자기 콜론을 포함하므로 뒤에 콜론이 **하나 더** 있어야 매칭됐다. 그래서 실제 공격 문자열인
// `data:text/html,<script>…` 는 통과하고 무의미한 `data:text/html:x` 만 걸렸다.
// `data:image/…`(정상 인라인 이미지)는 계속 통과해야 하므로 image 는 대상에 넣지 않는다.
const DANGEROUS_URI_SCHEME_RE = /(?:^|\s)(?:(?:javascript|vbscript)\s*:|data\s*:\s*(?:text\/html|application\/))/i;
function stripDangerousScheme(value: string): string {
    return DANGEROUS_URI_SCHEME_RE.test(value) ? "" : value;
}

export function replacePlaceholders(html: string, vars: Record<string, string>): string {
    return html.replace(/\{\{([A-Z_][A-Z0-9_]*)\}\}/g, (_, key: string) => {
        if (!Object.prototype.hasOwnProperty.call(vars, key)) return "";
        return stripDangerousScheme(vars[key]);
    });
}

async function hashKey(input: string): Promise<string> {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0"))
        .join("")
        .slice(0, 32);
}

function isFetchUrlAllowed(rawUrl: string): URL | null {
    let url: URL;
    try {
        url = new URL(rawUrl);
    } catch {
        return null;
    }
    if (url.protocol !== "https:") return null;

    const host = url.hostname.toLowerCase();

    // IPv6 literal — URL.hostname 은 brackets 없이 반환하지만 hostname 에 콜론이
    // 포함됐다면 IPv6 literal 이다. 운영 skin 호스트는 항상 도메인 명을 쓰므로
    // 안전하게 전체 거절.
    if (host.includes(":")) return null;

    if (BLOCKED_HOSTNAMES.has(host)) return null;
    if (BLOCKED_INTERNAL_HOSTS.has(host)) return null;
    if (host.endsWith(".local")) return null;
    if (host.endsWith(".internal")) return null;

    // 단일 라벨 (점 없는) 호스트명은 운영 도메인일 수 없음 — 내부 서비스 이름일
    // 가능성 큼 (kubernetes service, intranet hosts 등).
    if (!host.includes(".")) return null;

    // IPv4 private/link-local/loopback 차단 (defense-in-depth)
    if (/^10\./.test(host)) return null;
    if (/^192\.168\./.test(host)) return null;
    if (/^169\.254\./.test(host)) return null;
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) return null;
    if (/^127\./.test(host)) return null;
    if (/^0\./.test(host)) return null; // 0.0.0.0/8 전체

    return url;
}

/**
 * 테넌트 기본 스킨을 가리키는 예약값.
 *
 * 클라이언트가 특정되지 않는 흐름(관리자 초대 수락, 계정의 이메일 변경 확인 등)에도 스킨을
 * 적용하려면 "이 테넌트의 기본" 이라는 슬롯이 필요하다. `clientType`/`skin_type` 은 드리즐의
 * TS 전용 enum(컬럼은 text)이라 값을 늘려도 마이그레이션이 필요 없고, 기존 유니크 인덱스
 * (tenantId, clientType, clientRefId, skinType) 가 중복 등록을 그대로 막아준다.
 *
 * `clientRefId` 를 nullable 로 바꾸는 쪽이 의미상 깔끔하지만, 세 방언 모두 유니크 인덱스에서
 * NULL 을 서로 다른 값으로 취급해 기본 스킨이 중복 등록된다. 부분 유니크 인덱스는 MySQL 이
 * 지원하지 않으므로 예약값이 방언 간 가장 견고하다.
 */
export const TENANT_DEFAULT_CLIENT_TYPE = "tenant" as const;
export const TENANT_DEFAULT_CLIENT_REF = "*";

export type SkinType = "login" | "signup" | "find_id" | "find_password" | "mfa" | "reset_password" | "verify_email" | "accept_invite" | "confirm_email_change" | "logout" | "consent" | "terms";

type SkinRow = typeof clientSkins.$inferSelect;

/**
 * 클라이언트 전용 스킨 → 테넌트 기본 스킨 순으로 찾는다.
 * clientType/clientRefId 가 없으면(클라이언트 컨텍스트가 없는 페이지) 곧바로 기본 스킨을 본다.
 */
async function findSkinRow(db: DB, tenantId: string, clientType: "oidc" | "saml" | null, clientRefId: string | null, skinType: SkinType): Promise<SkinRow | null> {
    const pick = async (type: string, refId: string): Promise<SkinRow | null> => {
        const [row] = await db
            .select()
            .from(clientSkins)
            .where(
                and(
                    eq(clientSkins.tenantId, tenantId),
                    eq(clientSkins.clientType, type as SkinRow["clientType"]),
                    eq(clientSkins.clientRefId, refId),
                    eq(clientSkins.skinType, skinType),
                    eq(clientSkins.enabled, true),
                ),
            )
            .limit(1);
        return row ?? null;
    };

    if (clientType && clientRefId) {
        const own = await pick(clientType, clientRefId);
        if (own) return own;
    }
    return pick(TENANT_DEFAULT_CLIENT_TYPE, TENANT_DEFAULT_CLIENT_REF);
}

/**
 * `skinHint`("oidc:<id>" / "saml:<id>")를 클라이언트 참조로 분해한다.
 * 값이 없거나 형식이 어긋나면 둘 다 null — 호출부는 그대로 테넌트 기본 스킨으로 폴백한다.
 */
export function parseSkinHint(skinHint: string | null | undefined): { clientType: "oidc" | "saml" | null; clientRefId: string | null } {
    const none = { clientType: null, clientRefId: null } as const;
    if (!skinHint) return none;
    const colonIdx = skinHint.indexOf(":");
    if (colonIdx <= 0) return none;
    const clientType = skinHint.slice(0, colonIdx);
    const clientRefId = skinHint.slice(colonIdx + 1);
    if ((clientType !== "oidc" && clientType !== "saml") || !clientRefId) return none;
    return { clientType, clientRefId };
}

/**
 * skinHint 로 스킨을 해석한다. 힌트가 없으면 테넌트 기본 스킨을 본다 — 클라이언트가 특정되지
 * 않는 흐름(초대 수락, 이메일 변경 확인)이 쓰는 진입점이다.
 */
export async function resolveSkinByHint(db: DB, platform: App.Platform | undefined, tenantId: string, skinHint: string | null | undefined, skinType: SkinType): Promise<string | null> {
    const { clientType, clientRefId } = parseSkinHint(skinHint);
    return resolveSkinHtml(db, platform, tenantId, clientType, clientRefId, skinType);
}

export async function resolveSkinHtml(
    db: DB,
    platform: App.Platform | undefined,
    tenantId: string,
    clientType: "oidc" | "saml" | null,
    clientRefId: string | null,
    skinType: SkinType = "login",
): Promise<string | null> {
    const skin = await findSkinRow(db, tenantId, clientType, clientRefId, skinType);

    if (!skin) return null;

    const cache = getSkinCacheStore(platform);
    // 캐시 키는 **실제로 매칭된 행** 기준이다. 요청한 클라이언트 기준으로 만들면 기본 스킨으로
    // 폴백한 클라이언트마다 같은 HTML 이 따로 캐시되고, 무효화도 서로 어긋난다.
    const cacheKey = `${CACHE_PREFIX}${tenantId}/${skin.clientType}/${await hashKey(skin.clientRefId)}/${skinType}`;

    if (cache) {
        try {
            const cached = await cache.get(cacheKey);
            if (cached && Date.now() - cached.fetchedAt < skin.cacheTtlSeconds * 1000) {
                // ctrls C-14: 캐시에 사전 sanitize 적용 후 저장하지만 legacy 캐시
                // (sanitize 도입 전에 채워진) 가능성에 대비해 read time 에도 한 번 더.
                return await sanitizeSkinHtml(await cached.text());
            }
        } catch {
            // 캐시 오류는 무시하고 원본 fetch로 진행
        }
    }

    try {
        const fetchUrl = isFetchUrlAllowed(skin.fetchUrl);
        if (!fetchUrl) return null;

        // ctrls R7: DNS 리바인딩 완화 — 실호스트 해석 후 내부 IP 로 가면 skin fetch 를 건너뛴다.
        try {
            await assertResolvedHostAllowed(fetchUrl.hostname);
        } catch {
            return null;
        }

        const headers: Record<string, string> = { Accept: "text/html" };
        if (skin.fetchSecret) {
            headers["X-IDP-Token"] = skin.fetchSecret;
        }

        // ctrls C-14: fetch 시간 + 응답 크기 cap. slowloris / 거대 응답으로 Worker
        // CPU/메모리 점유, R2 저장 비용 폭증, 다음 사용자에게 거대 HTML 전송으로 인한
        // 가용성 공격을 모두 차단.
        const ctl = new AbortController();
        const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);

        let res: Response;
        try {
            // redirect: "manual" — secret leak via 3xx Location 방지
            res = await fetch(fetchUrl.toString(), { headers, redirect: "manual", signal: ctl.signal });
        } finally {
            clearTimeout(timer);
        }
        if (res.status >= 300 && res.status < 400) return null;
        if (!res.ok) return null;

        const contentType = res.headers.get("Content-Type") ?? "";
        if (!contentType.includes("text/html")) return null;

        // Content-Length 가 명시되어 있으면 사전 cap. 누락/거짓이어도 아래 text() 결과
        // 길이로 다시 한 번 검증한다.
        const declared = Number(res.headers.get("Content-Length") ?? 0);
        if (Number.isFinite(declared) && declared > MAX_SKIN_BYTES) return null;

        const rawHtml = await res.text();
        if (rawHtml.length > MAX_SKIN_BYTES) return null;
        // ctrls C-14: 외부 호스트가 손상되어도 임의 script/iframe/외부 form action
        // 이 사용자 브라우저에 닿지 않도록 sanitize. CSP 가 1차 방어이고 이건 2차.
        const html = await sanitizeSkinHtml(rawHtml);

        if (cache) {
            try {
                await cache.put(cacheKey, html, Date.now());
            } catch {
                // 캐시 저장 실패는 무시
            }
        }

        return html;
    } catch {
        return null;
    }
}

export async function invalidateSkinCache(
    platform: App.Platform | undefined,
    tenantId: string,
    clientType: "oidc" | "saml" | typeof TENANT_DEFAULT_CLIENT_TYPE,
    clientRefId: string,
    skinType: SkinType = "login",
): Promise<void> {
    const cache = getSkinCacheStore(platform);
    if (!cache) return;
    const cacheKey = `${CACHE_PREFIX}${tenantId}/${clientType}/${await hashKey(clientRefId)}/${skinType}`;
    try {
        await cache.delete(cacheKey);
    } catch {
        // 무시
    }
}
