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

export async function resolveSkinHtml(
    db: DB,
    platform: App.Platform | undefined,
    tenantId: string,
    clientType: "oidc" | "saml",
    clientRefId: string,
    skinType: "login" | "signup" | "find_id" | "find_password" | "mfa" | "reset_password" = "login",
): Promise<string | null> {
    const [skin] = await db
        .select()
        .from(clientSkins)
        .where(
            and(
                eq(clientSkins.tenantId, tenantId),
                eq(clientSkins.clientType, clientType),
                eq(clientSkins.clientRefId, clientRefId),
                eq(clientSkins.skinType, skinType),
                eq(clientSkins.enabled, true),
            ),
        )
        .limit(1);

    if (!skin) return null;

    const cache = getSkinCacheStore(platform);
    const cacheKey = `${CACHE_PREFIX}${tenantId}/${clientType}/${await hashKey(clientRefId)}/${skinType}`;

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
    clientType: "oidc" | "saml",
    clientRefId: string,
    skinType: "login" | "signup" | "find_id" | "find_password" | "mfa" | "reset_password" = "login",
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
