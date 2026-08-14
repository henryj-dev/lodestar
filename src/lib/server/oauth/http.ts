/**
 * upstream 프로바이더로 나가는 HTTP 호출 공용 래퍼.
 *
 * 이 경로의 URL 은 상당 부분 admin 이 입력한 값(discoveryUrl, 커스텀 엔드포인트)에서
 * 오므로 나갈 때마다 SSRF 를 다시 확인한다. 저장 시점의 `validateOAuthUrl` 이 1차,
 * 여기 `assertResolvedHostAllowed` 가 2차(DNS 리바인딩 완화) 방어선이다.
 */

import { assertResolvedHostAllowed, isForbiddenWebhookHost, isLoopbackHost } from "$lib/server/validation";

/** 외부 프로바이더 응답 대기 상한. 로그인 요청을 무한정 붙잡지 않도록 짧게 잡는다. */
const OUTBOUND_TIMEOUT_MS = 10_000;

/** 응답 본문 크기 상한. 악의적/오구성 엔드포인트가 메모리를 밀어넣는 것을 막는다. */
const MAX_BODY_BYTES = 512 * 1024;

/**
 * 일부 프로바이더(GitHub)는 User-Agent 가 없으면 403 을 준다.
 * 나머지 프로바이더에도 붙여서 손해가 없다.
 */
const USER_AGENT = "KeyStone-IdP";

/** 프로토콜·호스트를 검증한 뒤 fetch 한다. 검증 실패 시 예외. */
async function guardedFetch(url: string, init: RequestInit): Promise<Response> {
    let parsed: URL;
    try {
        parsed = new URL(url);
    } catch {
        throw new Error(`잘못된 URL: ${url}`);
    }

    const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
    if (scheme !== "https" && !(scheme === "http" && isLoopbackHost(parsed.hostname))) {
        throw new Error(`허용되지 않는 스킴: ${scheme} (${parsed.hostname})`);
    }
    if (isForbiddenWebhookHost(parsed.hostname)) {
        throw new Error(`SSRF blocked: ${parsed.hostname}`);
    }
    await assertResolvedHostAllowed(parsed.hostname);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), OUTBOUND_TIMEOUT_MS);
    let res: Response;
    try {
        res = await fetch(url, {
            ...init,
            signal: controller.signal,
            // redirect: "manual" — 리다이렉트를 따라가지 않는다. 검증을 통과한 호스트가
            // 3xx 로 내부 주소를 가리키는 SSRF 우회를 막고, client_secret 이 실린 요청이
            // 다른 호스트로 재전송되는 것도 막는다.
            //
            // "error" 를 쓰면 안 된다 — Cloudflare Workers 는 "follow"/"manual" 만 지원하고
            // "error" 는 fetch 호출 시점에 TypeError 를 던진다(edge 에서는 구현되지 않는다).
            // Node/undici 는 "error" 를 받아주기 때문에 로컬·테스트만으로는 드러나지 않는다.
            // `skin/resolver.ts` 도 같은 이유로 "manual" + 3xx 거부를 쓴다.
            redirect: "manual",
            headers: { "user-agent": USER_AGENT, ...(init.headers ?? {}) },
        });
    } finally {
        clearTimeout(timer);
    }

    // "manual" 은 3xx 를 그대로 돌려주므로 여기서 명시적으로 끊는다.
    if (res.status >= 300 && res.status < 400) {
        throw new Error(`${parsed.host} 가 리다이렉트(${res.status})로 응답했습니다 — 엔드포인트 설정을 확인하세요.`);
    }

    return res;
}

/** 상한을 넘지 않게 본문을 읽는다. */
async function readBounded(res: Response): Promise<string> {
    const text = await res.text();
    if (text.length > MAX_BODY_BYTES) {
        throw new Error("프로바이더 응답이 허용 크기를 초과했습니다.");
    }
    return text;
}

/** GET 후 JSON 파싱. 실패 시 상태코드를 포함한 예외를 던진다. */
export async function getJson<T>(url: string, headers: Record<string, string> = {}): Promise<T> {
    const res = await guardedFetch(url, { method: "GET", headers: { accept: "application/json", ...headers } });
    const body = await readBounded(res);
    if (!res.ok) throw new Error(`GET ${new URL(url).host} 실패 (${res.status}): ${body.slice(0, 200)}`);
    try {
        return JSON.parse(body) as T;
    } catch {
        throw new Error(`GET ${new URL(url).host} 응답이 JSON 이 아닙니다: ${body.slice(0, 200)}`);
    }
}

/**
 * form-urlencoded POST 후 JSON 파싱.
 *
 * 일부 프로바이더는 HTTP 200 에 `{"error": "..."}` 를 담아 실패를 알린다(네이버·카카오·
 * 깃허브 모두 해당). 그래서 status 뿐 아니라 본문의 `error` 필드도 확인한다.
 */
export async function postForm<T>(url: string, form: Record<string, string>, headers: Record<string, string> = {}): Promise<T> {
    const res = await guardedFetch(url, {
        method: "POST",
        headers: {
            "content-type": "application/x-www-form-urlencoded",
            accept: "application/json",
            ...headers,
        },
        body: new URLSearchParams(form).toString(),
    });

    const body = await readBounded(res);
    let parsed: unknown;
    try {
        parsed = JSON.parse(body);
    } catch {
        throw new Error(`POST ${new URL(url).host} 응답이 JSON 이 아닙니다 (${res.status}): ${body.slice(0, 200)}`);
    }

    const err = (parsed as { error?: unknown }).error;
    if (!res.ok || (typeof err === "string" && err)) {
        const desc = (parsed as { error_description?: string }).error_description;
        throw new Error(`POST ${new URL(url).host} 실패 (${res.status}): ${String(err ?? "")} ${desc ?? ""}`.trim());
    }

    return parsed as T;
}
