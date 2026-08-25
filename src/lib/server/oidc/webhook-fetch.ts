import { assertResolvedHostAllowed, isForbiddenWebhookHost } from "$lib/server/validation";

const WEBHOOK_TIMEOUT_MS = 10_000;
const MAX_ATTEMPTS = 3;
const RETRY_DELAYS_MS = [0, 100, 250];

export interface OidcWebhookQueue {
    send(message: OidcWebhookQueueMessage): Promise<unknown>;
}

export interface OidcWebhookQueueMessage {
    url: string;
    body: string;
}

/** Final URL gate for server-side OIDC webhook delivery. */
export function assertPublicWebhookUrl(raw: string): void {
    let parsed: URL;
    try {
        parsed = new URL(raw);
    } catch {
        throw new Error(`webhook URL invalid: ${raw}`);
    }
    if (parsed.protocol !== "https:") {
        throw new Error(`webhook URL must be https: ${raw}`);
    }
    if (isForbiddenWebhookHost(parsed.hostname)) {
        throw new Error(`webhook URL host is forbidden (SSRF guard): ${parsed.hostname}`);
    }
}

/**
 * POSTs a signed webhook without following redirects. The response body is
 * intentionally not consumed because webhook callers only need the status.
 */
export async function postOidcWebhook(url: string, body: string, options: { queue?: OidcWebhookQueue } = {}): Promise<{ status: number; durationMs: number; queued?: boolean }> {
    assertPublicWebhookUrl(url);
    await assertResolvedHostAllowed(new URL(url).hostname);

    const started = Date.now();
    let lastError: unknown;
    let queueEligible = true;
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
        if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, RETRY_DELAYS_MS[attempt]));
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);
        let retryable = true;
        try {
            const response = await fetch(url, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body,
                redirect: "manual",
                signal: controller.signal,
            });
            if (response.status >= 300 && response.status < 400) {
                retryable = false;
                queueEligible = false;
                throw new Error(`webhook redirected with status ${response.status}`);
            }
            if (!response.ok) {
                if (response.status >= 500 && attempt < MAX_ATTEMPTS - 1) continue;
                retryable = response.status >= 500;
                queueEligible = retryable;
                throw new Error(`webhook responded with status ${response.status}`);
            }
            return { status: response.status, durationMs: Date.now() - started };
        } catch (error) {
            lastError = error;
            if (error instanceof DOMException && error.name === "AbortError") {
                retryable = false;
            }
            if (!retryable || attempt === MAX_ATTEMPTS - 1) break;
        } finally {
            clearTimeout(timer);
        }
    }

    if (options.queue && queueEligible) {
        await options.queue.send({ url, body });
        return { status: 202, durationMs: Date.now() - started, queued: true };
    }
    throw lastError instanceof Error ? lastError : new Error("webhook delivery failed");
}
