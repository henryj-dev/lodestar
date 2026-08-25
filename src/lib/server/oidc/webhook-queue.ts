import { postOidcWebhook, type OidcWebhookQueueMessage } from "$lib/server/oidc/webhook-fetch";

/**
 * Queue consumer에서 호출할 재전송 함수.
 * 큐 재시도 횟수/백오프는 Cloudflare Queue 또는 Workflow 설정이 담당하고,
 * 여기서는 HTTP delivery 자체의 bounded retry만 수행한다.
 */
export async function deliverQueuedOidcWebhook(message: OidcWebhookQueueMessage): Promise<void> {
    await postOidcWebhook(message.url, message.body);
}
