import { normalizeLocale } from "$lib/i18n/core";
import { translate } from "$lib/i18n/server";
import { sendSecurityAlertEmail } from "$lib/server/email";

// F2: 보안 알림 이벤트 종류. 각 kind 는 i18n `security_alert.<kind>.{subject,heading,body}` 를 가진다.
export type SecurityEventKind =
    | "password_changed"
    | "password_reset_by_admin"
    | "account_locked"
    | "account_disabled"
    | "mfa_enrolled"
    | "mfa_disabled"
    | "backup_codes_regenerated"
    | "backup_codes_low"
    | "backup_codes_depleted"
    | "passkey_added"
    | "passkey_removed"
    // 소셜 계정 연결 해제 — 패스키 제거와 마찬가지로 로그인 수단이 하나 사라지는 변경이라
    // 계정 탈취 정황일 수 있어 본인에게 알린다.
    | "social_identity_unlinked"
    | "account_deletion_requested"
    | "email_change_requested"
    | "session_revoked"
    | "sessions_revoked_all";

// users.locale ("ko-KR"/"en-US"/"ja-JP" 등) → i18n Locale. 공용 normalizeLocale(core.ts) 로 정규화한다.
// 하위 호환 별칭 — 기존 호출부/테스트가 toLocale 을 참조한다.
export const toLocale = normalizeLocale;

// UTC 기준 사람이 읽을 수 있는 타임스탬프(locale 무관, 시간대 모호성 제거).
function formatWhen(when: Date): string {
    return when
        .toISOString()
        .replace("T", " ")
        .replace(/\.\d+Z$/, " UTC");
}

/**
 * 보안 알림 메일을 fire-and-forget 로 발송한다. 본 동작과 완전 격리한다:
 *  - 이메일이 없는 계정은 조용히 스킵
 *  - 발송 실패는 무시(서버 로그만)
 *  - Workers 는 waitUntil 로 응답 경로에서 분리, Node 는 fire-and-forget
 */
export function dispatchSecurityAlert(params: { to: string | null | undefined; locale: string | null | undefined; kind: SecurityEventKind; when?: Date; platform?: App.Platform }): void {
    const { to, kind, platform } = params;
    if (!to) return; // 이메일 없는 계정 스킵
    const L = normalizeLocale(params.locale);
    const when = params.when ?? new Date();
    const content = {
        subject: translate(L, `security_alert.${kind}.subject`),
        heading: translate(L, `security_alert.${kind}.heading`),
        body: translate(L, `security_alert.${kind}.body`),
        whenText: translate(L, "security_alert.when", { time: formatWhen(when) }),
        footer: translate(L, "security_alert.footer"),
    };
    const sendPromise = sendSecurityAlertEmail(to, content, platform).catch((e) => {
        console.error("[security-notify] 발송 실패", kind, e);
    });
    const wait = platform?.ctx?.waitUntil?.bind(platform.ctx);
    if (wait) wait(sendPromise);
}
