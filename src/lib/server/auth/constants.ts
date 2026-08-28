export const DEFAULT_TENANT_SLUG = "default";
export const SESSION_COOKIE_NAME = "idp_session";
export const SESSION_TTL_MS = 1000 * 60 * 60 * 12;
export const SESSION_TOUCH_INTERVAL_MS = 1000 * 60 * 5;
export const PASSWORD_CREDENTIAL_TYPE = "password";
export const LOCAL_IDENTITY_PROVIDER = "local";

// MFA credential 타입
export const TOTP_CREDENTIAL_TYPE = "totp";
export const BACKUP_CODE_CREDENTIAL_TYPE = "backup_code";

// AMR (Authentication Methods References) 값
export const AMR_PASSWORD = "pwd";
export const AMR_TOTP = "totp";
export const AMR_BACKUP_CODE = "swk"; // software key (RFC 8176 유사)
export const AMR_WEBAUTHN = "hwk"; // hardware key (RFC 8176)
/**
 * 외부 IdP 연합(소셜 로그인)으로 1차 인증했음을 뜻한다. RFC 8176 에 등재된 값은
 * 아니지만 "federated" 의 관용 표기로 널리 쓰인다. 사용자가 Lodestar 에 비밀번호를
 * 제시한 적이 없으므로 `pwd` 로 표기하면 downstream RP 에 거짓 정보가 나간다.
 */
export const AMR_FEDERATED = "fed";

// WebAuthn credential 타입
export const WEBAUTHN_CREDENTIAL_TYPE = "webauthn";

// ACR (Authentication Context Class Reference) 값
export const ACR_PASSWORD_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
export const ACR_MFA = "https://refeds.org/profile/mfa";

/**
 * 지식/연합 기반 1차 인증 수단. 이 중 하나 + 2차 수단이면 MFA 로 인정한다.
 * 연합(`fed`)이 여기 포함되는 이유: 소셜 로그인 후 TOTP 를 추가로 통과했다면
 * 실제로 서로 다른 두 요소를 거친 것이므로 `pwd + totp` 와 동등하게 봐야 한다.
 */
const FIRST_FACTORS = [AMR_PASSWORD, AMR_FEDERATED];
const SECOND_FACTORS = [AMR_TOTP, AMR_BACKUP_CODE];

/** AMR 배열로부터 ACR 을 결정한다. */
export function amrToAcr(amr: string[]): string {
    // 패스키(WebAuthn)는 단독으로 다요소를 만족한다(소유 + 사용자 인증).
    if (amr.includes(AMR_WEBAUTHN)) return ACR_MFA;
    if (amr.some((m) => FIRST_FACTORS.includes(m)) && amr.some((m) => SECOND_FACTORS.includes(m))) {
        return ACR_MFA;
    }
    return ACR_PASSWORD_TRANSPORT;
}

/** ACR 강도 레벨 (숫자가 높을수록 강함) */
const ACR_LEVEL: Record<string, number> = {
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Password": 1,
    [ACR_PASSWORD_TRANSPORT]: 1,
    [ACR_MFA]: 2,
};

function acrLevel(acr: string | null): number {
    return ACR_LEVEL[acr ?? ""] ?? 1;
}

/**
 * 세션 ACR 이 MFA 수준(`refeds/mfa`)에 도달했는지.
 *
 * 클라이언트/SP 의 `requireMfa` 게이트가 쓴다. `acrSatisfies` 는 SAML
 * `RequestedAuthnContext` 의 comparison 문법을 해석하는 용도라 단순 판정에는 과하다.
 */
export function acrMeetsMfa(acr: string | null): boolean {
    return acrLevel(acr) >= ACR_LEVEL[ACR_MFA];
}

/**
 * 상위 ACR 이 포함(subsume)하는 하위 ACR 목록.
 * refeds/mfa 로 인증한 사용자는 PasswordProtectedTransport 도 만족한다.
 */
const ACR_SUBSUMES: Record<string, string[]> = {
    [ACR_MFA]: [ACR_PASSWORD_TRANSPORT, "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"],
};

function acrSubsumes(sessionAcr: string | null, requestedRef: string): boolean {
    if (!sessionAcr) return false;
    return ACR_SUBSUMES[sessionAcr]?.includes(requestedRef) ?? false;
}

/**
 * 세션 ACR 이 SP 가 요구하는 RequestedAuthnContext 를 만족하는지 검사한다.
 * comparison: exact | minimum | maximum | better
 */
export function acrSatisfies(sessionAcr: string | null, requested: { comparison: string; classRefs: string[] }): boolean {
    const level = acrLevel(sessionAcr);
    switch (requested.comparison) {
        case "exact":
            // 정확히 일치하거나, 상위 ACR 이 해당 수준을 포함(subsume)하는 경우 허용
            return requested.classRefs.some((ref) => ref === sessionAcr || acrSubsumes(sessionAcr, ref));
        case "minimum":
            return requested.classRefs.some((ref) => level >= acrLevel(ref));
        case "maximum":
            return requested.classRefs.some((ref) => level <= acrLevel(ref));
        case "better":
            return requested.classRefs.some((ref) => level > acrLevel(ref));
        default:
            return requested.classRefs.some((ref) => ref === sessionAcr || acrSubsumes(sessionAcr, ref));
    }
}
