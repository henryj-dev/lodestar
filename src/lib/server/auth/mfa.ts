/**
 * MFA pending 상태 관리.
 *
 * 비밀번호 인증 성공 후 TOTP 단계가 남아있을 때, 단기(5분) HMAC-서명 쿠키로
 * { userId, tenantId, redirectTo } 를 안전하게 전달한다.
 *
 * 형식: `<payload_b64u>.<signature_b64u>`
 * payload JSON: { uid, tid, redir, exp }
 */

import { AMR_PASSWORD } from "./constants";

export const MFA_PENDING_COOKIE = "idp_mfa_pending";
const MFA_PENDING_TTL_MS = 5 * 60 * 1000; // 5분

export interface MfaPendingClaims {
    userId: string;
    tenantId: string;
    redirectTo: string | null;
    ip: string | null;
    /**
     * 강제 재인증 여부. true 면 신뢰 기기("이 기기에서 다시 인증하지 않기")를 적용하지 않는다.
     * admin 로그인 / SAML ForceAuthn / OIDC prompt=login·max_age 초과 / ACR step-up 이 해당한다.
     */
    forced: boolean;
    /**
     * MFA 단계 **이전에** 실제로 통과한 1차 인증 수단의 AMR 값.
     * 로컬 로그인은 `pwd`, 소셜 연합 로그인은 `fed` 다. MFA 완료 후 세션 amr 을
     * 조립할 때 쓰이며, 하드코딩하면 비밀번호를 제시한 적 없는 사용자에게 `pwd` 가
     * 붙어 downstream RP 에 거짓 정보가 나간다.
     */
    firstFactor?: string;
}

interface MfaPendingPayload {
    uid: string;
    tid: string;
    redir: string | null;
    ip: string | null;
    frc: boolean;
    /** 1차 인증 수단. 구버전 토큰에는 없으며 그 경우 `pwd` 로 간주한다. */
    ff?: string;
    exp: number;
}

function b64uEncode(input: Uint8Array): string {
    return btoa(String.fromCharCode(...input))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

function b64uDecode(str: string): Uint8Array<ArrayBuffer> {
    const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length) as Uint8Array<ArrayBuffer>;
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
}

async function deriveHmacKey(secret: string): Promise<CryptoKey> {
    const enc = new TextEncoder();
    return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

/**
 * MFA pending 토큰 생성. 쿠키 value 로 사용한다.
 */
export async function createMfaPendingToken(claims: MfaPendingClaims, signingKeySecret: string): Promise<string> {
    const enc = new TextEncoder();
    const payload: MfaPendingPayload = {
        uid: claims.userId,
        tid: claims.tenantId,
        redir: claims.redirectTo,
        ip: claims.ip,
        frc: claims.forced,
        ff: claims.firstFactor,
        exp: Date.now() + MFA_PENDING_TTL_MS,
    };
    const data = b64uEncode(enc.encode(JSON.stringify(payload)));
    const key = await deriveHmacKey(signingKeySecret);
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
    return `${data}.${b64uEncode(new Uint8Array(sig))}`;
}

/**
 * MFA pending 토큰을 검증하고 claims 를 반환한다.
 * 만료되었거나 서명이 유효하지 않으면 null 반환.
 */
export async function verifyMfaPendingToken(token: string, signingKeySecret: string): Promise<MfaPendingClaims | null> {
    try {
        const lastDot = token.lastIndexOf(".");
        if (lastDot === -1) return null;
        const data = token.slice(0, lastDot);
        const sigB64 = token.slice(lastDot + 1);
        const enc = new TextEncoder();
        const key = await deriveHmacKey(signingKeySecret);
        const valid = await crypto.subtle.verify("HMAC", key, b64uDecode(sigB64), enc.encode(data));
        if (!valid) return null;
        const payload = JSON.parse(new TextDecoder().decode(b64uDecode(data))) as MfaPendingPayload;
        if (payload.exp < Date.now()) return null;
        return {
            userId: payload.uid,
            tenantId: payload.tid,
            redirectTo: payload.redir,
            ip: payload.ip ?? null,
            // fail-safe: frc 필드가 없는 구버전 토큰(배포 전환 중 발급분)은 "강제"로 간주한다.
            // 기본값을 false 로 두면 구토큰이 신뢰 기기 등록/적용을 허용해 forceAuthn 을
            // 우회할 수 있으므로, 불확실할 때는 보수적으로 재인증을 요구하는 쪽을 택한다.
            forced: payload.frc ?? true,
            // ff 가 없는 구버전 토큰은 로컬 로그인에서만 발급됐으므로 pwd 가 맞다.
            firstFactor: payload.ff ?? AMR_PASSWORD,
        };
    } catch {
        return null;
    }
}
