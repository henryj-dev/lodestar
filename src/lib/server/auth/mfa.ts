/**
 * MFA pending 상태 관리.
 *
 * 두 가지 모드를 같은 토큰 형식으로 다룬다.
 *
 * 1. **login** — 비밀번호/연합 인증 성공 후 TOTP 단계가 남은 상태. MFA 통과 시 세션을 새로 만든다.
 * 2. **step-up** — 이미 인증된 세션의 ACR 을 올리기 위해 OTP 만 받는 상태. MFA 통과 시 세션 행을
 *    유지한 채 AMR/ACR 만 승격한다. `sessionId` 가 채워져 있으면 step-up 이다.
 *
 * 단기(5분) HMAC-서명 쿠키로 claims 를 안전하게 전달한다.
 *
 * 형식: `<payload_b64u>.<signature_b64u>`
 * payload JSON: { uid, tid, redir, ip, frc, ff, sid, exp }
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
     * MFA 단계 **이전에** 이미 통과한 인증 수단들의 AMR 값.
     *
     * login 모드에서는 1차 인증 수단 하나다 — 로컬 로그인은 `pwd`, 소셜 연합 로그인은 `fed`.
     * step-up 모드에서는 승격 대상 세션의 기존 AMR 전체다. MFA 완료 후 세션 amr 을 조립할 때
     * 쓰이며, 하드코딩하면 비밀번호를 제시한 적 없는 사용자에게 `pwd` 가 붙어 downstream RP 에
     * 거짓 정보가 나간다.
     */
    baseAmr?: string[];
    /**
     * step-up 모드에서 **승격 대상 세션의 id**(`sessions.id`). login 모드에서는 없다.
     *
     * 이 값의 존재가 두 모드를 가르는 유일한 판별자다. 토큰은 HMAC 서명되어 있으므로 클라이언트가
     * 임의로 붙일 수 없다. `/mfa` 는 이 값이 **현재 요청의 세션 id 와 일치하는지** 반드시 확인해야
     * 한다 — 확인하지 않으면 A 세션용으로 발급된 step-up 토큰이 B 세션을 승격시킬 수 있다.
     */
    sessionId?: string | null;
}

interface MfaPendingPayload {
    uid: string;
    tid: string;
    redir: string | null;
    ip: string | null;
    frc: boolean;
    /** 기존 인증 수단(공백 구분). 구버전 토큰에는 없으며 그 경우 `pwd` 로 간주한다. */
    ff?: string;
    /** step-up 대상 세션 id. 없으면 login 모드. */
    sid?: string;
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
        ff: claims.baseAmr && claims.baseAmr.length > 0 ? claims.baseAmr.join(" ") : undefined,
        sid: claims.sessionId ?? undefined,
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
            baseAmr: payload.ff ? payload.ff.split(" ").filter(Boolean) : [AMR_PASSWORD],
            sessionId: payload.sid ?? null,
        };
    } catch {
        return null;
    }
}
