/**
 * 단기 HMAC-서명 페이로드 유틸.
 *
 * 서버가 브라우저에 잠시 맡겨두되 **사용자가 변조할 수 없어야 하는** 상태를 쿠키로
 * 나르기 위한 공용 구현이다. `auth/mfa.ts` 의 MFA pending 토큰이 이 패턴의 원형이며,
 * OAuth state(`oauth/state.ts`)와 연합 가입 pending 링크(`auth/pending-link.ts`)가
 * 같은 형식을 공유한다.
 *
 * 형식: `<payload_b64u>.<signature_b64u>` — payload 는 JSON, 서명은 HMAC-SHA256.
 * payload 에는 항상 `exp`(epoch ms)가 포함되며 검증 시 만료를 확인한다.
 *
 * 주의: 페이로드는 서명만 되고 **암호화되지 않는다**(base64url 은 인코딩일 뿐이다).
 * 사용자가 읽어도 무방한 값만 담아야 한다. 비밀번호·client secret 등은 절대 금지.
 */

import { b64uDecode, b64uEncode } from "$lib/server/crypto/keys";

/** 서명 페이로드에 자동으로 부여되는 만료 필드. */
interface WithExpiry {
    exp: number;
}

async function deriveHmacKey(secret: string): Promise<CryptoKey> {
    return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

/**
 * payload 를 JSON 직렬화 후 `ttlMs` 만료를 붙여 서명한다.
 * 반환값은 쿠키 value 로 바로 사용할 수 있다.
 */
export async function signPayload<T extends object>(payload: T, secret: string, ttlMs: number): Promise<string> {
    const enc = new TextEncoder();
    const body: T & WithExpiry = { ...payload, exp: Date.now() + ttlMs };
    const data = b64uEncode(enc.encode(JSON.stringify(body)));
    const key = await deriveHmacKey(secret);
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
    return `${data}.${b64uEncode(new Uint8Array(sig))}`;
}

/**
 * 서명과 만료를 검증하고 payload 를 반환한다. 어느 하나라도 실패하면 null.
 *
 * 반환 타입은 호출부가 지정하지만 런타임 구조 검증은 하지 않는다. 호출부에서
 * 필요한 필드의 존재/타입을 반드시 다시 확인해야 한다.
 */
export async function verifyPayload<T extends object>(token: string, secret: string): Promise<T | null> {
    try {
        const lastDot = token.lastIndexOf(".");
        if (lastDot === -1) return null;

        const data = token.slice(0, lastDot);
        const sigB64 = token.slice(lastDot + 1);
        if (!data || !sigB64) return null;

        const enc = new TextEncoder();
        const key = await deriveHmacKey(secret);
        const valid = await crypto.subtle.verify("HMAC", key, b64uDecode(sigB64), enc.encode(data));
        if (!valid) return null;

        const payload = JSON.parse(new TextDecoder().decode(b64uDecode(data))) as T & WithExpiry;
        if (typeof payload.exp !== "number" || payload.exp < Date.now()) return null;

        return payload;
    } catch {
        return null;
    }
}

/**
 * 타이밍 공격을 피하는 문자열 비교. OAuth state 처럼 공격자가 값을 고를 수 있는
 * 대상을 비교할 때 사용한다.
 */
export function timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}
