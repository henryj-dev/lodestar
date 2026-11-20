/**
 * TOTP 등록 티켓 — `/api/totp/enroll/init` 이 발급한 secret 을 `/confirm` 에 묶는다.
 *
 * init 은 stateless 라 secret 을 DB 에 저장하지 않는다. 그래서 예전 confirm 은 body 의 secret 을
 * 그대로 믿었고, 호출자가 IdP 가 발급하지 않은 secret 이나 다른 userId 를 보내도 등록됐다.
 * 이 티켓은 (tenant, userId, secret 해시, 만료)를 HMAC 으로 서명해 init 응답에 싣는다.
 * confirm 은 티켓을 검증하고, 티켓의 userId·secret 이 요청 값과 같은지 확인한다.
 *
 * 키는 마스터 시크릿에서 HKDF 로 **이 용도 전용**으로 유도한다. access token·MFA pending 토큰과
 * 키를 공유하지 않으므로, 한쪽 토큰을 다른 쪽으로 내밀어도 서명이 맞지 않는다.
 *
 * secret 원문은 티켓에 넣지 않는다(SHA-256 해시만). 티켓이 로그에 남아도 seed 가 새지 않게 하기 위함이다.
 */

const TICKET_VERSION = 1;
/** 사용자가 QR 을 스캔하고 첫 코드를 입력할 시간. init 의 rate-limit 창(5분)보다 넉넉하게 둔다. */
export const TOTP_ENROLL_TICKET_TTL_S = 10 * 60;

const HKDF_SALT = "lodestar-totp-enroll-ticket";
const HKDF_INFO = "totp-enroll-ticket-hmac-v1";

interface TicketPayload {
    v: number;
    tid: string;
    uid: string;
    /** base64url(SHA-256(secret)) */
    sh: string;
    /** 만료 시각(초) */
    exp: number;
}

export type TicketCheck = { ok: true } | { ok: false; reason: "malformed" | "bad_signature" | "expired" | "mismatch" };

function b64uEncode(bytes: Uint8Array): string {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64uDecode(str: string): Uint8Array<ArrayBuffer> {
    const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length) as Uint8Array<ArrayBuffer>;
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
}

async function deriveTicketKey(secret: string): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const material = await crypto.subtle.importKey("raw", enc.encode(secret), "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: enc.encode(HKDF_SALT), info: enc.encode(HKDF_INFO) }, material, { name: "HMAC", hash: "SHA-256", length: 256 }, false, [
        "sign",
        "verify",
    ]);
}

async function hashSecret(totpSecret: string): Promise<string> {
    // base32Decode(totp.ts)와 같은 정규화 — 호출자가 대소문자·공백·패딩만 바꿔 돌려보내도 같은 secret 이다.
    const normalized = totpSecret.toUpperCase().replace(/[^A-Z2-7]/g, "");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalized));
    return b64uEncode(new Uint8Array(digest));
}

/** 서명 시크릿은 반드시 current(`runtimeConfig.signingKeySecret`)를 쓴다. */
export async function createTotpEnrollTicket(params: { tenantId: string; userId: string; totpSecret: string }, signingKeySecret: string, nowMs = Date.now()): Promise<string> {
    const payload: TicketPayload = {
        v: TICKET_VERSION,
        tid: params.tenantId,
        uid: params.userId,
        sh: await hashSecret(params.totpSecret),
        exp: Math.floor(nowMs / 1000) + TOTP_ENROLL_TICKET_TTL_S,
    };
    const enc = new TextEncoder();
    const data = b64uEncode(enc.encode(JSON.stringify(payload)));
    const sig = await crypto.subtle.sign("HMAC", await deriveTicketKey(signingKeySecret), enc.encode(data));
    return `${data}.${b64uEncode(new Uint8Array(sig))}`;
}

/**
 * 티켓을 검증한다. 회전 중에도 init→confirm 이 끊기지 않도록 `signingKeySecrets`(current→previous)를
 * 순서대로 시도한다.
 */
export async function verifyTotpEnrollTicket(
    ticket: string,
    expected: { tenantId: string; userId: string; totpSecret: string },
    signingKeySecrets: string[],
    nowMs = Date.now(),
): Promise<TicketCheck> {
    const lastDot = ticket.lastIndexOf(".");
    if (lastDot <= 0) return { ok: false, reason: "malformed" };
    const data = ticket.slice(0, lastDot);
    let sig: Uint8Array<ArrayBuffer>;
    try {
        sig = b64uDecode(ticket.slice(lastDot + 1));
    } catch {
        return { ok: false, reason: "malformed" };
    }

    const enc = new TextEncoder();
    let signed = false;
    for (const secret of signingKeySecrets) {
        if (await crypto.subtle.verify("HMAC", await deriveTicketKey(secret), sig, enc.encode(data))) {
            signed = true;
            break;
        }
    }
    if (!signed) return { ok: false, reason: "bad_signature" };

    let payload: TicketPayload;
    try {
        payload = JSON.parse(new TextDecoder().decode(b64uDecode(data))) as TicketPayload;
    } catch {
        return { ok: false, reason: "malformed" };
    }
    if (payload.v !== TICKET_VERSION || typeof payload.exp !== "number") return { ok: false, reason: "malformed" };
    if (payload.exp < Math.floor(nowMs / 1000)) return { ok: false, reason: "expired" };
    if (payload.tid !== expected.tenantId || payload.uid !== expected.userId) return { ok: false, reason: "mismatch" };
    if (payload.sh !== (await hashSecret(expected.totpSecret))) return { ok: false, reason: "mismatch" };
    return { ok: true };
}
