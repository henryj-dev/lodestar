/**
 * TOTP (RFC 6238) + 백업 코드 구현.
 *
 * - TOTP: WebCrypto HMAC-SHA-1, 30초 스텝, 6자리, ±1 윈도우
 * - 시크릿 암호화: AES-256-GCM + HKDF (IDP_SIGNING_KEY_SECRET 재사용)
 * - 백업 코드: 10개 × 8자리 alphanumeric, scrypt(salted, memory-hard) 단방향 해시
 *   (레거시 무염 SHA-256 해시는 검증 시 하위호환 처리)
 */

import { hashPassword, verifyPassword } from "$lib/server/auth/password";
import { and, eq, isNull, lt } from "drizzle-orm";
import { credentials } from "$lib/server/db/schema";
import { DB_DIALECT, type DB } from "$lib/server/db";

// ── Base32 (RFC 4648) ─────────────────────────────────────────────────────────

const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE32_MAP: Record<string, number> = {};
for (let i = 0; i < BASE32_CHARS.length; i++) BASE32_MAP[BASE32_CHARS[i]] = i;

export function base32Encode(input: Uint8Array): string {
    let bits = 0;
    let value = 0;
    let output = "";
    for (const byte of input) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            output += BASE32_CHARS[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) {
        output += BASE32_CHARS[(value << (5 - bits)) & 31];
    }
    return output;
}

export function base32Decode(input: string): Uint8Array<ArrayBuffer> {
    const normalized = input.toUpperCase().replace(/[^A-Z2-7]/g, "");
    let bits = 0;
    let value = 0;
    const output: number[] = [];
    for (const ch of normalized) {
        const v = BASE32_MAP[ch];
        if (v === undefined) continue;
        value = (value << 5) | v;
        bits += 5;
        if (bits >= 8) {
            output.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return new Uint8Array(output) as Uint8Array<ArrayBuffer>;
}

// ── HOTP / TOTP ───────────────────────────────────────────────────────────────

async function hotp(key: Uint8Array<ArrayBuffer>, counter: number): Promise<number> {
    const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const counterBuf = new Uint8Array(8);
    // counter를 빅엔디안 8바이트로 기록
    let c = counter;
    for (let i = 7; i >= 0; i--) {
        counterBuf[i] = c & 0xff;
        c = Math.floor(c / 256);
    }
    const sig = await crypto.subtle.sign("HMAC", cryptoKey, counterBuf);
    const hash = new Uint8Array(sig);
    const offset = hash[19] & 0xf;
    const code = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
    return code % 1_000_000;
}

/**
 * TOTP 코드를 생성한다 (검증 테스트·시드 등록 확인용).
 */
export async function generateTotpCode(base32Secret: string, stepOffset = 0): Promise<string> {
    const key = base32Decode(base32Secret);
    const step = Math.floor(Date.now() / 30_000) + stepOffset;
    const code = await hotp(key, step);
    return String(code).padStart(6, "0");
}

/**
 * TOTP 코드를 검증한다. 시간 드리프트를 고려해 ±1 윈도우(±30초)를 허용한다.
 * lastUsedStep 을 지정하면 해당 스텝 이하는 거부하여 재사용 공격을 방지한다.
 * 검증 성공 시 매칭된 스텝을 반환하고, 실패 시 null 을 반환한다.
 */
export async function verifyTotp(code: string, base32Secret: string, lastUsedStep?: number): Promise<number | null> {
    if (!/^\d{6}$/.test(code)) return null;
    const key = base32Decode(base32Secret);
    const t = Math.floor(Date.now() / 30_000);
    for (const offset of [-1, 0, 1]) {
        const step = t + offset;
        if (lastUsedStep !== undefined && step <= lastUsedStep) continue;
        const expected = await hotp(key, step);
        if (String(expected).padStart(6, "0") === code) return step;
    }
    return null;
}

/**
 * Atomically consumes a successfully verified TOTP step. The counter predicate
 * makes the verification single-use even when two requests pass verification
 * concurrently. MySQL has no UPDATE ... RETURNING, so its affectedRows result
 * is normalized here for all supported dialects.
 */
export async function consumeTotpCredential(db: DB, credentialId: string, step: number, now: Date, secret?: string): Promise<boolean> {
    const values = secret === undefined ? { lastUsedAt: now, usedAt: now, counter: step } : { lastUsedAt: now, usedAt: now, counter: step, secret };
    const builder = db
        .update(credentials)
        .set(values)
        .where(and(eq(credentials.id, credentialId), lt(credentials.counter, step)));

    if (DB_DIALECT === "mysql") {
        const result = (await builder) as unknown as [{ affectedRows?: number }];
        return (result?.[0]?.affectedRows ?? 0) === 1;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rows = (await (builder as any).returning({ id: credentials.id })) as Array<{ id: string }>;
    return rows.length === 1;
}

/** Atomically consumes one backup code, returning false when another request won. */
export async function consumeBackupCode(db: DB, credentialId: string, now: Date): Promise<boolean> {
    const builder = db
        .update(credentials)
        .set({ usedAt: now })
        .where(and(eq(credentials.id, credentialId), isNull(credentials.usedAt)));

    if (DB_DIALECT === "mysql") {
        const result = (await builder) as unknown as [{ affectedRows?: number }];
        return (result?.[0]?.affectedRows ?? 0) === 1;
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rows = (await (builder as any).returning({ id: credentials.id })) as Array<{ id: string }>;
    return rows.length === 1;
}

// ── TOTP 시크릿 암호화/복호화 ──────────────────────────────────────────────────

async function deriveTotpWrapKey(signingKeySecret: string, salt: Uint8Array<ArrayBuffer>, info: string): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(signingKeySecret), "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

const b64uEnc = (buf: Uint8Array): string =>
    btoa(String.fromCharCode(...buf))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

const b64uDec = (s: string): Uint8Array<ArrayBuffer> => {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length) as Uint8Array<ArrayBuffer>;
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
};

/**
 * TOTP base32 시크릿을 AES-256-GCM 으로 암호화한다.
 *
 * - userId 가 주어지면 v2 형식으로 저장 (HKDF info / AES-GCM AAD 에 userId 바인딩).
 *   다른 사용자 레코드로 ciphertext 를 옮겨붙여도 검증 실패.
 * - userId 미지정 시 v1 형식(레거시) 으로 저장 (호환).
 *
 * 형식 v1: `<salt_b64u>.<iv_b64u>.<ciphertext_b64u>`
 * 형식 v2: `v2.<salt_b64u>.<iv_b64u>.<ciphertext_b64u>` (AAD = "v2:" + userId)
 */
export async function encryptTotpSecret(base32Secret: string, signingKeySecret: string, userId?: string): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();

    if (userId) {
        const info = `idp-totp-secret-wrap-v2:${userId}`;
        const aad = enc.encode(`v2:${userId}`);
        const wrapKey = await deriveTotpWrapKey(signingKeySecret, salt, info);
        const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, wrapKey, enc.encode(base32Secret));
        return `v2.${b64uEnc(salt)}.${b64uEnc(iv)}.${b64uEnc(new Uint8Array(ct))}`;
    }

    const wrapKey = await deriveTotpWrapKey(signingKeySecret, salt, "idp-totp-secret-wrap-v1");
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, enc.encode(base32Secret));
    return `${b64uEnc(salt)}.${b64uEnc(iv)}.${b64uEnc(new Uint8Array(ct))}`;
}

/**
 * `encryptTotpSecret` 역연산. v1/v2 모두 자동 감지하여 복호화한다.
 *
 * - v2 ciphertext 는 userId 가 반드시 필요. 없으면 throw.
 * - v1 은 userId 없어도 복호화 가능 (레거시).
 *
 * 호출처에서 v1 을 만나면 복호화 후 즉시 v2 로 재암호화하여 lazy migration 을 진행한다.
 */
export async function decryptTotpSecret(encrypted: string, signingKeySecret: string, userId?: string): Promise<string> {
    if (encrypted.startsWith("v2.")) {
        if (!userId) throw new Error("userId required to decrypt v2 TOTP secret");
        const parts = encrypted.split(".");
        if (parts.length !== 4) throw new Error("Invalid encrypted TOTP secret format (v2)");
        const [, saltB64, ivB64, ctB64] = parts;
        const enc = new TextEncoder();
        const wrapKey = await deriveTotpWrapKey(signingKeySecret, b64uDec(saltB64), `idp-totp-secret-wrap-v2:${userId}`);
        const aad = enc.encode(`v2:${userId}`);
        const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64uDec(ivB64), additionalData: aad }, wrapKey, b64uDec(ctB64));
        return new TextDecoder().decode(plaintext);
    }

    // v1 (레거시): 형식 = salt.iv.ct
    const parts = encrypted.split(".");
    if (parts.length !== 3) throw new Error("Invalid encrypted TOTP secret format");
    const [saltB64, ivB64, ctB64] = parts;
    const wrapKey = await deriveTotpWrapKey(signingKeySecret, b64uDec(saltB64), "idp-totp-secret-wrap-v1");
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64uDec(ivB64) }, wrapKey, b64uDec(ctB64));
    return new TextDecoder().decode(plaintext);
}

/** 저장된 ciphertext 가 v1 (레거시) 인지 확인. v2 로 재암호화가 필요한지 판단할 때 사용한다. */
export function isLegacyTotpCiphertext(encrypted: string): boolean {
    return !encrypted.startsWith("v2.");
}

// ── OTP Auth URI ───────────────────────────────────────────────────────────────

/**
 * otpauth:// URI 생성 (QR 코드 소스로 사용).
 */
export function buildOtpAuthUri(base32Secret: string, username: string, issuer: string): string {
    const label = encodeURIComponent(`${issuer}:${username}`);
    const params = new URLSearchParams({
        secret: base32Secret,
        issuer,
        algorithm: "SHA1",
        digits: "6",
        period: "30",
    });
    return `otpauth://totp/${label}?${params.toString()}`;
}

/**
 * 새 TOTP base32 시크릿을 생성한다 (20 바이트 = 160 bit).
 */
export function generateTotpSecret(): string {
    return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}

// ── 백업 코드 ─────────────────────────────────────────────────────────────────

const BACKUP_CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 혼동 문자 제외

function randomBackupCode(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    return Array.from(bytes, (b) => BACKUP_CODE_CHARS[b % BACKUP_CODE_CHARS.length]).join("");
}

/**
 * 백업 코드 10개를 생성한다 (일회성, 화면 표시 후 해시만 저장).
 */
export function generateBackupCodes(): string[] {
    return Array.from({ length: 10 }, () => randomBackupCode());
}

/**
 * 백업 코드를 저장용 해시로 변환한다. ctrls M-4.
 *
 * 무염 SHA-256(fast hash)은 DB 유출 시 ~2^40 엔트로피의 코드를 전 사용자에 걸쳐 병렬로
 * GPU 크랙할 수 있어(오프라인 MFA 우회), 패스워드와 동일한 scrypt(salted, memory-hard)
 * KDF 를 재사용한다. 코드는 대문자 정규화 후 해싱한다.
 */
export async function hashBackupCode(code: string): Promise<string> {
    return hashPassword(code.toUpperCase());
}

/**
 * 입력한 코드가 저장된 해시와 일치하는지 검증한다.
 * - scrypt/argon2/pbkdf2 형식: 패스워드 KDF(verifyPassword)로 상수시간 검증.
 * - 레거시 무염 SHA-256 hex: 하위호환을 위해 상수시간 비교(이미 저장된 코드 대상).
 *   백업 코드는 일회성이라 사용 즉시 소진되므로 레거시 해시는 자연 소멸한다.
 */
export async function verifyBackupCode(code: string, storedHash: string): Promise<boolean> {
    if (storedHash.startsWith("scrypt$") || storedHash.startsWith("$argon2") || storedHash.startsWith("pbkdf2$")) {
        const { valid } = await verifyPassword(code.toUpperCase(), storedHash);
        return valid;
    }
    // 레거시 무염 SHA-256 hex.
    const enc = new TextEncoder();
    const digest = await crypto.subtle.digest("SHA-256", enc.encode(code.toUpperCase()));
    const legacy = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
    if (legacy.length !== storedHash.length) return false;
    let diff = 0;
    for (let i = 0; i < legacy.length; i++) {
        diff |= legacy.charCodeAt(i) ^ storedHash.charCodeAt(i);
    }
    return diff === 0;
}
