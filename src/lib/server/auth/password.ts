/**
 * 패스워드 해싱 유틸리티
 *
 * 신규 해시: scrypt (node:crypto 네이티브 — Workers nodejs_compat / Node / Bun 공통)
 * 레거시 해시: argon2id (@hicaru/argon2-pure.js), PBKDF2-SHA256 — 검증 후 scrypt 로 자동 업그레이드
 *
 * argon2id → scrypt 전환 이유: @hicaru/argon2-pure.js 는 순수 JS 라 verify 1회에
 * ~4.4초의 CPU 를 태운다 (Workers 요청 지연의 주범). Workers 는 런타임 WASM
 * 바이트 컴파일을 금지해 WASM argon2 도입에는 빌드 배관이 필요한 반면,
 * node:crypto scrypt 는 2025-04 부터 Workers 에서 네이티브(BoringSSL) 지원되어
 * 동일한 메모리 하드 강도를 ~100ms 에 처리한다 (OWASP 승인 KDF).
 *
 * 파라미터(회원 공통 정책 2026-10-18): N=2^16, r=8, p=2 — 메모리 128·N·r = 64 MiB.
 * Workers 한도(scrypt N×r×p ≤ 2^20, isolate 128 MB)에 맞춘 값이다. 예전 N=2^15/p=3 해시는
 * 로그인 성공 시 현행 파라미터로 다시 저장된다(verifyPassword 의 rehash).
 *
 * 백업 코드는 무작위 고엔트로피 값이라 비밀번호만큼의 비용이 필요 없고, 검증 때 최대 10개를
 * 순서대로 대조하므로 예전 파라미터(N=2^15, r=8, p=3)를 그대로 쓴다(hashBackupSecret).
 *
 * 비밀번호는 판정·해시 전에 NFC 로 정규화한다. 같은 글자를 조합형/완성형으로 입력해도 같은
 * 비밀번호로 본다. 정규화 도입 전에 만든 해시는 원문으로도 한 번 더 대조해 통과시키고 NFC 로 다시 저장한다.
 */

import { randomBytes, scrypt as scryptCallback } from "node:crypto";
import { verifyEncoded } from "@hicaru/argon2-pure.js";

// ── scrypt ────────────────────────────────────────────────────────────────────

// ── 비밀번호 정책 ─────────────────────────────────────────────────────────────
//
// 최소 8자(NFC 정규화 후 코드 포인트 기준), 영소문자·영대문자·숫자·특수문자 4종류 중 3종류 이상.
// 특수문자는 영문자·숫자가 아닌 모든 문자다(한글 등 포함). 최대 길이는 두지 않는다 — 대신 로그인·가입·
// 재설정 요청 본문을 64 KiB 로 제한해 자원 낭비를 막는다(hooks.server.ts, AUTH_BODY_LIMIT_BYTES).
export const MIN_PASSWORD_LENGTH = 8;
const MIN_PASSWORD_CLASSES = 3;

export type PasswordPolicyViolation = "too_short" | "weak_composition";

/** 판정과 해시에 쓰는 정규형. */
export function normalizePassword(password: string): string {
    return password.normalize("NFC");
}

/** 정책을 어기면 사유를, 지키면 null 을 돌려준다. */
export function checkPasswordPolicy(password: string): PasswordPolicyViolation | null {
    const normalized = normalizePassword(password);
    if ([...normalized].length < MIN_PASSWORD_LENGTH) return "too_short";
    let classes = 0;
    if (/[a-z]/.test(normalized)) classes += 1;
    if (/[A-Z]/.test(normalized)) classes += 1;
    if (/[0-9]/.test(normalized)) classes += 1;
    if (/[^A-Za-z0-9]/.test(normalized)) classes += 1;
    return classes >= MIN_PASSWORD_CLASSES ? null : "weak_composition";
}

const SCRYPT_N = 65536; // 2^16
const SCRYPT_R = 8;
const SCRYPT_P = 2;
const SCRYPT_KEY_LENGTH = 32;
const SCRYPT_SALT_LENGTH = 16;
// 128·N·r = 64 MiB 가 maxmem 과 같으면 Node/BoringSSL 이 거부하므로 여유를 둔다.
const SCRYPT_MAXMEM = 96 * 1024 * 1024;

// 백업 코드 전용(무작위 고엔트로피) — 위 주석 참고.
const BACKUP_SCRYPT_N = 32768; // 2^15
const BACKUP_SCRYPT_R = 8;
const BACKUP_SCRYPT_P = 3;

// 저장된 해시의 파라미터 파싱 시 허용 상한 — 손상/조작된 레코드가 요청당
// 과도한 메모리/CPU 를 유발하지 않도록 방어.
const SCRYPT_MAX_N = 131072; // 2^17
const SCRYPT_MAX_R = 32;
const SCRYPT_MAX_P = 16;

function deriveScrypt(password: string, salt: Uint8Array, keyLength: number, N: number, r: number, p: number): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
        scryptCallback(password, salt, keyLength, { N, r, p, maxmem: SCRYPT_MAXMEM }, (err, derived) => {
            if (err) reject(err);
            else resolve(new Uint8Array(derived.buffer, derived.byteOffset, derived.byteLength));
        });
    });
}

async function hashScrypt(secret: string, N: number, r: number, p: number): Promise<string> {
    const salt = new Uint8Array(randomBytes(SCRYPT_SALT_LENGTH));
    const derived = await deriveScrypt(secret, salt, SCRYPT_KEY_LENGTH, N, r, p);
    return `scrypt$N=${N},r=${r},p=${p}$${bytesToBase64(salt)}$${bytesToBase64(derived)}`;
}

/** 비밀번호 해시. NFC 로 정규화한 뒤 현행 파라미터로 만든다. */
export async function hashPassword(password: string): Promise<string> {
    return hashScrypt(normalizePassword(password), SCRYPT_N, SCRYPT_R, SCRYPT_P);
}

/** 백업 코드처럼 무작위 고엔트로피 값의 해시. 정규화하지 않는다. */
export async function hashBackupSecret(secret: string): Promise<string> {
    return hashScrypt(secret, BACKUP_SCRYPT_N, BACKUP_SCRYPT_R, BACKUP_SCRYPT_P);
}

/**
 * 해시 대조만 한다(재해시 없음, 정규화 없음). 백업 코드 검증용 — 현행 비밀번호 파라미터와 달라도
 * 다시 저장할 필요가 없다.
 */
export async function verifyKdfHash(secret: string, record: string): Promise<boolean> {
    return (await verifyRecord(secret, record)).valid;
}

async function verifyScrypt(password: string, record: string): Promise<{ valid: boolean; paramsCurrent: boolean }> {
    const invalid = { valid: false, paramsCurrent: true };
    const parts = record.split("$");
    if (parts.length !== 4) return invalid;
    const [, params, saltB64, hashB64] = parts;

    const parsed: Record<string, number> = {};
    for (const pair of params.split(",")) {
        const [key, value] = pair.split("=");
        parsed[key] = Number(value);
    }
    const { N, r, p } = parsed;
    if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return invalid;
    if (N < 2 || (N & (N - 1)) !== 0 || N > SCRYPT_MAX_N) return invalid;
    if (r < 1 || r > SCRYPT_MAX_R || p < 1 || p > SCRYPT_MAX_P) return invalid;

    try {
        const salt = base64ToBytes(saltB64);
        const storedHash = base64ToBytes(hashB64);
        const derived = await deriveScrypt(password, salt, storedHash.length, N, r, p);
        return {
            valid: timingSafeEqual(derived, storedHash),
            paramsCurrent: N === SCRYPT_N && r === SCRYPT_R && p === SCRYPT_P,
        };
    } catch {
        return invalid;
    }
}

// ── 공통 유틸 ─────────────────────────────────────────────────────────────────

function bytesToBase64(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(value: string): Uint8Array {
    return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

export function timingSafeEqual(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) return false;
    let difference = 0;
    for (let index = 0; index < left.length; index += 1) {
        difference |= left[index] ^ right[index];
    }
    return difference === 0;
}

// ── 검증 진입점 ───────────────────────────────────────────────────────────────

export async function verifyPassword(
    password: string,
    record: string,
): Promise<{
    valid: boolean;
    rehash?: string;
}> {
    const normalized = normalizePassword(password);
    const result = await verifyRecord(normalized, record);
    if (result.valid) {
        return result.paramsCurrent ? { valid: true } : { valid: true, rehash: await hashPassword(password) };
    }
    // NFC 도입 전 해시는 사용자가 입력한 원문(비정규형)으로 만들어졌을 수 있다. 원문이 정규형과 다를 때만
    // 한 번 더 대조하고, 맞으면 정규형으로 다시 저장해 다음부터는 이 분기를 타지 않게 한다.
    if (normalized !== password && (await verifyRecord(password, record)).valid) {
        return { valid: true, rehash: await hashPassword(password) };
    }
    return { valid: false };
}

/** 저장 형식(scrypt/argon2/pbkdf2)별 대조. paramsCurrent=false 면 현행 scrypt 로 다시 저장해야 한다. */
async function verifyRecord(password: string, record: string): Promise<{ valid: boolean; paramsCurrent: boolean }> {
    // scrypt (현행 형식) — 파라미터가 이후 상향됐으면 paramsCurrent=false 로 알려 다시 저장하게 한다.
    if (record.startsWith("scrypt$")) {
        return verifyScrypt(password, record);
    }

    // argon2id 레거시 (@hicaru 순수 JS — verify 1회 ~4.4초) — 통과하면 scrypt 로 다시 저장한다.
    if (record.startsWith("$argon2")) {
        const valid = verifyEncoded(record, new TextEncoder().encode(password));
        return { valid, paramsCurrent: false };
    }

    // PBKDF2 레거시 — 통과하면 scrypt 로 다시 저장한다.
    if (record.startsWith("pbkdf2$")) {
        return { valid: Boolean(await verifyPbkdf2(password, record)), paramsCurrent: false };
    }

    return { valid: false, paramsCurrent: true };
}

// ── PBKDF2 레거시 검증 (신규 해싱에는 사용하지 않음) ──────────────────────────

const PBKDF2_ITERATIONS = 100_000;

async function verifyPbkdf2(password: string, record: string): Promise<boolean> {
    const parts = record.split("$");
    if (parts.length !== 4) return false;
    const [, params, saltB64, hashB64] = parts;
    const [digest, iterationsStr] = params?.split(":") ?? [];
    const iterations = Number(iterationsStr);
    // ctrls L-3 (H-AUTH-4 묶음): 기존 조건은 && 라서 사실상 모든 입력이 통과됐다.
    // digest 알고리즘 명시 일치 + iterations 최소값 강제로 정정.
    if (digest !== "sha256" || !Number.isFinite(iterations) || iterations < PBKDF2_ITERATIONS) return false;

    const salt = base64ToBytes(saltB64);
    const storedHash = base64ToBytes(hashB64);
    const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: salt.buffer as ArrayBuffer, iterations: iterations || PBKDF2_ITERATIONS }, keyMaterial, 256);
    return timingSafeEqual(new Uint8Array(bits), storedHash);
}
