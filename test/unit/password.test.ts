import { describe, it, expect } from "vitest";
import { hashEncoded, Config } from "@hicaru/argon2-pure.js";
import { hashPassword, verifyPassword, timingSafeEqual } from "$lib/server/auth/password";

// 운영 scrypt 파라미터 (password.ts 와 동일해야 함) — 교차 검증용 상수.
const OP_N = 65536;
const OP_R = 8;
const OP_P = 2;

function bytesFromB64(b64: string): Uint8Array {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
function b64FromBytes(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes));
}

// scrypt$N=..,r=..,p=..$saltB64$hashB64 레코드를 파싱한다.
function parseScryptRecord(record: string) {
    const parts = record.split("$");
    expect(parts).toHaveLength(4);
    expect(parts[0]).toBe("scrypt");
    const params: Record<string, number> = {};
    for (const pair of parts[1].split(",")) {
        const [k, v] = pair.split("=");
        params[k] = Number(v);
    }
    return { params, salt: bytesFromB64(parts[2]), hash: bytesFromB64(parts[3]) };
}

describe("scrypt 해시 (hashPassword / verifyPassword)", () => {
    it("해시 → 검증 라운드트립 (현행 파라미터는 rehash 없음)", async () => {
        const record = await hashPassword("hunter2");
        const result = await verifyPassword("hunter2", record);
        expect(result.valid).toBe(true);
        expect(result.rehash).toBeUndefined();
    });

    it("오답 거부", async () => {
        const record = await hashPassword("hunter2");
        expect(await verifyPassword("wrong-password", record)).toEqual({ valid: false });
    });

    it("레코드 형식: 운영 파라미터(N=65536,r=8,p=2), salt 16B, derived 32B", async () => {
        const record = await hashPassword("pw");
        expect(record.startsWith("scrypt$N=65536,r=8,p=2$")).toBe(true);
        const { params, salt, hash } = parseScryptRecord(record);
        expect(params).toEqual({ N: OP_N, r: OP_R, p: OP_P });
        expect(salt).toHaveLength(16);
        expect(hash).toHaveLength(32);
    });

    it("같은 비밀번호라도 salt 랜덤화로 매번 다른 해시", async () => {
        const a = await hashPassword("same");
        const b = await hashPassword("same");
        expect(a).not.toBe(b);
        // 그럼에도 둘 다 검증 통과
        expect((await verifyPassword("same", a)).valid).toBe(true);
        expect((await verifyPassword("same", b)).valid).toBe(true);
    });

    it("손상된 scrypt 파라미터(N 비-2의거듭제곱) 거부", async () => {
        const { salt, hash } = parseScryptRecord(await hashPassword("pw"));
        const bad = `scrypt$N=1000,r=8,p=3$${b64FromBytes(salt)}$${b64FromBytes(hash)}`;
        expect(await verifyPassword("pw", bad)).toEqual({ valid: false });
    });

    it("과대 파라미터(N > 2^17) 거부 — 메모리 폭탄 방어", async () => {
        const { salt, hash } = parseScryptRecord(await hashPassword("pw"));
        const bad = `scrypt$N=262144,r=8,p=3$${b64FromBytes(salt)}$${b64FromBytes(hash)}`;
        expect(await verifyPassword("pw", bad)).toEqual({ valid: false });
    });
});

describe("상수시간 비교 (timingSafeEqual)", () => {
    it("동일 바이트열 true, 상이 false, 길이 불일치 false", () => {
        const a = new Uint8Array([1, 2, 3, 4]);
        expect(timingSafeEqual(a, new Uint8Array([1, 2, 3, 4]))).toBe(true);
        expect(timingSafeEqual(a, new Uint8Array([1, 2, 3, 5]))).toBe(false);
        expect(timingSafeEqual(a, new Uint8Array([1, 2, 3]))).toBe(false);
    });
});

describe("레거시 PBKDF2 검증 → scrypt 업그레이드", () => {
    async function makePbkdf2(password: string, iterations: number, digestLabel: string): Promise<string> {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
        // verifyPbkdf2 는 항상 SHA-256 으로 재파생하므로 정답 해시는 SHA-256 기반.
        const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: salt.buffer as ArrayBuffer, iterations }, keyMaterial, 256);
        return `pbkdf2$${digestLabel}:${iterations}$${b64FromBytes(salt)}$${b64FromBytes(new Uint8Array(bits))}`;
    }

    it("유효 pbkdf2(sha256, 100000) → valid + scrypt rehash", async () => {
        const record = await makePbkdf2("legacy-pw", 100_000, "sha256");
        const result = await verifyPassword("legacy-pw", record);
        expect(result.valid).toBe(true);
        expect(result.rehash?.startsWith("scrypt$")).toBe(true);
    });

    it("오답 거부", async () => {
        const record = await makePbkdf2("legacy-pw", 100_000, "sha256");
        expect(await verifyPassword("nope", record)).toEqual({ valid: false });
    });

    it("iteration 하한(100000) 미만 거부", async () => {
        const record = await makePbkdf2("legacy-pw", 99_999, "sha256");
        expect(await verifyPassword("legacy-pw", record)).toEqual({ valid: false });
    });

    it("digest 불일치(sha512 라벨) 거부", async () => {
        // 해시는 SHA-256 으로 만들었지만 라벨이 sha512 → digest 명시 일치 실패로 거부
        const record = await makePbkdf2("legacy-pw", 100_000, "sha512");
        expect(await verifyPassword("legacy-pw", record)).toEqual({ valid: false });
    });
});

describe("레거시 argon2id 검증 → scrypt 업그레이드", () => {
    function makeArgon2id(password: string): string {
        // 테스트 속도용 저강도 파라미터. 검증 경로(verifyEncoded)만 확인하면 충분.
        const cfg = new Config();
        cfg.memCost = 64;
        cfg.timeCost = 1;
        cfg.lanes = 1;
        cfg.hashLength = 16;
        const salt = new TextEncoder().encode("test-salt-16byte");
        return hashEncoded(new TextEncoder().encode(password), salt, cfg);
    }

    it("유효 argon2id → valid + scrypt rehash", async () => {
        const record = makeArgon2id("legacy-pw");
        expect(record.startsWith("$argon2id$")).toBe(true);
        const result = await verifyPassword("legacy-pw", record);
        expect(result.valid).toBe(true);
        expect(result.rehash?.startsWith("scrypt$")).toBe(true);
    });

    it("오답 거부", async () => {
        const record = makeArgon2id("legacy-pw");
        expect(await verifyPassword("nope", record)).toEqual({ valid: false });
    });
});

describe("TIMING_DUMMY_HASH (users.ts, S1 타이밍 균등화 상수)", () => {
    // users.ts 는 DB 의존이라 import 대상 외 — 상수 문자열만 복제해 형식을 교차 검증한다.
    const TIMING_DUMMY_HASH = "scrypt$N=65536,r=8,p=2$hVmifHhlsivEhcuMH7TzxA==$d+O6MqRdeYS7W67a6bV6U82qevX56IyHCLzbLe2krwk=";

    it("운영 scrypt 파라미터와 일치하는 유효 레코드 (salt 16B, hash 32B)", () => {
        const { params, salt, hash } = parseScryptRecord(TIMING_DUMMY_HASH);
        expect(params).toEqual({ N: OP_N, r: OP_R, p: OP_P });
        expect(salt).toHaveLength(16);
        expect(hash).toHaveLength(32);
    });

    it("verifyPassword 가 파싱/파생 가능한 레코드로 동작 (임의 입력은 불일치)", async () => {
        // 실제 scrypt 파생 1회를 태우되(타이밍 균등화 목적) 결과는 valid:false 여야 한다.
        const result = await verifyPassword("any-attacker-guess", TIMING_DUMMY_HASH);
        expect(result).toEqual({ valid: false });
    });
});
