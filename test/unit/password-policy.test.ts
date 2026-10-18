import { describe, it, expect } from "vitest";
import { checkPasswordPolicy, hashBackupSecret, hashPassword, verifyPassword } from "../../src/lib/server/auth/password";
import { hashBackupCode, verifyBackupCode } from "../../src/lib/server/auth/totp";

// 회원 공통 정책(2026-10-18): 8자 이상, 영소문자·영대문자·숫자·특수문자 중 3종류 이상, 최대 길이 없음,
// 판정·해시 전에 NFC 정규화.

describe("checkPasswordPolicy", () => {
    it("8자 미만은 too_short", () => {
        expect(checkPasswordPolicy("Ab1!xyz")).toBe("too_short");
    });

    it("2종류뿐이면 weak_composition", () => {
        expect(checkPasswordPolicy("abcdefgh")).toBe("weak_composition");
        expect(checkPasswordPolicy("abcd1234")).toBe("weak_composition");
        expect(checkPasswordPolicy("correct horse battery")).toBe("weak_composition"); // 소문자 + 공백(특수)
    });

    it("3종류 이상이면 통과", () => {
        expect(checkPasswordPolicy("abcd123!")).toBeNull();
        expect(checkPasswordPolicy("Abcdefg1")).toBeNull();
        expect(checkPasswordPolicy("Ab1!Ab1!")).toBeNull();
    });

    it("영문자·숫자가 아닌 모든 문자는 특수문자다(한글 포함)", () => {
        expect(checkPasswordPolicy("비밀번호abc12")).toBeNull(); // 한글(특수) + 소문자 + 숫자
    });

    it("길이는 NFC 정규화 뒤 코드 포인트로 센다", () => {
        // "가" 를 자모로 분해(NFD)하면 3 코드 포인트지만 NFC 로는 1자다.
        const decomposed = "가".normalize("NFD").repeat(3) + "ab1"; // NFC 로 6자
        expect(checkPasswordPolicy(decomposed)).toBe("too_short");
    });

    it("최대 길이 제한이 없다", () => {
        expect(checkPasswordPolicy("Aa1!" + "x".repeat(10_000))).toBeNull();
    });
});

describe("NFC 정규화", () => {
    const composed = "Pässwörd1".normalize("NFC");
    const decomposed = composed.normalize("NFD");

    it("조합형으로 만든 해시를 분해형 입력으로도 통과한다", async () => {
        const record = await hashPassword(composed);
        expect((await verifyPassword(decomposed, record)).valid).toBe(true);
    });

    it("정규화 도입 전(원문 그대로) 해시도 통과하고, 정규형으로 다시 저장하게 한다", async () => {
        // 예전 hashPassword 는 정규화 없이 원문을 해시했다 — 정규화하지 않는 해시로 그 상황을 만든다.
        const legacy = await hashBackupSecret(decomposed);
        const result = await verifyPassword(decomposed, legacy);
        expect(result.valid).toBe(true);
        expect(result.rehash).toBeDefined();
        expect((await verifyPassword(composed, result.rehash!)).valid).toBe(true);
    });
});

describe("백업 코드 해시", () => {
    it("비밀번호보다 가벼운 고정 파라미터(N=2^15, r=8, p=3)를 쓰고 검증된다", async () => {
        const record = await hashBackupCode("abcd2345");
        expect(record.startsWith("scrypt$N=32768,r=8,p=3$")).toBe(true);
        expect(await verifyBackupCode("ABCD2345", record)).toBe(true);
        expect(await verifyBackupCode("WRONG000", record)).toBe(false);
    });
});
