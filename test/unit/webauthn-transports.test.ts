import { describe, it, expect } from "vitest";
import { parseStoredTransports } from "$lib/server/auth/webauthn";

describe("parseStoredTransports", () => {
    it("정상 배열은 그대로 반환", () => {
        expect(parseStoredTransports('["internal","hybrid"]')).toEqual(["internal", "hybrid"]);
    });

    it("null / 빈 문자열 / undefined 는 undefined", () => {
        expect(parseStoredTransports(null)).toBeUndefined();
        expect(parseStoredTransports("")).toBeUndefined();
        expect(parseStoredTransports(undefined)).toBeUndefined();
    });

    it("JSON 이 아닌 문자열은 throw 하지 않고 undefined", () => {
        expect(() => parseStoredTransports("not-json{")).not.toThrow();
        expect(parseStoredTransports("not-json{")).toBeUndefined();
    });

    it.each(["{}", '"usb"', "1", "null"])("배열이 아닌 값 %s 는 undefined", (raw) => {
        expect(parseStoredTransports(raw)).toBeUndefined();
    });

    it("숫자 원소가 섞인 배열은 undefined", () => {
        expect(parseStoredTransports('["usb",1]')).toBeUndefined();
    });

    it("길이 16 은 통과, 17 은 undefined", () => {
        expect(parseStoredTransports(JSON.stringify(Array(16).fill("usb")))).toHaveLength(16);
        expect(parseStoredTransports(JSON.stringify(Array(17).fill("usb")))).toBeUndefined();
    });
});
