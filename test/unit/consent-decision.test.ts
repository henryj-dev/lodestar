import { describe, it, expect } from "vitest";
import { decideConsent, formatScopeList, parseScopeList } from "$lib/server/consent";

// 동의 판정은 DB 를 보지 않는 순수 함수다. 여기서 규칙을 고정한다.
//
// 핵심 성질 두 개:
//   1. **필수 항목이 모두 승인돼 있으면 통과한다** — 선택 항목이 빠졌다는 이유만으로 다시 묻지
//      않는다. 그러지 않으면 한 번 거부한 사용자에게 매번 같은 화면이 뜬다.
//   2. **발급 범위는 요청 ∩ 동의** — 거부된 선택 항목은 토큰에 실리지 않는다. 화면이 아니라
//      이 계산이 실제 강제 지점이다.

describe("parseScopeList / formatScopeList", () => {
    it("공백으로 쪼개고 중복을 제거하며 순서를 보존한다", () => {
        expect(parseScopeList("openid profile openid email")).toEqual(["openid", "profile", "email"]);
    });

    it("여러 공백·탭·줄바꿈을 견딘다", () => {
        expect(parseScopeList("openid \t profile\nemail  ")).toEqual(["openid", "profile", "email"]);
    });

    it("null·빈 문자열은 빈 배열", () => {
        expect(parseScopeList(null)).toEqual([]);
        expect(parseScopeList(undefined)).toEqual([]);
        expect(parseScopeList("   ")).toEqual([]);
    });

    it("왕복한다", () => {
        expect(formatScopeList(parseScopeList("openid profile"))).toBe("openid profile");
    });
});

describe("decideConsent: 첫 동의", () => {
    it("저장된 동의가 없으면 화면을 띄운다", () => {
        const d = decideConsent({ requested: ["openid", "profile"], optional: [], granted: [] });

        expect(d.satisfied).toBe(false);
        expect(d.required).toEqual(["openid", "profile"]);
        expect(d.optional).toEqual([]);
        expect(d.newlyRequested).toEqual(["openid", "profile"]);
        expect(d.alreadyGranted).toEqual([]);
    });

    it("optionalScopes 로 요청을 필수/선택으로 나눈다", () => {
        const d = decideConsent({ requested: ["openid", "profile", "phone", "address"], optional: ["phone", "address"], granted: [] });

        expect(d.required).toEqual(["openid", "profile"]);
        expect(d.optional).toEqual(["phone", "address"]);
    });

    it("클라이언트가 요청하지 않은 선택 항목은 화면에 오르지 않는다", () => {
        const d = decideConsent({ requested: ["openid"], optional: ["phone"], granted: [] });

        expect(d.optional).toEqual([]);
        expect(d.required).toEqual(["openid"]);
    });
});

describe("decideConsent: 재방문", () => {
    it("필수 항목이 모두 승인돼 있으면 통과한다", () => {
        const d = decideConsent({ requested: ["openid", "profile"], optional: [], granted: ["openid", "profile"] });

        expect(d.satisfied).toBe(true);
        expect(d.effectiveScopes).toEqual(["openid", "profile"]);
    });

    it("승인 범위가 더 넓어도 통과한다 (요청이 부분집합)", () => {
        const d = decideConsent({ requested: ["openid"], optional: [], granted: ["openid", "profile", "email"] });

        expect(d.satisfied).toBe(true);
        expect(d.effectiveScopes).toEqual(["openid"]); // 요청한 것만 발급
    });

    it("필수 항목이 늘어나면 다시 묻고, 새 항목만 강조한다", () => {
        const d = decideConsent({ requested: ["openid", "profile", "email"], optional: [], granted: ["openid", "profile"] });

        expect(d.satisfied).toBe(false);
        expect(d.newlyRequested).toEqual(["email"]);
        expect(d.alreadyGranted).toEqual(["openid", "profile"]);
    });

    it("선택 항목이 거부된 상태여도 다시 묻지 않는다 (반복 노출 방지)", () => {
        const d = decideConsent({ requested: ["openid", "phone"], optional: ["phone"], granted: ["openid"] });

        expect(d.satisfied).toBe(true);
        // 거부한 선택 항목은 발급되지 않는다 — 여기가 강제 지점이다.
        expect(d.effectiveScopes).toEqual(["openid"]);
        expect(d.effectiveScopes).not.toContain("phone");
    });

    it("선택 항목만 새로 생겨도 다시 묻지 않는다", () => {
        const d = decideConsent({ requested: ["openid", "address"], optional: ["address"], granted: ["openid"] });

        expect(d.satisfied).toBe(true);
        expect(d.effectiveScopes).toEqual(["openid"]);
    });

    it("필수가 늘어나 화면을 띄우는 경우에는 미승인 선택 항목도 함께 제안한다", () => {
        const d = decideConsent({ requested: ["openid", "email", "phone"], optional: ["phone"], granted: ["openid"] });

        expect(d.satisfied).toBe(false);
        expect(d.required).toEqual(["openid", "email"]);
        expect(d.optional).toEqual(["phone"]);
        expect(d.newlyRequested).toEqual(["email", "phone"]);
    });
});

describe("decideConsent: prompt=consent", () => {
    it("저장된 동의를 무시하고 다시 묻는다", () => {
        const d = decideConsent({ requested: ["openid", "profile"], optional: [], granted: ["openid", "profile"], forceConsent: true });

        expect(d.satisfied).toBe(false);
        // 이미 승인된 것은 접어 표시할 수 있게 그대로 알려준다.
        expect(d.alreadyGranted).toEqual(["openid", "profile"]);
        expect(d.newlyRequested).toEqual([]);
    });

    it("강제 재동의에서도 필수/선택 구분은 유지된다", () => {
        const d = decideConsent({ requested: ["openid", "phone"], optional: ["phone"], granted: ["openid"], forceConsent: true });

        expect(d.satisfied).toBe(false);
        expect(d.required).toEqual(["openid"]);
        expect(d.optional).toEqual(["phone"]);
    });
});

describe("decideConsent: SAML (스코프 대신 속성명)", () => {
    it("속성 목록도 같은 규칙으로 판정한다", () => {
        const d = decideConsent({ requested: ["email", "displayName", "department"], optional: ["department"], granted: ["email", "displayName"] });

        expect(d.satisfied).toBe(true);
        expect(d.effectiveScopes).toEqual(["email", "displayName"]);
    });

    it("SP 가 속성을 추가하면 다시 묻는다", () => {
        const d = decideConsent({ requested: ["email", "displayName", "jobTitle"], optional: [], granted: ["email", "displayName"] });

        expect(d.satisfied).toBe(false);
        expect(d.newlyRequested).toEqual(["jobTitle"]);
    });
});

describe("decideConsent: 경계", () => {
    it("요청이 비어 있으면 통과한다", () => {
        const d = decideConsent({ requested: [], optional: [], granted: [] });
        expect(d.satisfied).toBe(true);
        expect(d.effectiveScopes).toEqual([]);
    });

    it("요청에 중복이 있어도 한 번만 센다", () => {
        const d = decideConsent({ requested: ["openid", "openid", "profile"], optional: [], granted: ["openid", "profile"] });
        expect(d.satisfied).toBe(true);
        expect(d.effectiveScopes).toEqual(["openid", "profile"]);
    });
});
