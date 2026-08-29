import { describe, it, expect } from "vitest";
import ko from "../../src/lib/i18n/ko.json";
import en from "../../src/lib/i18n/en.json";
import { resolveMessage } from "../../src/lib/i18n/core";

// ko/en 카탈로그 정합성.
//
// resolveMessage 는 키를 못 찾으면 조용히 ko 로 폴백하고, ko 에도 없으면 키 문자열 자체를
// 돌려준다. 그래서 한쪽 카탈로그에만 키를 추가하는 실수가 런타임 에러 없이 넘어가고, 영어
// 사용자에게 한국어가 그대로 보이거나 화면에 `error_page.home` 같은 키가 노출된다.
// schema-parity 가 방언별 스키마를 묶어두는 것과 같은 목적으로 카탈로그를 묶어둔다.

type Catalog = { [key: string]: string | Catalog };

/** 중첩 객체를 "a.b.c" 형태의 평면 맵으로 만든다. */
function flatten(catalog: Catalog, prefix = ""): Map<string, string> {
    const out = new Map<string, string>();
    for (const [key, value] of Object.entries(catalog)) {
        const path = prefix ? `${prefix}.${key}` : key;
        if (typeof value === "string") out.set(path, value);
        else for (const [k, v] of flatten(value, path)) out.set(k, v);
    }
    return out;
}

/** `{{param}}` 플레이스홀더 이름 목록(정렬). */
function placeholders(message: string): string[] {
    return [...message.matchAll(/\{\{\s*([A-Za-z0-9_]+)\s*\}\}/g)].map((m) => m[1]).sort();
}

const koFlat = flatten(ko as Catalog);
const enFlat = flatten(en as Catalog);

describe("i18n 카탈로그 정합성", () => {
    it("ko 와 en 의 키 집합이 완전히 같다", () => {
        const onlyKo = [...koFlat.keys()].filter((k) => !enFlat.has(k)).sort();
        const onlyEn = [...enFlat.keys()].filter((k) => !koFlat.has(k)).sort();

        expect(onlyKo, "en.json 에 없는 키").toEqual([]);
        expect(onlyEn, "ko.json 에 없는 키").toEqual([]);
        expect(koFlat.size).toBeGreaterThan(0);
    });

    it("빈 문자열인 메시지가 없다", () => {
        const empty = [...koFlat, ...enFlat].filter(([, v]) => v.trim() === "").map(([k]) => k);
        expect(empty).toEqual([]);
    });

    it("같은 키의 플레이스홀더가 로케일 간 일치한다", () => {
        const mismatched = [...koFlat]
            .filter(([key, value]) => {
                const other = enFlat.get(key);
                return other !== undefined && placeholders(value).join(",") !== placeholders(other).join(",");
            })
            .map(([key]) => key);

        expect(mismatched, "번역 과정에서 {{param}} 이 빠지거나 이름이 달라진 키").toEqual([]);
    });

    it("resolveMessage 가 두 로케일 모두에서 키가 아닌 실제 메시지를 돌려준다", () => {
        // 이 작업에서 새로 추가한 키들 — 엔드포인트가 직접 렌더하는 화면들이 쓰는 값이라
        // 누락되면 화면에 키 문자열이 그대로 노출된다.
        const keys = [
            "error_page.not_found",
            "error_page.forbidden",
            "error_page.unavailable",
            "error_page.generic",
            "error_page.home",
            "error_page.csrf_title",
            "error_page.csrf_message",
            "oidc.logout_progress.title",
            "oidc.logout_progress.subtitle",
            "oidc.logout_confirm.title",
            "saml.sso_progress.title",
            "saml.sso_progress.subtitle",
            "saml.sso_progress.manual_submit",
        ];

        for (const key of keys) {
            for (const locale of ["ko", "en"] as const) {
                const message = resolveMessage(locale, key);
                expect(message, `${locale}:${key}`).not.toBe(key);
                expect(message.trim().length, `${locale}:${key}`).toBeGreaterThan(0);
            }
            // en 이 ko 로 폴백한 게 아니라 실제로 번역되어 있어야 한다.
            expect(resolveMessage("en", key), `en:${key} 가 ko 와 동일`).not.toBe(resolveMessage("ko", key));
        }
    });
});
