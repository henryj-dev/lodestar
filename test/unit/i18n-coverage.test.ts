import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import ko from "../../src/lib/i18n/ko.json";
import en from "../../src/lib/i18n/en.json";

// 코드가 참조하는 i18n 키가 카탈로그에 실제로 있는지 본다.
//
// i18n-parity 는 ko/en 사이의 드리프트만 잡는다. 양쪽에 **똑같이 없는** 키는 통과해 버리는데,
// resolveMessage 는 그 경우 키 문자열을 그대로 반환하므로 사용자 화면에
// `reset_password.err_expired_link` 같은 값이 노출된다. 예외도 로그도 남지 않아서 조용히 살아남는다.
//
// 실제로 이 테스트를 만들 때 6개 누락(find_id/find_password/reset_password)과 잘못된 키 경로
// 2개(`sessions.err_*` → 실제 위치는 `account.sessions.*`)를 찾아냈다.

type Catalog = { [key: string]: string | Catalog };

function flatten(catalog: Catalog, prefix = ""): Set<string> {
    const out = new Set<string>();
    for (const [key, value] of Object.entries(catalog)) {
        const path = prefix ? `${prefix}.${key}` : key;
        if (typeof value === "string") out.add(path);
        else for (const k of flatten(value, path)) out.add(k);
    }
    return out;
}

/** src 아래의 .ts / .svelte 를 모은다. 카탈로그 자체와 테스트 스텁은 제외. */
function sourceFiles(dir: string, acc: string[] = []): string[] {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) {
            if (entry.name === "i18n") continue;
            sourceFiles(path, acc);
        } else if (entry.name.endsWith(".ts") || entry.name.endsWith(".svelte")) {
            acc.push(path);
        }
    }
    return acc;
}

// `translate(locale, "a.b")` 와 `t("a.b")` 의 **리터럴** 키만 뽑는다. 템플릿 리터럴로 조립하는
// 동적 키(예: `skins.skin_type_${skin.skinType}`)는 정적으로 검증할 수 없어 대상에서 빠진다.
const KEY_PATTERNS = [/translate\(\s*[^,]+,\s*"([a-z_][a-z0-9_]*(?:\.[a-z0-9_]+)+)"/g, /(?<![\w$])t\(\s*"([a-z_][a-z0-9_]*(?:\.[a-z0-9_]+)+)"/g];

function referencedKeys(): Map<string, string[]> {
    const found = new Map<string, string[]>();
    for (const file of sourceFiles("src")) {
        const text = readFileSync(file, "utf-8");
        for (const pattern of KEY_PATTERNS) {
            for (const match of text.matchAll(pattern)) {
                const key = match[1];
                const where = found.get(key) ?? [];
                if (!where.includes(file)) where.push(file);
                found.set(key, where);
            }
        }
    }
    return found;
}

const koKeys = flatten(ko as Catalog);
const enKeys = flatten(en as Catalog);
const referenced = referencedKeys();

describe("i18n 코드→카탈로그 커버리지", () => {
    it("리터럴 키를 실제로 수집한다 (정규식이 죽으면 테스트가 무의미해지므로)", () => {
        expect(referenced.size).toBeGreaterThan(300);
        expect(referenced.has("login.err_missing_credentials")).toBe(true);
    });

    it("코드가 참조하는 모든 리터럴 키가 ko 카탈로그에 있다", () => {
        const missing = [...referenced.entries()]
            .filter(([key]) => !koKeys.has(key))
            .map(([key, files]) => `${key}  ← ${files.join(", ")}`)
            .sort();

        expect(missing, "카탈로그에 없는 키 (화면에 키 문자열이 그대로 노출된다)").toEqual([]);
    });

    it("코드가 참조하는 모든 리터럴 키가 en 카탈로그에 있다", () => {
        const missing = [...referenced.entries()]
            .filter(([key]) => !enKeys.has(key))
            .map(([key, files]) => `${key}  ← ${files.join(", ")}`)
            .sort();

        expect(missing).toEqual([]);
    });
});
