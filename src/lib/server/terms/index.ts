/**
 * 약관 문서 조회·판정·기록.
 *
 * ── 노출 범위 (T5-A) ───────────────────────────────────────────────────────────
 *
 * `client_terms` 매핑이 **없는** 문서는 전역 약관 — 로그인 직후 모든 사용자에게 요구한다(T1-A).
 * 매핑이 **있는** 문서는 그 앱으로 SSO 할 때 요구한다(T1-B). 매핑은 문서 id 가 아니라 `key` 로
 * 걸려 있어, 개정으로 version 이 올라가도 다시 걸 필요가 없다.
 *
 * ── 버전과 재동의 (T2-A) ───────────────────────────────────────────────────────
 *
 * 같은 `key` 의 최신 발행(version 이 가장 큰, publishedAt 이 있는) 문서가 현재 유효본이다.
 * 사용자의 동의 기록은 (key, version) 에 묶여 있으므로, version 이 올라가면 그 사용자에게는
 * 기록이 없는 상태가 되어 자동으로 재동의 대상이 된다. 이전 버전 행은 지우지 않아 "그때 무엇에
 * 동의했는가" 를 나중에도 답할 수 있다.
 *
 * ── 필수/선택 (T3-A) ───────────────────────────────────────────────────────────
 *
 * 필수 약관은 거부하면 진행할 수 없다. 선택은 거부해도 통과하지만 **거부도 기록한다** —
 * 그러지 않으면 "물어봤지만 거부했다" 와 "아직 안 물어봤다" 를 구분할 수 없어 매번 다시 묻게 된다.
 */
import { and, eq, inArray, isNotNull } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { clientTerms, termsDocuments, userTermAgreements } from "$lib/server/db/schema";
import { FALLBACK_LOCALE, type Locale } from "$lib/i18n/core";

export type TermsClientType = "oidc" | "saml";

export interface TermsItem {
    key: string;
    version: number;
    locale: Locale;
    title: string;
    body: string;
    required: boolean;
    displayOrder: number;
}

/** 같은 key 의 여러 행에서 유효본 하나를 고른다: 요청 로케일 우선, 없으면 기본 로케일, 그중 최신 version. */
function pickEffective(rows: TermsItem[], locale: Locale): TermsItem | null {
    const byLocale = rows.filter((r) => r.locale === locale);
    const candidates = byLocale.length > 0 ? byLocale : rows.filter((r) => r.locale === FALLBACK_LOCALE);
    if (candidates.length === 0) return null;
    return candidates.reduce((best, cur) => (cur.version > best.version ? cur : best));
}

export interface ListTermsOptions {
    locale: Locale;
    /** 지정하면 이 앱에 매핑된 약관도 함께 대상에 넣는다(T1-B). 없으면 전역 약관만(T1-A). */
    client?: { clientType: TermsClientType; clientRefId: string };
}

/**
 * 이 맥락에서 동의를 요구할 약관 목록(각 key 의 유효본). displayOrder → key 순으로 정렬한다.
 *
 * 전역/앱별 판정을 위해 매핑 테이블 전체를 한 번 읽는다 — "어떤 key 가 어느 앱에도 매핑되지
 * 않았는가" 를 알아야 전역을 고를 수 있고, 테넌트당 매핑 수는 작다.
 */
export async function listApplicableTerms(db: DB, tenantId: string, options: ListTermsOptions): Promise<TermsItem[]> {
    const published = await db
        .select({
            key: termsDocuments.key,
            version: termsDocuments.version,
            locale: termsDocuments.locale,
            title: termsDocuments.title,
            body: termsDocuments.body,
            required: termsDocuments.required,
            displayOrder: termsDocuments.displayOrder,
        })
        .from(termsDocuments)
        .where(and(eq(termsDocuments.tenantId, tenantId), isNotNull(termsDocuments.publishedAt)));
    if (published.length === 0) return [];

    const mappings = await db
        .select({ clientType: clientTerms.clientType, clientRefId: clientTerms.clientRefId, termsKey: clientTerms.termsKey })
        .from(clientTerms)
        .where(eq(clientTerms.tenantId, tenantId));

    const mappedKeys = new Set(mappings.map((m) => m.termsKey));
    const keysForThisClient = new Set(
        options.client ? mappings.filter((m) => m.clientType === options.client!.clientType && m.clientRefId === options.client!.clientRefId).map((m) => m.termsKey) : [],
    );

    const grouped = new Map<string, TermsItem[]>();
    for (const row of published) {
        // 전역(어느 앱에도 매핑되지 않음) 또는 이 앱에 매핑된 것만.
        if (mappedKeys.has(row.key) && !keysForThisClient.has(row.key)) continue;
        const list = grouped.get(row.key) ?? [];
        list.push(row as TermsItem);
        grouped.set(row.key, list);
    }

    const out: TermsItem[] = [];
    for (const rows of grouped.values()) {
        const picked = pickEffective(rows, options.locale);
        if (picked) out.push(picked);
    }
    return out.sort((a, b) => a.displayOrder - b.displayOrder || a.key.localeCompare(b.key));
}

export interface TermsDecisionState {
    /** 아직 묻지 않은 항목 — 화면에 올린다. */
    pending: TermsItem[];
    /** 진행을 막는 항목 (필수 중 미동의). */
    blocking: TermsItem[];
}

/**
 * 이미 결정한 항목을 걸러낸다.
 *
 * (key, version) 기록이 있으면 결정된 것으로 본다 — 선택 항목을 거부한 경우도 기록이 남아 다시
 * 묻지 않는다. 필수 항목을 거부한 기록이 있으면 여전히 진행을 막아야 하므로 blocking 에 남긴다.
 */
export async function evaluateTerms(db: DB, tenantId: string, userId: string, items: readonly TermsItem[]): Promise<TermsDecisionState> {
    if (items.length === 0) return { pending: [], blocking: [] };

    const rows = await db
        .select({ termsKey: userTermAgreements.termsKey, version: userTermAgreements.version, agreed: userTermAgreements.agreed })
        .from(userTermAgreements)
        .where(
            and(
                eq(userTermAgreements.tenantId, tenantId),
                eq(userTermAgreements.userId, userId),
                inArray(
                    userTermAgreements.termsKey,
                    items.map((i) => i.key),
                ),
            ),
        );

    const decided = new Map<string, boolean>();
    for (const r of rows) decided.set(`${r.termsKey}@${r.version}`, r.agreed);

    const pending: TermsItem[] = [];
    const blocking: TermsItem[] = [];
    for (const item of items) {
        const answer = decided.get(`${item.key}@${item.version}`);
        if (answer === undefined) {
            pending.push(item);
            if (item.required) blocking.push(item);
            continue;
        }
        // 필수를 거부한 기록이 있으면 다시 물어야 한다 — 거부 상태로 통과시킬 수는 없다.
        if (item.required && !answer) {
            pending.push(item);
            blocking.push(item);
        }
    }
    return { pending, blocking };
}

export interface TermsDecisionInput {
    key: string;
    version: number;
    locale: Locale;
    agreed: boolean;
}

/**
 * 동의/거부를 기록한다. 같은 (user, key, version) 은 유니크하므로 재제출은 값을 덮어쓴다
 * (선택 항목을 나중에 승인으로 바꾸는 경우).
 */
export async function recordTermDecisions(db: DB, tenantId: string, userId: string, decisions: readonly TermsDecisionInput[], now: Date = new Date()): Promise<void> {
    for (const d of decisions) {
        await db.delete(userTermAgreements).where(and(eq(userTermAgreements.userId, userId), eq(userTermAgreements.termsKey, d.key), eq(userTermAgreements.version, d.version)));
        await db.insert(userTermAgreements).values({
            tenantId,
            userId,
            termsKey: d.key,
            version: d.version,
            locale: d.locale,
            agreed: d.agreed,
            agreedAt: now,
        });
    }
}

/**
 * 약관 본문(마크다운 부분집합)을 HTML 로 만든다.
 *
 * **이스케이프를 먼저 하고 그 위에 서식만 얹는다** — 구조적으로 원본 HTML 이 살아남을 수 없다.
 * 의존성을 늘리지 않기 위한 최소 구현이고, 지원 범위는 관리 화면에 안내한다.
 *
 * 지원: `## 제목`, `**굵게**`, `- 목록`, `[문구](https://…)`, 빈 줄 = 단락.
 * 링크는 http(s) 만 허용한다(javascript: 등은 링크로 만들지 않고 문구만 남긴다).
 */
export function renderTermsBody(markdown: string): string {
    const escaped = markdown.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

    const inline = (text: string): string =>
        text
            .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
            // 이스케이프 후이므로 URL 안의 위험 문자는 이미 무해하다. scheme 만 제한한다.
            .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');

    const blocks: string[] = [];
    for (const rawBlock of escaped.split(/\n{2,}/)) {
        const block = rawBlock.trim();
        if (!block) continue;

        const lines = block.split("\n");
        if (lines.every((l) => /^[-*]\s+/.test(l.trim()))) {
            const items = lines.map((l) => `<li>${inline(l.trim().replace(/^[-*]\s+/, ""))}</li>`).join("");
            blocks.push(`<ul>${items}</ul>`);
            continue;
        }

        const heading = /^(#{1,3})\s+(.*)$/.exec(lines[0]);
        if (heading && lines.length === 1) {
            const level = Math.min(heading[1].length + 1, 4); // # → h2 (문서 제목은 h1 이 이미 쓴다)
            blocks.push(`<h${level}>${inline(heading[2])}</h${level}>`);
            continue;
        }

        blocks.push(`<p>${lines.map((l) => inline(l)).join("<br />")}</p>`);
    }
    return blocks.join("");
}
