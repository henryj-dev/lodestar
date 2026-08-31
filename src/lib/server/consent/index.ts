/**
 * 첫 사용 동의(consent) 판정과 기록.
 *
 * OIDC 와 SAML 을 같은 테이블(`user_client_consents`)로 다룬다 — "이 서비스에 무엇을 내보내는가"
 * 라는 축이 같기 때문이다. OIDC 는 스코프 목록, SAML 은 SP 의 `allowedAttributes` 목록을 동의
 * 대상으로 쓴다.
 *
 * ── 판정 규칙 (C1-C: 필수/선택 2단) ─────────────────────────────────────────────
 *
 * 요청 항목을 클라이언트의 `optionalScopes` 로 필수/선택으로 나눈 뒤,
 *
 *     충족 = 필수 항목 전체가 저장된 동의에 포함됨
 *
 * **선택 항목이 빠져 있다는 이유만으로는 다시 묻지 않는다.** 그러지 않으면 `phone` 을 한 번
 * 거부한 사용자에게 매 로그인마다 같은 화면이 뜬다(스키마에 "물어봤음" 을 따로 두지 않고
 * 승인된 것만 담는 선택의 결과다). 선택 항목을 다시 제안할 수단은 두 가지로 충분하다.
 *
 *   - RP 가 `prompt=consent` 를 보낸다 (강제 재동의)
 *   - 사용자가 계정 화면에서 동의를 철회하고 다시 승인한다
 *
 * 필수 항목이 늘어나 화면을 띄우는 경우에는, 아직 승인되지 않은 선택 항목도 함께 제안한다
 * (이미 화면을 보여주는 참에 묻는 것이므로 추가 마찰이 없다).
 *
 * ── 발급 범위 ──────────────────────────────────────────────────────────────────
 *
 * 판정이 통과해도 **발급되는 scope 는 요청 ∩ 동의** 다. 거부된 선택 항목은 토큰과 UserInfo 에
 * 실리지 않는다 — 여기가 실제 강제 지점이고, 화면은 그 결정을 받는 곳일 뿐이다.
 */
import { and, desc, eq, isNull } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { userClientConsents } from "$lib/server/db/schema";
import type { UserClientConsent } from "$lib/server/db/schema";

export type ConsentClientType = "oidc" | "saml";

/** 공백 구분 문자열 → 중복 없는 목록(순서 보존). */
export function parseScopeList(value: string | null | undefined): string[] {
    if (!value) return [];
    const out: string[] = [];
    for (const token of value.split(/\s+/)) {
        const t = token.trim();
        if (t && !out.includes(t)) out.push(t);
    }
    return out;
}

export function formatScopeList(scopes: readonly string[]): string {
    return scopes.join(" ");
}

export interface ConsentTarget {
    tenantId: string;
    userId: string;
    clientType: ConsentClientType;
    clientRefId: string;
}

/** 철회되지 않은 최신 동의 1건. 없으면 null. */
export async function getActiveConsent(db: DB, target: ConsentTarget): Promise<UserClientConsent | null> {
    const [row] = await db
        .select()
        .from(userClientConsents)
        .where(
            and(
                eq(userClientConsents.tenantId, target.tenantId),
                eq(userClientConsents.userId, target.userId),
                eq(userClientConsents.clientType, target.clientType),
                eq(userClientConsents.clientRefId, target.clientRefId),
                isNull(userClientConsents.revokedAt),
            ),
        )
        .orderBy(desc(userClientConsents.grantedAt))
        .limit(1);
    return row ?? null;
}

export interface ConsentDecision {
    /** 화면을 띄우지 않고 진행해도 되는가. */
    satisfied: boolean;
    /** 거부할 수 없는 항목 (요청 − 선택). */
    required: string[];
    /** 거부할 수 있는 항목 (요청 ∩ 클라이언트 optionalScopes). */
    optional: string[];
    /** 이미 승인돼 있는 항목 — 재동의 화면에서 접어 표시한다(C3-A). */
    alreadyGranted: string[];
    /** 이번에 새로 묻는 항목 — 재동의 화면에서 강조한다(C3-A). */
    newlyRequested: string[];
    /** 실제로 발급할 범위 (요청 ∩ 동의). satisfied 일 때만 의미가 있다. */
    effectiveScopes: string[];
}

export interface DecideConsentInput {
    /** 클라이언트가 요청했고 등록 범위 안에 있는 항목. */
    requested: readonly string[];
    /** 클라이언트가 "거부 가능" 으로 설정한 항목. */
    optional: readonly string[];
    /** 저장된 동의 스냅샷. 없으면 빈 배열. */
    granted: readonly string[];
    /** `prompt=consent` — 저장된 동의를 무시하고 다시 묻는다. */
    forceConsent?: boolean;
}

/**
 * 동의 화면을 띄워야 하는지, 띄운다면 무엇을 강조할지 판정한다.
 * DB 를 보지 않는 순수 함수 — 호출부가 조회한 값을 넣는다.
 */
export function decideConsent(input: DecideConsentInput): ConsentDecision {
    const requested = parseScopeList(input.requested.join(" "));
    const optionalSet = new Set(input.optional);
    const granted = new Set(input.granted);

    const optional = requested.filter((s) => optionalSet.has(s));
    const required = requested.filter((s) => !optionalSet.has(s));

    const alreadyGranted = requested.filter((s) => granted.has(s));
    const newlyRequested = requested.filter((s) => !granted.has(s));

    // 선택 항목이 빠진 것만으로는 다시 묻지 않는다(위 주석 참고).
    const requiredCovered = required.every((s) => granted.has(s));
    const satisfied = !input.forceConsent && requiredCovered;

    return {
        satisfied,
        required,
        optional,
        alreadyGranted,
        newlyRequested,
        effectiveScopes: requested.filter((s) => granted.has(s)),
    };
}

/**
 * 동의를 기록한다. 기존 동의는 철회 표시하고 새 행을 만든다 — 스냅샷의 이력이 남아
 * "그때 무엇에 동의했는가" 를 나중에도 답할 수 있다.
 *
 * `approvedScopes` 는 필수 항목을 모두 포함해야 한다(호출부가 보장). 여기서는 저장만 한다.
 */
export async function recordConsent(db: DB, target: ConsentTarget, approvedScopes: readonly string[], now: Date = new Date()): Promise<void> {
    await revokeConsentRows(db, target, now);
    await db.insert(userClientConsents).values({
        tenantId: target.tenantId,
        userId: target.userId,
        clientType: target.clientType,
        clientRefId: target.clientRefId,
        grantedScopes: formatScopeList(parseScopeList(approvedScopes.join(" "))),
        grantedAt: now,
    });
}

/** 활성 동의 행에 철회 표시. 행을 지우지 않아 감사 흔적이 남는다. */
export async function revokeConsentRows(db: DB, target: ConsentTarget, now: Date = new Date()): Promise<void> {
    await db
        .update(userClientConsents)
        .set({ revokedAt: now })
        .where(
            and(
                eq(userClientConsents.tenantId, target.tenantId),
                eq(userClientConsents.userId, target.userId),
                eq(userClientConsents.clientType, target.clientType),
                eq(userClientConsents.clientRefId, target.clientRefId),
                isNull(userClientConsents.revokedAt),
            ),
        );
}

/** 사용자의 활성 동의 전체 (계정 화면의 "연결된 서비스" 목록용). */
export async function listActiveConsents(db: DB, tenantId: string, userId: string): Promise<UserClientConsent[]> {
    return db
        .select()
        .from(userClientConsents)
        .where(and(eq(userClientConsents.tenantId, tenantId), eq(userClientConsents.userId, userId), isNull(userClientConsents.revokedAt)))
        .orderBy(desc(userClientConsents.grantedAt));
}
