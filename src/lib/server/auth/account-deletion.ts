/**
 * 계정 즉시 삭제(회원 공통 정책 2026-10-18 — 탈퇴 시 개인정보 즉시 삭제).
 *
 * 예전에는 본인 탈퇴를 `deletion_pending` + 30일 유예로 처리하고 GC 가 나중에 지웠다. 이제는 요청 즉시
 * 지운다. 순서가 중요하다:
 *   1. revokeUserEverywhere — 세션·refresh 폐기와 RP back-channel logout. 대상 RP 를 서비스 배정으로
 *      찾으므로 **사용자 행이 살아 있을 때** 해야 한다.
 *   2. 식별자 기록(retired_subjects) + users 행 삭제를 한 묶음(runAtomic)으로 실행한다. FK cascade 가
 *      자격 증명·세션·신원·배정 등 자식 행을 지우고, audit_events.userId 는 set null 로 남는다.
 *
 * 남기는 것은 Lodestar 가 발급한 sub(=users.id, 서버가 만든 무작위 UUID)와 issuer 뿐이다.
 * 연결돼 있던 외부 신원(identities)의 subject 는 **남기지 않는다** — 로컬 가입은 subject 가 이메일이고
 * LDAP 은 DN(대개 실명 포함)이라, 그대로 두면 탈퇴 뒤에도 개인정보가 기한 없이 남는다. 외부 신원 행은
 * 사용자 행과 함께 cascade 로 지워진다. 감사 로그는 보존 기간(1년) 동안 남지만 사용자 행과의
 * 연결(userId)은 끊긴다.
 *
 * 30일 유예로 이미 `deletion_pending` 인 계정은 그때 안내한 대로 유예가 끝날 때 GC 가 지운다
 * (`runUsersBatchDelete`). 그 경로도 이 기록을 남긴다(`recordRetiredSubjects`).
 */
import type { RequestEvent } from "@sveltejs/kit";
import { and, eq } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { retiredSubjects, users } from "$lib/server/db/schema";
import { runAtomic, type AtomicOp } from "$lib/server/db/atomic";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";
import { revokeUserEverywhere } from "$lib/server/oidc/revoke-everywhere";

/** Lodestar 가 발급한 sub 의 provider 표기. */
export const LODESTAR_SUBJECT_PROVIDER = "lodestar";

interface RetiredRow {
    tenantId: string;
    provider: string;
    subject: string;
    issuer: string | null;
}

/** 삭제 대상 사용자의 식별자 기록 행을 만든다(이미 기록돼 있으면 비운다 — 같은 사용자를 두 번 지우는 경우). */
async function buildRetiredRows(db: DB, tenantId: string, userId: string, issuer: string | null): Promise<RetiredRow[]> {
    const [existing] = await db
        .select({ id: retiredSubjects.id })
        .from(retiredSubjects)
        .where(and(eq(retiredSubjects.tenantId, tenantId), eq(retiredSubjects.provider, LODESTAR_SUBJECT_PROVIDER), eq(retiredSubjects.subject, userId)))
        .limit(1);
    return existing ? [] : [{ tenantId, provider: LODESTAR_SUBJECT_PROVIDER, subject: userId, issuer }];
}

function deleteOps(rows: RetiredRow[], tenantId: string, userId: string): AtomicOp[] {
    const ops: AtomicOp[] = [];
    if (rows.length > 0) ops.push((h) => h.insert(retiredSubjects).values(rows));
    ops.push((h) => h.delete(users).where(and(eq(users.id, userId), eq(users.tenantId, tenantId))));
    return ops;
}

/** issuer 를 못 구해도 삭제는 한다 — 기록의 issuer 만 비운다. */
function issuerOrNull(event: RequestEvent, tenantSlug: string): string | null {
    try {
        return resolveIssuerUrl(event.locals.runtimeConfig, event.url.origin, tenantSlug);
    } catch {
        return null;
    }
}

/** GC 처럼 요청 컨텍스트가 없는 곳에서 식별자를 기록하고 지운다(issuer 는 알 수 없어 null). */
export async function retireAndDeleteUser(db: DB, tenantId: string, userId: string, issuer: string | null = null): Promise<void> {
    const rows = await buildRetiredRows(db, tenantId, userId, issuer);
    await runAtomic(db, deleteOps(rows, tenantId, userId));
}

/**
 * 요청 처리 중 계정을 즉시 삭제한다(본인 탈퇴, 관리자 삭제).
 * 반환값은 revokeUserEverywhere 결과(감사 detail 용).
 */
export async function deleteUserNow(
    event: RequestEvent,
    params: { db: DB; tenant: { id: string; slug: string }; userId: string; actorId: string | null; reason: string },
): Promise<{ sessions: number; backchannelTargets: number }> {
    const { db, tenant, userId, actorId, reason } = params;
    const revoked = await revokeUserEverywhere(event, { db, tenant, userId, actorId, reason });

    await retireAndDeleteUser(db, tenant.id, userId, issuerOrNull(event, tenant.slug));
    return revoked;
}
