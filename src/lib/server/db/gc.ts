/**
 * 만료 데이터 GC (Garbage Collection)
 *
 * 만료·소진된 행이 무한히 쌓이는 테이블을 주기적으로 정리한다. 정의만 되어 있고
 * 호출부가 없던 purge 함수 3개(webauthn 챌린지 / refresh token / rate limit)를
 * 통합 호출하고, purge 함수조차 없던 나머지 테이블은 여기서 직접 만료 DELETE 한다.
 *
 * 설계 원칙 — **미만료·미소진 데이터는 절대 삭제하지 않는다.**
 *   - 각 테이블의 만료 판정 컬럼/시맨틱을 스키마·사용처 코드에서 확인해 보수적으로 삭제.
 *   - 테이블별 에러 격리: 하나가 실패해도 나머지는 계속 진행한다.
 *   - 삭제 건수는 best-effort 로 로깅한다(방언별 결과 형태가 달라 미상일 수 있음).
 *
 * 실행 경로(두 런타임):
 *   - Cloudflare Workers: adapter-cloudflare 는 커스텀 worker 엔트리 없이는 `scheduled()`
 *     핸들러(Cron Trigger)를 노출할 수 없다(생성된 `_worker.js` 는 fetch 만 export). 빌드
 *     구조를 바꾸는 것은 과침습이므로, 요청의 ~1% 에서 `ctx.waitUntil` 로 GC 를 백그라운드
 *     발사한다(응답 지연 0). → maybeRunWorkersGc()
 *   - Node(adapter-node): 프로세스가 장수하므로 setInterval(1시간, unref) 로 주기 실행하고
 *     globalThis 플래그로 중복 기동을 막는다. → ensureNodeGcScheduler()
 *
 * GC 실패는 요청 처리에 절대 영향을 주지 않는다(전부 try/catch + waitUntil 격리).
 */

import { and, eq, lt, or, isNotNull, inArray } from "drizzle-orm";
import { getDb, DB_DIALECT, type DB } from "./index";
import { sessions, oidcGrants, passwordResetTokens, emailVerificationTokens, emailChangeTokens, samlSloStates, samlAuthnRequestIds, samlSessions, users, inviteTokens } from "./schema";
import { purgeExpiredChallenges } from "$lib/server/auth/webauthn";
import { purgeExpiredRefreshTokens, REFRESH_TOKEN_TTL_MS } from "$lib/server/oidc/refresh";
import { purgeExpiredRateLimits } from "$lib/server/ratelimit";
import { SESSION_TTL_MS } from "$lib/server/auth/constants";
import { checkTenantConsistency } from "$lib/server/ldap/consistency";

// ── 유예(grace) 상수 ─────────────────────────────────────────────────────────────

/**
 * sessions 삭제 유예 = refresh token TTL(30일). 단, 이 값은 안전성의 **근거가 아니라
 * 보수적 버퍼**다 — 실제 안전성은 아래 revoke-on-logout 불변식이 보장한다.
 *
 * 문제 표면: 세션 row 가 삭제되면 refresh token/grant 의 sessionId 가 FK
 * `onDelete: set null` 로 NULL 이 되고, 토큰 엔드포인트는 sessionId 가 NULL 이면 연결
 * 세션의 폐기/만료 검사를 건너뛴다. 따라서 "성급히 삭제된 세션의 토큰이 되살아나는" 우회를
 * 막아야 한다.
 *
 * "토큰 TTL 산술"(토큰 expiresAt ≤ session.expiresAt + 30일)은 이 안전성의 엄밀한 근거가
 * 아니다: 자연 만료(expired)된 세션은 refresh 토큰 회전을 막지 않으므로, 세션이 자연 만료된
 * 채로 남아 있어도 우회 자체가 문제되지 않고, 반대로 산술만으로 우회 부재를 증명할 수도 없다.
 *
 * 실제 안전 근거(revoke-on-logout 불변식): 우회가 위험한 경우는 **폐기(revoked)** 세션뿐인데,
 * 로그아웃/강제 종료 시 세션 폐기와 **동시에** 그 세션에 묶인 refresh token 이 전부 revoke
 * 된다(logout 플로우의 revokeSession + revokeRefreshTokensForSession). 그리고
 * rotateRefreshToken 은 `record.revokedAt` 이 설정된 토큰을 sessionId 가 NULL 인지와
 * 무관하게 거부한다. 즉 GC 가 폐기 세션을 일찍 삭제해 sessionId 를 NULL 로 만들어도, 그 토큰은
 * 이미 revoked 이므로 계속 거부된다 — 세션 검사 우회로 되살아나지 않는다. 30일 유예는 이 불변식
 * 위에 얹는 여유일 뿐 정확성 요건은 아니다.
 */
const SESSION_GC_GRACE_MS = REFRESH_TOKEN_TTL_MS;

/**
 * saml_sessions 삭제 유예 = IdP 세션 TTL(12시간).
 *
 * SLO 체인은 `endedAt IS NULL` 로 활성 SAML 세션을 조회한다(notOnOrAfter 무관).
 * 만료(notOnOrAfter 경과)됐거나 로그아웃(endedAt 설정)된 SAML 세션이라도, 부모 IdP
 * 세션이 살아있는 동안 진행 중인 SLO 체인에서 참조될 수 있다. 부모 IdP 세션 TTL(12h)
 * 만큼 유예를 두면 부모 세션도 확실히 만료된 뒤에만 삭제되어 SLO 일관성을 해치지 않는다.
 */
const SAML_SESSION_GC_GRACE_MS = SESSION_TTL_MS;

// ── 실행 주기/샘플링 ─────────────────────────────────────────────────────────────

/** Node setInterval 주기(1시간). */
const NODE_GC_INTERVAL_MS = 60 * 60 * 1000;

/** Workers 확률적 GC 발사 비율(요청의 ~1%). */
const WORKERS_GC_SAMPLE_RATE = 0.01;

/**
 * users 하드삭제 배치 크기. 대량의 deletion_pending 계정이 한 번에 삭제되면 FK cascade
 * (credentials/sessions/identities/…)로 인한 광범위한 락이 걸릴 수 있어, id 를 배치 단위로
 * 조회해 나눠 삭제한다. DELETE … LIMIT 는 방언별(sqlite/pg/mysql) 이식성이 없어 "id 조회 →
 * IN(...) 삭제" 2단계 루프로 이식성 있게 구현한다.
 */
const USERS_GC_BATCH_SIZE = 100;

// ── 결과 타입 ────────────────────────────────────────────────────────────────────

export interface GcTableResult {
    table: string;
    /** 삭제 행 수. 방언별 결과 형태로 산출 불가하면 null. */
    deleted: number | null;
    ok: boolean;
    error?: string;
}

export interface GcResult {
    startedAt: number;
    durationMs: number;
    tables: GcTableResult[];
}

/**
 * 방언별 DELETE 결과에서 영향받은 행 수를 best-effort 로 추출한다.
 * d1: meta.changes / libsql: rowsAffected / postgres-js: count / mysql2: [header].affectedRows.
 * 어느 것도 아니면 null(미상).
 */
function extractAffected(res: unknown): number | null {
    if (res == null) return null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const r = res as any;
    if (typeof r.rowsAffected === "number") return r.rowsAffected; // libsql
    if (r.meta && typeof r.meta.changes === "number") return r.meta.changes; // d1
    if (typeof r.count === "number") return r.count; // postgres-js
    if (typeof r.affectedRows === "number") return r.affectedRows; // mysql2 (일부 경로)
    if (Array.isArray(r) && r[0] && typeof r[0].affectedRows === "number") return r[0].affectedRows; // mysql2
    return null;
}

/**
 * users 하드삭제를 배치로 수행한다(대량 cascade 락 방지). deletion_pending & 유예 경과 계정의
 * id 를 USERS_GC_BATCH_SIZE 만큼 조회 → IN(...) 삭제하는 루프. 마지막 배치(조회 수 < 배치 크기)
 * 이후 종료한다. 방언 이식성을 위해 DELETE … LIMIT 대신 2단계(select→delete)로 구현한다.
 * 자체 try/catch 로 에러를 격리하고 결과를 tables 에 push 한다(다른 테이블 GC 에 영향 없음).
 */
async function runUsersBatchDelete(db: DB, now: Date, tables: GcTableResult[]): Promise<void> {
    try {
        let total = 0;
        for (;;) {
            const rows = await db
                .select({ id: users.id })
                .from(users)
                .where(and(eq(users.status, "deletion_pending"), lt(users.deletionScheduledAt, now)))
                .limit(USERS_GC_BATCH_SIZE);
            if (rows.length === 0) break;
            await db.delete(users).where(
                inArray(
                    users.id,
                    rows.map((r) => r.id),
                ),
            );
            total += rows.length;
            if (rows.length < USERS_GC_BATCH_SIZE) break;
        }
        tables.push({ table: "users", deleted: total, ok: true });
    } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        console.error(`[gc] delete users 실패:`, msg);
        tables.push({ table: "users", deleted: null, ok: false, error: msg });
    }
}

// ── 통합 GC ──────────────────────────────────────────────────────────────────────

/**
 * 만료 데이터를 정리한다. 테이블별 에러 격리 + 삭제 건수 로깅.
 * GC 는 조회 성능·저장공간을 위한 것이며, 어떤 만료 판정도 **인증 쿼리와 동일하거나 더
 * 보수적인 조건**만 사용한다(미만료·미소진 행 보존이 최우선).
 *
 * @param opts.isWorkers Workers 런타임 여부. `rate_limits` 는 **Workers 에서만 쓰는 테이블**
 *   이라(`resolveRateLimitStore` 가 Workers 가 아니면 `MemoryRateLimitStore` 를 쓴다) Node
 *   배포에서는 청소를 건너뛴다. 쓰지도 않는 테이블에 매시간 DELETE 를 날릴 이유가 없다.
 *   판정 조건은 `resolveRateLimitStore` 와 같아야 한다 — 어긋나면 실제로 쓰는 테이블을
 *   청소하지 않게 된다.
 */
export async function runExpiredDataGc(db: DB, opts: { isWorkers: boolean }): Promise<GcResult> {
    const startedAt = Date.now();
    const now = new Date();
    const tables: GcTableResult[] = [];

    // Non-destructive periodic integrity alert. Disable only for a deliberate migration window.
    if (typeof process === "undefined" || process.env.IDP_TENANT_CONSISTENCY_CHECK !== "false") {
        await checkTenantConsistency(db).catch((error) => console.error("[gc] tenant 정합성 점검 실패:", error));
    }

    // 각 정리 단계를 개별 격리 실행. purge 함수(void 반환)는 건수 미상(null).
    const runPurge = async (table: string, fn: () => Promise<void>) => {
        try {
            await fn();
            tables.push({ table, deleted: null, ok: true });
        } catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            console.error(`[gc] purge ${table} 실패:`, msg);
            tables.push({ table, deleted: null, ok: false, error: msg });
        }
    };

    const runDelete = async (table: string, exec: () => Promise<unknown>) => {
        try {
            const res = await exec();
            const deleted = extractAffected(res);
            tables.push({ table, deleted, ok: true });
        } catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            console.error(`[gc] delete ${table} 실패:`, msg);
            tables.push({ table, deleted: null, ok: false, error: msg });
        }
    };

    // 1) refresh token 을 먼저 purge — 만료 토큰을 제거해 아래 sessions 삭제 시 FK set-null
    //    대상(살아있는 토큰)이 없음을 확실히 한다.
    await runPurge("oidc_refresh_tokens", () => purgeExpiredRefreshTokens(db));
    // 2) 기존 purge 함수들 (import 호출)
    await runPurge("webauthn_challenges", () => purgeExpiredChallenges(db));
    //    rate_limits 는 Workers 에서만 쓰인다 — 위 opts.isWorkers 주석 참조.
    if (opts.isWorkers) {
        await runPurge("rate_limits", () => purgeExpiredRateLimits(db));
    }

    // 3) 직접 만료 DELETE ─────────────────────────────────────────────────────────
    const sessionCutoff = new Date(now.getTime() - SESSION_GC_GRACE_MS);
    const samlSessionCutoff = new Date(now.getTime() - SAML_SESSION_GC_GRACE_MS);

    // oidc_grants: authorization code(수 분 TTL). expiresAt 경과 시 삭제(미사용·소진 무관 —
    // 소진(usedAt) 여부와 상관없이 만료된 grant 는 재사용 불가하며 5분 창을 넘기면 무의미).
    await runDelete("oidc_grants", () => db.delete(oidcGrants).where(lt(oidcGrants.expiresAt, now)));

    // password_reset_tokens: expiresAt 경과 시 삭제. 사용됨(usedAt)·미사용 모두 만료 후엔 무효.
    await runDelete("password_reset_tokens", () => db.delete(passwordResetTokens).where(lt(passwordResetTokens.expiresAt, now)));

    // email_verification_tokens: expiresAt 경과 시 삭제. 사용됨·미사용 모두 만료 후엔 무효.
    await runDelete("email_verification_tokens", () => db.delete(emailVerificationTokens).where(lt(emailVerificationTokens.expiresAt, now)));

    // email_change_tokens: 만료(expiresAt 경과) 또는 소진(usedAt 설정)된 이메일 변경 토큰 삭제.
    //   invite_tokens 와 동일 시맨틱 — 소진분도 재사용 불가하므로 함께 정리(무한 성장 차단).
    //   미만료·미소진 토큰(유효한 변경 대기)은 두 조건 모두 거짓이라 보존된다.
    await runDelete("email_change_tokens", () => db.delete(emailChangeTokens).where(or(lt(emailChangeTokens.expiresAt, now), isNotNull(emailChangeTokens.usedAt))));

    // invite_tokens: 만료(expiresAt 경과) 또는 소진(usedAt 설정)된 초대 토큰 삭제. 다른 토큰
    //   테이블과 동일 시맨틱이되, 소진분도 재사용 불가하므로 함께 정리한다(무한 성장 차단).
    //   미만료·미소진 토큰(유효한 초대 대기)은 두 조건 모두 거짓이라 보존된다.
    await runDelete("invite_tokens", () => db.delete(inviteTokens).where(or(lt(inviteTokens.expiresAt, now), isNotNull(inviteTokens.usedAt))));

    // saml_slo_states: SLO 체인 상태. 자체 expiresAt 경과 시 삭제(만료된 체인은 죽은 상태).
    await runDelete("saml_slo_states", () => db.delete(samlSloStates).where(lt(samlSloStates.expiresAt, now)));

    // saml_authn_request_ids: AuthnRequest ID replay 캐시. **반드시 expiresAt 이후에만** 삭제
    //   (조기 삭제 시 replay 창이 다시 열림). 만료된 요청 ID 는 재생 방어 대상이 아니므로 안전.
    await runDelete("saml_authn_request_ids", () => db.delete(samlAuthnRequestIds).where(lt(samlAuthnRequestIds.expiresAt, now)));

    // saml_sessions: notOnOrAfter(SAML 세션 유효창, 8h) 또는 endedAt(로그아웃)이 유예(12h)를
    //   넘겨 지난 경우만 삭제. endedAt IS NULL 인 활성 세션은 notOnOrAfter 분기로만 잡힌다
    //   (NULL 비교는 참이 아니므로 활성 세션이 성급히 삭제되지 않는다).
    await runDelete("saml_sessions", () => db.delete(samlSessions).where(or(lt(samlSessions.notOnOrAfter, samlSessionCutoff), lt(samlSessions.endedAt, samlSessionCutoff))));

    // sessions: expiresAt 이 refresh TTL(30일) 유예를 넘겨 지난 경우만 삭제. 위 SESSION_GC_GRACE_MS
    //   주석의 근거대로, 이 시점엔 세션에 묶인 모든 refresh token 이 만료(및 purge)돼 있어
    //   FK set-null 로 인한 세션 검사 우회가 발생하지 않는다.
    await runDelete("sessions", () => db.delete(sessions).where(lt(sessions.expiresAt, sessionCutoff)));

    // users: 셀프서비스 탈퇴(soft-delete)로 status='deletion_pending' + deletionScheduledAt(유예 만료
    //   30일) 이 지난 계정만 하드 삭제한다. FK onDelete:cascade 가 자식 행(credentials/sessions/…)을
    //   정리하고, audit_events.userId 는 onDelete:set null 로 감사 로그를 보존한다.
    //   **보수적 조건**: (a) status 가 정확히 deletion_pending 이고 (b) deletionScheduledAt < now 인
    //   행만 대상이다. deletionScheduledAt 이 NULL 인 활성/일반 계정은 `<` 비교에서 참이 되지 않아
    //   절대 매칭되지 않으며(활성 계정 오삭제 불가), 유예 미경과 계정도 삭제되지 않는다.
    //   대량 cascade 락을 피하려고 배치(USERS_GC_BATCH_SIZE)로 id 를 조회해 나눠 삭제한다.
    await runUsersBatchDelete(db, now, tables);

    const result: GcResult = { startedAt, durationMs: Date.now() - startedAt, tables };

    const totalDeleted = tables.reduce((sum, t) => sum + (t.deleted ?? 0), 0);
    const failed = tables.filter((t) => !t.ok).map((t) => t.table);
    // 구조화(JSON) 로깅 — 로그 수집기에서 파싱 가능한 단일 라인으로 GC 결과를 남긴다.
    // 과설계(전면 로거/메트릭 파이프라인)는 범위 밖 — 결과 요약 + 테이블별 상세만 직렬화한다.
    // deleted 는 방언별로 산출 불가할 수 있어 null 이면 "+" 의미(최소 건수)로 totalDeleted 에 0 처리.
    console.log(
        JSON.stringify({
            event: "gc_complete",
            startedAt: new Date(result.startedAt).toISOString(),
            durationMs: result.durationMs,
            totalDeleted,
            ok: failed.length === 0,
            failedTables: failed,
            tables: result.tables,
        }),
    );

    return result;
}

// ── 실행 경로: Workers(확률적) ────────────────────────────────────────────────────

/**
 * Cloudflare Workers 요청 훅에서 호출. 확률적으로(~1%) GC 를 백그라운드 발사한다.
 * - `platform.ctx.waitUntil` 이 없으면(=Workers 아님) no-op.
 * - 요청 응답을 지연시키지 않는다(waitUntil 백그라운드).
 * - 요청 DB 연결의 생명주기(dispose)와 얽히지 않도록 GC 전용 연결을 새로 열고 닫는다.
 * - GC 실패는 요청 처리에 영향 없음(내부에서 전부 catch).
 */
export function maybeRunWorkersGc(platform: App.Platform | undefined): void {
    const waitUntil = platform?.ctx?.waitUntil?.bind(platform.ctx);
    if (!waitUntil) return; // Workers 아님
    if (Math.random() >= WORKERS_GC_SAMPLE_RATE) return;

    waitUntil(
        (async () => {
            let dispose: (() => Promise<void>) | undefined;
            try {
                const handle = await getDb(platform);
                dispose = handle.dispose;
                await runExpiredDataGc(handle.db, { isWorkers: true });
            } catch (error) {
                console.error("[gc] Workers GC 실행 실패:", error);
            } finally {
                if (dispose) await dispose().catch((e) => console.error("[gc] GC 연결 정리 실패:", e));
            }
        })(),
    );
}

// ── 실행 경로: Node(setInterval) ──────────────────────────────────────────────────

declare global {
    var __lodestarGcTimer: ReturnType<typeof setInterval> | undefined;
}

/**
 * Node(adapter-node) 서버에서 호출. 최초 1회만 1시간 간격 GC 타이머를 건다.
 * - globalThis 플래그로 중복 기동을 막는다(HMR/다중 import 안전).
 * - `unref()` 로 이 타이머가 프로세스 종료를 막지 않게 한다.
 * - DB_DIALECT="d1" 은 Workers 전용이라 Node 경로에선 스케줄하지 않는다.
 * - 매 tick 마다 getDb(undefined)(Node 전역 재사용 연결)로 GC 를 돌린다.
 */
export function ensureNodeGcScheduler(): void {
    if (globalThis.__lodestarGcTimer) return;
    if (DB_DIALECT === "d1") return; // d1 은 Workers 전용 — Node 스케줄 불가

    const timer = setInterval(() => {
        void (async () => {
            try {
                const { db } = await getDb(undefined);
                await runExpiredDataGc(db, { isWorkers: false });
            } catch (error) {
                console.error("[gc] Node GC 실행 실패:", error);
            }
        })();
    }, NODE_GC_INTERVAL_MS);

    // 프로세스 종료를 막지 않도록 unref (테스트/CLI 환경 안전).
    timer.unref?.();
    globalThis.__lodestarGcTimer = timer;
}
