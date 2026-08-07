import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { getTableName, type SQL } from "drizzle-orm";
import { SQLiteSyncDialect } from "drizzle-orm/sqlite-core";
import type { DB } from "$lib/server/db";
import { runExpiredDataGc } from "$lib/server/db/gc";
import { REFRESH_TOKEN_TTL_MS } from "$lib/server/oidc/refresh";
import { SESSION_TTL_MS } from "$lib/server/auth/constants";

// ── 순수 로직 검증용 목(mock) ──────────────────────────────────────────────
// runExpiredDataGc 는 각 테이블에 대해 db.delete(table).where(cond) 만 호출한다.
// (직접 DELETE + import 된 purge 함수 모두 동일 shape.) mock 은 delete 대상 테이블명과
// 전달된 where SQL 을 캡처하고, 선택적으로 특정 테이블에서 예외를 던져 에러 격리를 검증한다.
const dialect = new SQLiteSyncDialect();
function render(where: SQL): { sql: string; params: unknown[] } {
    const q = dialect.sqlToQuery(where);
    return { sql: q.sql, params: q.params };
}

interface DeleteCapture {
    table: string;
    where: SQL;
}

function makeDb(opts: { failFor?: string[] } = {}) {
    const deletes: DeleteCapture[] = [];
    const selects: DeleteCapture[] = [];
    const db = {
        delete: (table: unknown) => {
            const name = getTableName(table as Parameters<typeof getTableName>[0]);
            return {
                where: async (where: SQL) => {
                    if (opts.failFor?.includes(name)) throw new Error(`boom:${name}`);
                    deletes.push({ table: name, where });
                    return { rowsAffected: 0 };
                },
            };
        },
        // users 배치 하드삭제(runUsersBatchDelete)는 select().from(users).where(cond).limit(n) 로
        // id 를 조회한 뒤 delete(users).where(inArray(...)) 한다. select 를 캡처하고, users 는
        // 한 배치(배치 크기보다 작음)만 반환해 루프가 정확히 1회 만에 종료되게 한다.
        select: () => ({
            from: (table: unknown) => {
                const name = getTableName(table as Parameters<typeof getTableName>[0]);
                const builder = {
                    _where: undefined as SQL | undefined,
                    where(where: SQL) {
                        this._where = where;
                        return this;
                    },
                    async limit() {
                        if (opts.failFor?.includes(name)) throw new Error(`boom:${name}`);
                        if (this._where) selects.push({ table: name, where: this._where });
                        return name === "users" ? [{ id: "u1" }] : [];
                    },
                };
                return builder;
            },
        }),
    } as unknown as DB;
    return { db, deletes, selects };
}

/** 캡처된 delete/select 목록에서 테이블명으로 where 를 찾아 렌더링한다. */
function whereFor(captures: DeleteCapture[], table: string): { sql: string; params: unknown[] } {
    const cap = captures.find((d) => d.table === table);
    if (!cap) throw new Error(`capture for ${table} 미실행`);
    return render(cap.where);
}

// runExpiredDataGc 는 진행 로그를 console 에 남긴다 — 테스트 출력 소음 억제.
let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
    logSpy.mockRestore();
    errSpy.mockRestore();
});

/** Workers 런타임에서 도는 전체 대상. `rate_limits` 는 Workers 에서만 포함된다. */
const ALL_TABLES = [
    "oidc_refresh_tokens",
    "webauthn_challenges",
    "rate_limits",
    "oidc_grants",
    "password_reset_tokens",
    "email_verification_tokens",
    "email_change_tokens",
    "invite_tokens",
    "saml_slo_states",
    "saml_authn_request_ids",
    "saml_sessions",
    "sessions",
    "users",
];

describe("runExpiredDataGc — 보수적 만료 조건", () => {
    it("모든 대상 테이블에 대해 정확히 한 번씩 DELETE 를 실행한다", async () => {
        const { db, deletes } = makeDb();
        const result = await runExpiredDataGc(db, { isWorkers: true });
        expect(deletes.map((d) => d.table).sort()).toEqual([...ALL_TABLES].sort());
        expect(result.tables.filter((t) => t.ok).length).toBe(ALL_TABLES.length);
    });

    it("sessions: expiresAt 이 refresh TTL(30일) 유예를 넘긴 세션만 삭제한다", async () => {
        const start = Date.now();
        const { db, deletes } = makeDb();
        await runExpiredDataGc(db, { isWorkers: true });
        const end = Date.now();

        const { sql, params } = whereFor(deletes, "sessions");
        expect(sql).toContain('"sessions"."expires_at" < ?');
        // cutoff = now - 30일. (sqlite timestamp_ms 컬럼 → 파라미터는 epoch ms 숫자)
        const cutoff = params[0] as number;
        expect(typeof cutoff).toBe("number");
        expect(cutoff).toBeLessThanOrEqual(end - REFRESH_TOKEN_TTL_MS);
        expect(cutoff).toBeGreaterThanOrEqual(start - REFRESH_TOKEN_TTL_MS - 5_000);
    });

    it("saml_authn_request_ids: 유예 없이 expiresAt 경과분만 삭제한다(replay 창 보존)", async () => {
        const start = Date.now();
        const { db, deletes } = makeDb();
        await runExpiredDataGc(db, { isWorkers: true });
        const end = Date.now();

        const { sql, params } = whereFor(deletes, "saml_authn_request_ids");
        expect(sql).toContain('"saml_authn_request_ids"."expires_at" < ?');
        const cutoff = params[0] as number;
        // 유예가 없으므로 cutoff ≈ now (sessions 의 30일 소급과 대비).
        expect(cutoff).toBeGreaterThanOrEqual(start - 5_000);
        expect(cutoff).toBeLessThanOrEqual(end);

        // sessions cutoff 는 약 30일 더 과거여야 한다(유예 존재 대비 검증).
        const sessCutoff = whereFor(deletes, "sessions").params[0] as number;
        expect(cutoff - sessCutoff).toBeGreaterThanOrEqual(REFRESH_TOKEN_TTL_MS - 5_000);
    });

    it("email_verification_tokens: 유예 없이 expiresAt 경과분만 삭제한다", async () => {
        const start = Date.now();
        const { db, deletes } = makeDb();
        await runExpiredDataGc(db, { isWorkers: true });
        const end = Date.now();

        const { sql, params } = whereFor(deletes, "email_verification_tokens");
        expect(sql).toContain('"email_verification_tokens"."expires_at" < ?');
        const cutoff = params[0] as number;
        expect(cutoff).toBeGreaterThanOrEqual(start - 5_000);
        expect(cutoff).toBeLessThanOrEqual(end);
    });

    it("saml_sessions: 활성 세션(endedAt NULL)을 삭제하지 않고, notOnOrAfter/endedAt 유예 경과분만 삭제한다", async () => {
        const start = Date.now();
        const { db, deletes } = makeDb();
        await runExpiredDataGc(db, { isWorkers: true });
        const end = Date.now();

        const { sql, params } = whereFor(deletes, "saml_sessions");
        // 두 분기(OR): 만료창(notOnOrAfter) 또는 로그아웃(endedAt) 이 유예를 넘긴 경우.
        expect(sql).toContain('"saml_sessions"."not_on_or_after" < ?');
        expect(sql).toContain('"saml_sessions"."ended_at" < ?');
        expect(sql).toContain(" or ");
        // endedAt 은 오직 `<` 비교로만 쓰인다 → SQL 시맨틱상 NULL(활성) 은 절대 매칭되지 않는다.
        // (is null / is not null 스윕이 없어야 활성 세션이 성급히 삭제되지 않는다.)
        expect(sql).not.toContain('"saml_sessions"."ended_at" is');

        // 두 분기 모두 IdP 세션 TTL(12h) 유예 cutoff = now - SESSION_TTL_MS.
        const [c1, c2] = params as number[];
        expect(c1).toBe(c2);
        expect(c1).toBeLessThanOrEqual(end - SESSION_TTL_MS);
        expect(c1).toBeGreaterThanOrEqual(start - SESSION_TTL_MS - 5_000);
    });

    it("users: status=deletion_pending 이고 deletionScheduledAt 경과분만 (배치)조회·삭제한다(활성/미경과 보존)", async () => {
        const start = Date.now();
        const { db, deletes, selects } = makeDb();
        await runExpiredDataGc(db, { isWorkers: true });
        const end = Date.now();

        // 배치 하드삭제는 대상 id 를 select 로 먼저 조회한다 — 대상 조건(where)을 이 select 에서 검증.
        const { sql, params } = whereFor(selects, "users");
        // 두 조건(AND): status = 'deletion_pending' 그리고 deletion_scheduled_at < now.
        expect(sql).toContain('"users"."status" = ?');
        expect(sql).toContain('"users"."deletion_scheduled_at" < ?');
        expect(sql).toContain(" and ");
        // deletionScheduledAt 은 오직 `<` 비교로만 쓰인다 → NULL(활성/일반 계정)은 절대 매칭되지 않는다.
        expect(sql).not.toContain('"users"."deletion_scheduled_at" is');

        const [statusParam, cutoff] = params as [string, number];
        expect(statusParam).toBe("deletion_pending");
        // 유예 없이 즉시(now) cutoff — 실제 30일 유예는 신청 시 deletionScheduledAt 에 반영되어 있으므로
        // GC 는 예정 시각 경과분만 지운다.
        expect(cutoff).toBeGreaterThanOrEqual(start - 5_000);
        expect(cutoff).toBeLessThanOrEqual(end);

        // 조회된 id 로 실제 삭제(inArray)가 배치 수행된다.
        const delSql = whereFor(deletes, "users").sql;
        expect(delSql).toContain('"users"."id" in');
    });

    it("invite_tokens: 만료(expiresAt 경과) 또는 소진(usedAt 설정) 토큰을 삭제한다(유효 대기분 보존)", async () => {
        const start = Date.now();
        const { db, deletes } = makeDb();
        await runExpiredDataGc(db, { isWorkers: true });
        const end = Date.now();

        const { sql, params } = whereFor(deletes, "invite_tokens");
        // 두 분기(OR): 만료(expires_at <) 또는 소진(used_at is not null).
        expect(sql).toContain('"invite_tokens"."expires_at" < ?');
        expect(sql).toContain('"invite_tokens"."used_at" is not null');
        expect(sql).toContain(" or ");
        const cutoff = params[0] as number;
        expect(cutoff).toBeGreaterThanOrEqual(start - 5_000);
        expect(cutoff).toBeLessThanOrEqual(end);
    });

    it("oidc_grants / password_reset_tokens / saml_slo_states: expiresAt 경과분만 삭제한다", async () => {
        const { db, deletes } = makeDb();
        await runExpiredDataGc(db, { isWorkers: true });
        for (const table of ["oidc_grants", "password_reset_tokens", "saml_slo_states"]) {
            const { sql } = whereFor(deletes, table);
            expect(sql, table).toContain(`"${table}"."expires_at" < ?`);
        }
    });
});

// GC 가 매시간 ok:false 로 실패하던 회귀. purge 함수 2개가 raw SQL 에 `Date.now()` 숫자를
// 박아 `expires_at <= 1786…` 를 만들었는데, sqlite/d1 은 timestamp 를 정수(ms)로 저장해
// 통했지만 postgres(timestamptz)·mysql(datetime) 에서는 비교가 성립하지 않아 던졌다.
// 여기서는 sqlite 방언으로 렌더하므로 "PG 에서 던진다"를 직접 재현할 수는 없고, 대신
// **두 테이블이 나머지 테이블과 동일한 drizzle 연산자 형태(lt)로 만들어지는지**를 고정한다.
// raw SQL 판은 `<=` 를 냈으므로 이 검사로 갈린다.
describe("runExpiredDataGc — purge 함수의 방언 안전성", () => {
    for (const table of ["webauthn_challenges", "rate_limits"]) {
        it(`${table}: raw SQL 이 아니라 drizzle 연산자(lt)로 만료 비교를 만든다`, async () => {
            const { db, deletes } = makeDb();
            await runExpiredDataGc(db, { isWorkers: true });

            const { sql, params } = whereFor(deletes, table);
            // lt(col, new Date()) → `"<table>"."expires_at" < ?` (바인드 파라미터 1개).
            expect(sql).toContain(`"${table}"."expires_at" < ?`);
            expect(params).toHaveLength(1);
            // 리터럴이 SQL 문자열에 인라인되지 않는다(= 컬럼 매퍼를 탄다).
            expect(sql).not.toMatch(/\d{10,}/);
        });
    }
});

describe("runExpiredDataGc — rate_limits 는 Workers 에서만 청소한다", () => {
    // resolveRateLimitStore 가 Workers 가 아니면 MemoryRateLimitStore 를 쓰므로 Node 배포는
    // rate_limits 테이블에 애초에 쓰지 않는다. 쓰지도 않는 테이블을 매시간 지우러 가지 않는다.
    it("Node(isWorkers:false)에서는 rate_limits 를 건너뛴다", async () => {
        const { db, deletes } = makeDb();
        const result = await runExpiredDataGc(db, { isWorkers: false });

        expect(deletes.map((d) => d.table)).not.toContain("rate_limits");
        expect(result.tables.map((t) => t.table)).not.toContain("rate_limits");
        // 나머지 테이블은 그대로 다 돈다.
        const expected = ALL_TABLES.filter((t) => t !== "rate_limits");
        expect(deletes.map((d) => d.table).sort()).toEqual([...expected].sort());
    });

    it("Workers(isWorkers:true)에서는 rate_limits 를 청소한다", async () => {
        const { db, deletes } = makeDb();
        await runExpiredDataGc(db, { isWorkers: true });
        expect(deletes.map((d) => d.table)).toContain("rate_limits");
    });
});

describe("runExpiredDataGc — 테이블별 에러 격리", () => {
    it("한 테이블의 실패가 다른 테이블의 purge/delete 를 막지 않는다", async () => {
        // purge 함수 대상(oidc_refresh_tokens) 과 직접 delete 대상(saml_sessions) 을 동시에 실패시킨다.
        const failing = ["oidc_refresh_tokens", "saml_sessions"];
        const { db, deletes } = makeDb({ failFor: failing });
        const result = await runExpiredDataGc(db, { isWorkers: true });

        // 실패한 테이블은 결과에 ok:false + error 로 기록된다.
        for (const t of failing) {
            const entry = result.tables.find((r) => r.table === t);
            expect(entry?.ok).toBe(false);
            expect(entry?.error).toContain("boom");
        }

        // 나머지 테이블은 모두 정상 실행(캡처됨 + ok:true)돼야 한다.
        const survivors = ALL_TABLES.filter((t) => !failing.includes(t));
        for (const t of survivors) {
            expect(
                deletes.some((d) => d.table === t),
                `${t} 실행됨`,
            ).toBe(true);
            expect(result.tables.find((r) => r.table === t)?.ok).toBe(true);
        }

        // 결과에는 여전히 모든 테이블 항목이 존재한다.
        expect(result.tables.map((r) => r.table).sort()).toEqual([...ALL_TABLES].sort());
    });
});
