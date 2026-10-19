import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { DB } from "$lib/server/db";
import { checkRateLimit, peekRateLimit, DbRateLimitStore, MemoryRateLimitStore, type RateLimitCounts, type RateLimitStore } from "$lib/server/ratelimit/index";

// ── 설계 요약 ──────────────────────────────────────────────────────────────────
// 원자증가/조회는 RateLimitStore 뒤로 캡슐화됐고, checkRateLimit/peekRateLimit 은 두 버킷
// 카운트에 슬라이딩 윈도우 감쇠 산식을 적용하는 순수 로직이다. 따라서:
//   - checkRateLimit/peekRateLimit: store 를 목으로 주입해 산식만 검증(백엔드 무관 동일 결과).
//   - DbRateLimitStore: 기존 mock DB 패턴으로 upsert shape/키 규약/expiresAt 검증.
//   - MemoryRateLimitStore: 실제 인스턴스로 증가·슬라이딩·evict 를 검증.
// 시간은 vi.useFakeTimers 로 고정해 windowIndex·elapsed 를 결정론적으로 만든다.

// now=90000, windowMs=60000 → windowIndex=1, windowStart=60000, elapsed=30000 (윈도우 절반)
const NOW = 90_000;
const WINDOW = 60_000;

beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(NOW));
});
afterEach(() => {
    vi.useRealTimers();
});

// 산식 테스트에는 단일 키 연산이 필요 없다.
const ENTRY_STUBS = { getEntry: async () => null, setEntry: async () => undefined, deleteEntry: async () => undefined };

// increment/peek 가 항상 고정 카운트를 반환하는 목 store — 산식만 검증하기 위한 것.
function mockStore(counts: RateLimitCounts): RateLimitStore {
    return {
        increment: async () => counts,
        peek: async () => counts,
        ...ENTRY_STUBS,
    };
}

describe("checkRateLimit — 한도 내/초과 (store 주입)", () => {
    it("한도 내: allowed=true, remaining=limit-sliding, retryAfter=0", async () => {
        // prev=0, current=3 → sliding = floor(0*0.5)+3 = 3 ≤ 5
        const res = await checkRateLimit(mockStore({ current: 3, prev: 0 }), "user:a", { windowMs: WINDOW, limit: 5 });
        expect(res.allowed).toBe(true);
        expect(res.remaining).toBe(2);
        expect(res.retryAfterMs).toBe(0);
    });

    it("초과: allowed=false, remaining=0, retryAfterMs=windowMs-elapsed", async () => {
        // prev=0, current=6 → sliding = 6 > 5
        const res = await checkRateLimit(mockStore({ current: 6, prev: 0 }), "user:a", { windowMs: WINDOW, limit: 5 });
        expect(res.allowed).toBe(false);
        expect(res.remaining).toBe(0);
        // elapsed = 30000 → retryAfter = 60000-30000 = 30000
        expect(res.retryAfterMs).toBe(WINDOW - 30_000);
    });
});

describe("checkRateLimit — 슬라이딩 윈도우 감쇠 산식 (기존 동일성)", () => {
    it("floor(prev*(1-elapsed/window)) + current 로 이전 버킷을 가중 감쇠", async () => {
        // elapsed=30000, factor=1-0.5=0.5. prev=4, current=1 → floor(4*0.5)+1 = 3 ≤ 5 → 허용, remaining=2
        const res = await checkRateLimit(mockStore({ current: 1, prev: 4 }), "user:a", { windowMs: WINDOW, limit: 5 });
        expect(res.allowed).toBe(true);
        expect(res.remaining).toBe(2);
    });

    it("감쇠된 prev 가중치로 한도를 넘으면 차단", async () => {
        // prev=10, current=1, factor=0.5 → floor(5)+1 = 6 > 5 → 차단
        const res = await checkRateLimit(mockStore({ current: 1, prev: 10 }), "user:a", { windowMs: WINDOW, limit: 5 });
        expect(res.allowed).toBe(false);
        expect(res.remaining).toBe(0);
    });

    it("elapsed 비율에 따라 감쇠 강도가 달라진다(윈도우 초반엔 prev 가중치 큼)", async () => {
        // now=61000 → elapsed=1000. prev=5, current=1 → floor(5*(1-1000/60000))+1 = floor(4.916..)+1 = 5 ≤ 5 → 허용(경계)
        vi.setSystemTime(new Date(61_000));
        const res = await checkRateLimit(mockStore({ current: 1, prev: 5 }), "user:a", { windowMs: WINDOW, limit: 5 });
        expect(res.allowed).toBe(true);
        expect(res.remaining).toBe(0);
    });

    it("이전 버킷이 없으면(prev=0) sliding=current", async () => {
        const res = await checkRateLimit(mockStore({ current: 5, prev: 0 }), "user:a", { windowMs: WINDOW, limit: 5 });
        expect(res.allowed).toBe(true);
        expect(res.remaining).toBe(0); // 5-5
    });
});

describe("peekRateLimit — 동일 산식, 증가 없음", () => {
    it("peek 결과에 checkRateLimit 과 동일한 산식을 적용한다", async () => {
        const res = await peekRateLimit(mockStore({ current: 6, prev: 0 }), "user:a", { windowMs: WINDOW, limit: 5 });
        expect(res.allowed).toBe(false); // 6 > 5
        expect(res.retryAfterMs).toBe(WINDOW - 30_000);
    });

    it("store.increment 가 아니라 store.peek 를 호출한다(증가 부작용 없음)", async () => {
        const increment = vi.fn();
        const peek = vi.fn(async () => ({ current: 1, prev: 0 }) as RateLimitCounts);
        const store: RateLimitStore = { increment, peek, ...ENTRY_STUBS };
        await peekRateLimit(store, "user:a", { windowMs: WINDOW, limit: 5 });
        expect(peek).toHaveBeenCalledOnce();
        expect(increment).not.toHaveBeenCalled();
    });
});

describe("단일 타임스탬프 시맨틱 — increment/peek/evaluate 가 동일 now 사용", () => {
    it("checkRateLimit 은 store.increment 와 evaluate 에 동일한 now(=Date.now())를 전달한다", async () => {
        let seenNow: number | undefined;
        const store: RateLimitStore = {
            ...ENTRY_STUBS,
            increment: async (_k, _w, now) => {
                seenNow = now;
                return { current: 6, prev: 0 };
            },
            peek: async () => ({ current: 0, prev: 0 }),
        };
        const res = await checkRateLimit(store, "user:a", { windowMs: WINDOW, limit: 5 });
        // store 가 받은 now 로 windowIndex=1, windowStart=60000, elapsed=30000 이 결정되고
        // evaluate 도 같은 now 를 써야 retryAfterMs = WINDOW-30000 이 나온다.
        expect(seenNow).toBe(NOW);
        expect(res.allowed).toBe(false);
        expect(res.retryAfterMs).toBe(WINDOW - 30_000);
    });

    it("peekRateLimit 도 store.peek 와 evaluate 에 동일한 now 를 전달한다", async () => {
        let seenNow: number | undefined;
        const store: RateLimitStore = {
            ...ENTRY_STUBS,
            increment: async () => ({ current: 0, prev: 0 }),
            peek: async (_k, _w, now) => {
                seenNow = now;
                return { current: 6, prev: 0 };
            },
        };
        const res = await peekRateLimit(store, "user:a", { windowMs: WINDOW, limit: 5 });
        expect(seenNow).toBe(NOW);
        expect(res.retryAfterMs).toBe(WINDOW - 30_000);
    });

    it("윈도우 경계 직전/직후: 명시적 now 로 버킷 인덱스가 결정론적으로 갈린다", async () => {
        const store = new MemoryRateLimitStore();
        // 경계 직전: now=119999 → windowIndex=1 → 키 k:1
        const before = await store.increment("k", WINDOW, 2 * WINDOW - 1);
        expect(before).toEqual({ current: 1, prev: 0 });
        // 경계 직후: now=120000 → windowIndex=2 → 새 버킷 k:2 (직전 k:1 은 prev 로 노출)
        const after = await store.increment("k", WINDOW, 2 * WINDOW);
        expect(after).toEqual({ current: 1, prev: 1 });
    });
});

// ── DbRateLimitStore (mock DB) ────────────────────────────────────────────────
// 테스트 방언 = d1 → onConflictDoUpdate + RETURNING 경로.
//   increment: insert(...).values(v).onConflictDoUpdate(...).returning() → [{count}]
//              그 뒤 이전 버킷 select 1회.
//   peek:      current select → prev select (증가 없음).
// select 결과는 호출 순서대로 selectRows 큐에서 소비한다.
interface MakeDbOpts {
    currentCount: number;
    selectRows?: Array<Array<{ count: number }>>;
}
function makeDb(opts: MakeDbOpts) {
    let insertValues: Record<string, unknown> | undefined;
    let selectCall = 0;
    const selectRows = opts.selectRows ?? [];
    const db = {
        insert: () => ({
            values: (v: Record<string, unknown>) => {
                insertValues = v;
                return {
                    onConflictDoUpdate: () => ({
                        returning: async () => [{ count: opts.currentCount }],
                    }),
                    onDuplicateKeyUpdate: async () => undefined,
                };
            },
        }),
        select: () => ({
            from: () => ({
                where: () => ({
                    limit: async () => selectRows[selectCall++] ?? [],
                }),
            }),
        }),
    };
    return {
        db: db as unknown as DB,
        get insertValues() {
            return insertValues;
        },
    };
}

describe("DbRateLimitStore — upsert shape / 키 규약 / 만료", () => {
    it("increment: current 는 upsert RETURNING, prev 는 이전 버킷 select", async () => {
        // prev 버킷 select → [{count:4}]
        const store = makeDb({ currentCount: 3, selectRows: [[{ count: 4 }]] });
        const counts = await new DbRateLimitStore(store.db).increment("user:a", WINDOW);
        expect(counts).toEqual({ current: 3, prev: 4 });
    });

    it("increment: current 버킷 key=`${key}:${windowIndex}`, count=1, expiresAt=windowStart+windowMs*2", async () => {
        const store = makeDb({ currentCount: 1, selectRows: [[]] });
        await new DbRateLimitStore(store.db).increment("user:a", WINDOW);
        expect(store.insertValues?.key).toBe("user:a:1"); // floor(90000/60000)=1
        expect(store.insertValues?.count).toBe(1);
        expect((store.insertValues?.expiresAt as Date).getTime()).toBe(60_000 + WINDOW * 2); // 180000
    });

    it("increment: 이전 버킷 row 부재 → prev=0", async () => {
        const store = makeDb({ currentCount: 5, selectRows: [[]] });
        const counts = await new DbRateLimitStore(store.db).increment("user:a", WINDOW);
        expect(counts).toEqual({ current: 5, prev: 0 });
    });

    it("peek: 증가 없이 current/prev 두 select 만 수행", async () => {
        // 첫 select = current 버킷, 둘째 = prev 버킷
        const store = makeDb({ currentCount: 999, selectRows: [[{ count: 2 }], [{ count: 7 }]] });
        const counts = await new DbRateLimitStore(store.db).peek("user:a", WINDOW);
        expect(counts).toEqual({ current: 2, prev: 7 });
        // insert(upsert)는 호출되지 않았어야 한다 → insertValues 미설정
        expect(store.insertValues).toBeUndefined();
    });
});

// ── MemoryRateLimitStore ──────────────────────────────────────────────────────
describe("MemoryRateLimitStore — 증가/슬라이딩/evict", () => {
    it("increment 는 현재 버킷을 원자 증가하고 prev 를 함께 반환", async () => {
        const store = new MemoryRateLimitStore();
        expect(await store.increment("k", WINDOW)).toEqual({ current: 1, prev: 0 });
        expect(await store.increment("k", WINDOW)).toEqual({ current: 2, prev: 0 });
        expect(await store.increment("k", WINDOW)).toEqual({ current: 3, prev: 0 });
    });

    it("이전 윈도우 버킷 카운트를 prev 로 노출한다", async () => {
        const store = new MemoryRateLimitStore();
        // windowIndex 0 (t=30000) 에서 2회 증가 → k:0 count=2, expiresAt=120000
        vi.setSystemTime(new Date(30_000));
        await store.increment("k", WINDOW);
        await store.increment("k", WINDOW);
        // windowIndex 1 (t=90000) 에서 조회 → prev=k:0=2, current=k:1=0
        vi.setSystemTime(new Date(NOW));
        expect(await store.peek("k", WINDOW)).toEqual({ current: 0, prev: 2 });
    });

    it("checkRateLimit 과 결합 시 DB 백엔드와 동일한 한도 판정을 낸다", async () => {
        const store = new MemoryRateLimitStore();
        const opts = { windowMs: WINDOW, limit: 5 };
        // prev=0 이므로 sliding=current. 5회까지 허용, 6회째 초과.
        for (let i = 1; i <= 5; i++) {
            const r = await checkRateLimit(store, "user:a", opts);
            expect(r.allowed).toBe(true);
            expect(r.remaining).toBe(5 - i);
        }
        const sixth = await checkRateLimit(store, "user:a", opts);
        expect(sixth.allowed).toBe(false);
        expect(sixth.retryAfterMs).toBe(WINDOW - 30_000);
    });

    it("만료 버킷은 조회 시 0 으로 취급된다", async () => {
        const store = new MemoryRateLimitStore();
        // t=90000: k:1 expiresAt = 60000 + 120000 = 180000
        await store.increment("k", WINDOW);
        // t=200000 > 180000 → 만료
        vi.setSystemTime(new Date(200_000));
        expect(await store.peek("k", WINDOW)).toEqual({ current: 0, prev: 0 });
    });

    it("evict: 만료 버킷은 스윕에서 실제로 제거되어 메모리가 누적되지 않는다", async () => {
        const store = new MemoryRateLimitStore();
        // t=90000: 첫 sweep(lastSweep 0→90000, 빈 맵), k:1 저장(expiresAt 180000)
        await store.increment("k", WINDOW);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        expect((store as any).buckets.size).toBe(1);
        // t=250000: sweep 간격(≥60s) 경과 + k:1 만료(180000<250000) → k 제거, other 만 남음
        vi.setSystemTime(new Date(250_000));
        await store.increment("other", WINDOW);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const buckets = (store as any).buckets as Map<string, unknown>;
        expect(buckets.size).toBe(1);
        expect([...buckets.keys()][0]).toBe(`other:${Math.floor(250_000 / WINDOW)}`);
    });
});
