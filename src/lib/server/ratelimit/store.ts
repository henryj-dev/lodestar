/**
 * 레이트 리밋 저장소 추상화.
 *
 * `checkRateLimit`(두 버킷 슬라이딩 윈도우)의 산식은 그대로 두고, "현재 버킷 원자 증가 +
 * 이전 버킷 조회"라는 상태 연산만 이 인터페이스 뒤로 캡슐화한다. 덕분에 백엔드(DB / in-memory /
 * 향후 Redis·DO)를 런타임 환경에 맞춰 교체할 수 있다.
 *
 * 런타임 선택(resolveRateLimitStore):
 *   - Cloudflare Workers: isolate 는 요청 간 상태를 공유하지 못하므로 공유 저장소가 필요 →
 *     DB(rate_limits 테이블) 기반 DbRateLimitStore. 4방언 upsert 분기를 여기 캡슐화한다.
 *   - Node(adapter-node): 기본은 MemoryRateLimitStore지만 `RATELIMIT_STORE=db|redis`로
 *     다중 인스턴스용 공유 DB/Upstash 호환 Redis REST 저장소를 선택할 수 있다.
 */

import { eq, sql } from "drizzle-orm";
import { type DB, DB_DIALECT } from "$lib/server/db";
import { rateLimits } from "$lib/server/db/schema";

/** 슬라이딩 윈도우 산식이 필요로 하는 두 버킷의 카운트. */
export interface RateLimitCounts {
    /** 현재 윈도우 버킷 카운트. */
    current: number;
    /** 직전 윈도우 버킷 카운트(감쇠 가중치 적용 대상). */
    prev: number;
}

/**
 * 레이트 리밋 상태 저장소.
 * - increment: 현재 버킷을 원자적으로 +1 하고, 증가 후 현재 카운트와 이전 버킷 카운트를 반환.
 * - peek: 증가 없이 현재/이전 버킷 카운트만 조회(로그인 계정 잠금 등 read-only 판정용).
 * windowMs 로부터 windowIndex(=floor(now/windowMs))를 계산하고 `${key}:${idx}` 키 규약과
 * 버킷 만료(windowStart + windowMs*2)를 각 구현이 내부적으로 관리한다.
 */
export interface RateLimitStore {
    increment(key: string, windowMs: number, now?: number): Promise<RateLimitCounts>;
    peek(key: string, windowMs: number, now?: number): Promise<RateLimitCounts>;
}

/**
 * `${key}:${windowIndex}` 규약 + 버킷 만료 시각을 한 번에 계산.
 * `now` 를 넘기면 그 타임스탬프로 버킷 인덱스를 고정한다(미전달 시 `Date.now()`).
 */
function bucketKeys(key: string, windowMs: number, now: number = Date.now()): { currentKey: string; prevKey: string; windowStart: number } {
    const windowIndex = Math.floor(now / windowMs);
    return {
        currentKey: `${key}:${windowIndex}`,
        prevKey: `${key}:${windowIndex - 1}`,
        windowStart: windowIndex * windowMs,
    };
}

/**
 * DB(rate_limits 테이블) 기반 저장소 — Cloudflare Workers 등 공유 상태가 필요한 환경용.
 * 방언별 upsert 차이(d1/postgres 는 RETURNING, MySQL 은 ON DUPLICATE KEY + 재조회)를
 * 캡슐화한다. 정규 DB 타입은 활성 방언 하나만 노출하므로 비활성 분기의 메서드는 캐스팅으로 흡수.
 */
export class DbRateLimitStore implements RateLimitStore {
    constructor(private readonly db: DB) {}

    async increment(key: string, windowMs: number, now?: number): Promise<RateLimitCounts> {
        const { currentKey, prevKey, windowStart } = bucketKeys(key, windowMs, now);
        // 두 윈도우가 지나면 만료.
        const currentExpiresAt = new Date(windowStart + windowMs * 2);

        // 현재 버킷 원자적 증가.
        // d1/postgres 는 upsert + RETURNING 을 지원하지만, MySQL 은 RETURNING 이 없으므로
        // ON DUPLICATE KEY UPDATE 후 재조회로 카운트를 얻는다.
        let currentCount: number;
        const insertValues = { key: currentKey, count: 1, expiresAt: currentExpiresAt };
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const insertBuilder = this.db.insert(rateLimits).values(insertValues) as any;
        if (DB_DIALECT === "mysql") {
            await insertBuilder.onDuplicateKeyUpdate({ set: { count: sql`${rateLimits.count} + 1` } });
            const [row] = await this.db.select({ count: rateLimits.count }).from(rateLimits).where(eq(rateLimits.key, currentKey)).limit(1);
            currentCount = row?.count ?? 1;
        } else {
            const [row] = (await insertBuilder.onConflictDoUpdate({ target: rateLimits.key, set: { count: sql`${rateLimits.count} + 1` } }).returning({ count: rateLimits.count })) as Array<{
                count: number;
            }>;
            currentCount = row?.count ?? 1;
        }

        // 이전 버킷 조회 (best-effort).
        const [prevRow] = await this.db.select({ count: rateLimits.count }).from(rateLimits).where(eq(rateLimits.key, prevKey)).limit(1);
        return { current: currentCount, prev: prevRow?.count ?? 0 };
    }

    async peek(key: string, windowMs: number, now?: number): Promise<RateLimitCounts> {
        const { currentKey, prevKey } = bucketKeys(key, windowMs, now);
        const [curRow] = await this.db.select({ count: rateLimits.count }).from(rateLimits).where(eq(rateLimits.key, currentKey)).limit(1);
        const [prevRow] = await this.db.select({ count: rateLimits.count }).from(rateLimits).where(eq(rateLimits.key, prevKey)).limit(1);
        return { current: curRow?.count ?? 0, prev: prevRow?.count ?? 0 };
    }
}

/** Upstash Redis REST API와 호환되는 최소 응답 형태. */
interface RedisRestResponse {
    result?: unknown;
    error?: string;
}

const REDIS_INCREMENT_SCRIPT = `
local current = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], ARGV[1])
local previous = redis.call('GET', KEYS[2])
return { current, tonumber(previous) or 0 }
`;

/**
 * Upstash 호환 Redis REST 저장소.
 * EVAL로 현재 버킷 증가와 만료 설정을 한 원자 연산으로 실행한다.
 * `RATELIMIT_REDIS_URL`과 `RATELIMIT_REDIS_TOKEN`이 필요하다.
 */
export class RedisRateLimitStore implements RateLimitStore {
    constructor(
        private readonly url: string,
        private readonly token: string,
        private readonly fetchImpl: typeof fetch = fetch,
    ) {}

    private async command(command: unknown[]): Promise<unknown> {
        const response = await this.fetchImpl(this.url, {
            method: "POST",
            headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
            body: JSON.stringify(command),
        });
        const body = (await response.json().catch(() => null)) as RedisRestResponse | null;
        if (!response.ok || body?.error) throw new Error(`Redis rate-limit command failed (${response.status})`);
        return body?.result;
    }

    async increment(key: string, windowMs: number, now?: number): Promise<RateLimitCounts> {
        const { currentKey, prevKey } = bucketKeys(key, windowMs, now);
        const result = await this.command(["EVAL", REDIS_INCREMENT_SCRIPT, "2", currentKey, prevKey, String(windowMs * 2)]);
        if (!Array.isArray(result) || result.length < 2) throw new Error("Redis rate-limit response malformed");
        return { current: Number(result[0]), prev: Number(result[1]) };
    }

    async peek(key: string, windowMs: number, now?: number): Promise<RateLimitCounts> {
        const { currentKey, prevKey } = bucketKeys(key, windowMs, now);
        const [current, previous] = await Promise.all([this.command(["GET", currentKey]), this.command(["GET", prevKey])]);
        return { current: Number(current ?? 0), prev: Number(previous ?? 0) };
    }
}

interface MemoryBucket {
    count: number;
    /** epoch ms — 이 시각 이후 버킷은 만료로 간주(조회 시 0, 스윕 시 삭제). */
    expiresAt: number;
}

/**
 * 프로세스 내 Map 기반 저장소 — Node(adapter-node) 단일 프로세스 환경용.
 * DB write 없이 동일한 슬라이딩 윈도우 결과를 낸다. 만료 버킷은 조회 시 0 으로 취급하고,
 * 메모리 무한 증가를 막기 위해 increment 핫패스에서 최대 1분 간격으로 전체 스윕한다.
 *
 * 한계: 단일 프로세스 가정 — 다중 인스턴스로 수평 확장하면 한도가 인스턴스 수만큼 완화된다
 * (공유 저장소 아님). 그 경우 RateLimitStore 를 구현하는 Redis/DO 백엔드로 교체해야 한다.
 */
export class MemoryRateLimitStore implements RateLimitStore {
    private readonly buckets = new Map<string, MemoryBucket>();
    private lastSweep = 0;

    /** 만료 키 정리 — 핫패스 O(n) 스윕을 최소 1분 간격으로만 수행. */
    private sweep(now: number): void {
        if (now - this.lastSweep < 60_000) return;
        this.lastSweep = now;
        for (const [k, b] of this.buckets) {
            if (b.expiresAt <= now) this.buckets.delete(k);
        }
    }

    /** 만료된 버킷은 0 으로 취급. */
    private read(fullKey: string, now: number): number {
        const b = this.buckets.get(fullKey);
        return b && b.expiresAt > now ? b.count : 0;
    }

    async increment(key: string, windowMs: number, nowArg?: number): Promise<RateLimitCounts> {
        const now = nowArg ?? Date.now();
        this.sweep(now);
        const { currentKey, prevKey, windowStart } = bucketKeys(key, windowMs, now);
        const expiresAt = windowStart + windowMs * 2;
        const current = this.read(currentKey, now) + 1;
        this.buckets.set(currentKey, { count: current, expiresAt });
        return { current, prev: this.read(prevKey, now) };
    }

    async peek(key: string, windowMs: number, nowArg?: number): Promise<RateLimitCounts> {
        const now = nowArg ?? Date.now();
        const { currentKey, prevKey } = bucketKeys(key, windowMs, now);
        return { current: this.read(currentKey, now), prev: this.read(prevKey, now) };
    }
}

// Node 전역 재사용: 프로세스 내 단일 MemoryRateLimitStore 를 공유한다(HMR/다중 import 안전).
declare global {
    var __keystoneRateLimitMemoryStore: MemoryRateLimitStore | undefined;
    var __keystoneRateLimitWarningShown: boolean | undefined;
}

function getMemoryRateLimitStore(): MemoryRateLimitStore {
    if (!globalThis.__keystoneRateLimitMemoryStore) {
        globalThis.__keystoneRateLimitMemoryStore = new MemoryRateLimitStore();
    }
    return globalThis.__keystoneRateLimitMemoryStore;
}

/**
 * 런타임 환경에 맞는 RateLimitStore 를 반환한다.
 * - Workers(platform.ctx.waitUntil 존재): 요청당 db 로 DbRateLimitStore(공유 상태).
 * - Node: 프로세스 전역 MemoryRateLimitStore 싱글턴(DB write 없음).
 */
function runtimeEnv(platform: App.Platform | undefined, key: string): string | undefined {
    const platformValue = (platform?.env as Record<string, unknown> | undefined)?.[key];
    if (typeof platformValue === "string" && platformValue.length > 0) return platformValue;
    const nodeValue = typeof process !== "undefined" ? process.env[key] : undefined;
    return nodeValue && nodeValue.length > 0 ? nodeValue : undefined;
}

function warnAboutNodeMemoryRateLimit(instanceCount: string | undefined): void {
    if (globalThis.__keystoneRateLimitWarningShown) return;
    globalThis.__keystoneRateLimitWarningShown = true;
    const suffix = instanceCount && Number(instanceCount) > 1 ? ` APP_INSTANCE_COUNT=${instanceCount}` : "";
    console.warn(`[ratelimit] MemoryRateLimitStore is process-local${suffix}; use RATELIMIT_STORE=db or redis for shared limits.`);
}

export function resolveRateLimitStore(platform: App.Platform | undefined, db: DB): RateLimitStore {
    const isWorkers = typeof platform?.ctx?.waitUntil === "function";
    const selected = (runtimeEnv(platform, "RATELIMIT_STORE") ?? "auto").toLowerCase();
    const mode = selected === "auto" ? (isWorkers ? "db" : "memory") : selected;

    if (mode === "db") return new DbRateLimitStore(db);
    if (mode === "memory") {
        if (!isWorkers) warnAboutNodeMemoryRateLimit(runtimeEnv(platform, "APP_INSTANCE_COUNT"));
        return getMemoryRateLimitStore();
    }
    if (mode === "redis") {
        const url = runtimeEnv(platform, "RATELIMIT_REDIS_URL");
        const token = runtimeEnv(platform, "RATELIMIT_REDIS_TOKEN");
        if (!url || !token) throw new Error("RATELIMIT_STORE=redis requires RATELIMIT_REDIS_URL and RATELIMIT_REDIS_TOKEN");
        return new RedisRateLimitStore(url, token);
    }
    throw new Error(`지원하지 않는 RATELIMIT_STORE=${selected} (auto|memory|db|redis 중 하나를 사용하세요)`);
}
