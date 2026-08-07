/**
 * 슬라이딩 윈도우 레이트 리밋 (두 버킷 근사법).
 *
 * 윈도우를 고정 인덱스(Math.floor(now/windowMs))로 분할해 두 버킷을 유지:
 *   - 현재 버킷 카운터를 원자적으로 증가
 *   - 이전 버킷 카운트에 경과 비율의 역수를 가중치로 적용
 *   count ≈ prev * (1 - elapsed/window) + current
 *
 * Fixed Window 대비 경계 burst(최대 2x) 문제를 제거.
 *
 * 원자증가/조회라는 상태 연산은 RateLimitStore(store.ts) 뒤로 캡슐화했고, 이 파일은
 * 윈도우 감쇠 산식만 담당한다 — 백엔드(DB/in-memory/Redis)와 무관하게 결과가 동일하다.
 */

import { lt } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { rateLimits } from "$lib/server/db/schema";
import type { RateLimitCounts, RateLimitStore } from "./store";

export { DbRateLimitStore, MemoryRateLimitStore, resolveRateLimitStore } from "./store";
export type { RateLimitCounts, RateLimitStore } from "./store";

export interface RateLimitResult {
    allowed: boolean;
    remaining: number;
    retryAfterMs: number;
}

export interface RateLimitOptions {
    /** 윈도우 크기 (ms) */
    windowMs: number;
    /** 윈도우 내 최대 허용 횟수 */
    limit: number;
}

/**
 * 두 버킷 카운트에 슬라이딩 윈도우 감쇠 산식을 적용해 허용 여부를 판정한다.
 * store.increment / store.peek 어느 쪽에서 얻은 카운트든 동일한 산식을 쓴다.
 */
function evaluate(counts: RateLimitCounts, options: RateLimitOptions, now: number = Date.now()): RateLimitResult {
    const windowIndex = Math.floor(now / options.windowMs);
    const windowStart = windowIndex * options.windowMs;
    const elapsed = now - windowStart;

    const slidingCount = Math.floor(counts.prev * (1 - elapsed / options.windowMs)) + counts.current;

    if (slidingCount > options.limit) {
        return { allowed: false, remaining: 0, retryAfterMs: options.windowMs - elapsed };
    }
    return { allowed: true, remaining: Math.max(0, options.limit - slidingCount), retryAfterMs: 0 };
}

/**
 * 현재 버킷을 원자적으로 증가시키고 한도 초과 여부를 판정한다(쓰기 경로).
 * 대부분의 호출부는 `if (!allowed) throw 429` 패턴으로 사용한다.
 */
export async function checkRateLimit(store: RateLimitStore, key: string, options: RateLimitOptions): Promise<RateLimitResult> {
    // 단일 타임스탬프를 캡처해 버킷 선택(store)과 elapsed 계산(evaluate)에 일관되게 사용한다.
    const now = Date.now();
    const counts = await store.increment(key, options.windowMs, now);
    return evaluate(counts, options, now);
}

/**
 * 증가 없이 현재 상태만으로 한도 초과 여부를 판정한다(read-only 경로).
 * 로그인 계정 잠금처럼 "성공은 미카운트, 실패 시에만 기록" 요건에서, 인증 전에 잠금 여부를
 * 조기 판정할 때 사용한다(선증가 없이 조회).
 */
export async function peekRateLimit(store: RateLimitStore, key: string, options: RateLimitOptions): Promise<RateLimitResult> {
    // 단일 타임스탬프를 캡처해 버킷 선택(store)과 elapsed 계산(evaluate)에 일관되게 사용한다.
    const now = Date.now();
    const counts = await store.peek(key, options.windowMs, now);
    return evaluate(counts, options, now);
}

/**
 * 만료된 rate_limit 레코드를 정리 (주기적 호출 또는 훅에서 사용). DbRateLimitStore(Workers) 전용.
 *
 * **`Date` 를 drizzle 연산자에 넘긴다** — `purgeExpiredChallenges` 와 같은 이유다(raw SQL 에
 * epoch 숫자를 박으면 postgres `timestamptz` / mysql `datetime` 과 비교되지 않아 던진다).
 */
export async function purgeExpiredRateLimits(db: DB): Promise<void> {
    await db.delete(rateLimits).where(lt(rateLimits.expiresAt, new Date()));
}
