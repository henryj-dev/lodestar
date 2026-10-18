/**
 * 로그인·MFA 실패 지수 지연(회원 공통 정책 2026-10-18).
 *
 * - 기준: 계정 + IP. 같은 계정이라도 다른 IP 의 실패는 따로 센다. 그래서 무인증 공격자가 다른 곳에서
 *   실패를 일으켜 정상 사용자를 막는 DoS 가 성립하지 않는다.
 * - 5회 실패까지는 지연이 없다. 5회째 실패부터 다음 시도까지 1초, 이후 실패마다 두 배(2·4·8…초),
 *   상한 15분.
 * - 마지막 실패 후 15분 동안 실패가 없으면 초기화한다. 성공하면 바로 초기화한다.
 * - 영구 잠금은 없다.
 *
 * 저장소는 rate_limits(공유 db 저장소 기본)의 키 하나에 (실패 횟수, 만료 = 마지막 실패 + 15분)을 담는다.
 * 마지막 실패 시각은 만료 시각에서 15분을 빼서 얻는다. 동시 실패의 읽기-쓰기는 원자적이지 않아 몇 회가
 * 덜 셀 수 있지만, 지연이 조금 늦게 걸릴 뿐 우회가 되지는 않는다(IP 단위 한도가 따로 있다).
 */
import type { RateLimitStore } from "$lib/server/ratelimit";

export const THROTTLE_FREE_FAILURES = 5;
export const THROTTLE_BASE_DELAY_MS = 1000;
export const THROTTLE_MAX_DELAY_MS = 15 * 60 * 1000;
export const THROTTLE_RESET_MS = 15 * 60 * 1000;

const PREFIX = "throttle:";

/** n 번 실패한 뒤 다음 시도까지 기다려야 하는 시간. */
export function throttleDelayMs(failures: number): number {
    if (failures < THROTTLE_FREE_FAILURES) return 0;
    const exp = failures - THROTTLE_FREE_FAILURES;
    // 2^exp 가 커지면 상한에 먼저 닿으므로 지수를 잘라 오버플로를 피한다.
    return Math.min(THROTTLE_BASE_DELAY_MS * 2 ** Math.min(exp, 30), THROTTLE_MAX_DELAY_MS);
}

export interface ThrottleCheck {
    allowed: boolean;
    retryAfterMs: number;
    failures: number;
}

export async function checkThrottle(store: RateLimitStore, scope: string, now = Date.now()): Promise<ThrottleCheck> {
    const entry = await store.getEntry(PREFIX + scope, now);
    if (!entry) return { allowed: true, retryAfterMs: 0, failures: 0 };
    const lastFailureAt = entry.expiresAt - THROTTLE_RESET_MS;
    const until = lastFailureAt + throttleDelayMs(entry.count);
    return until > now ? { allowed: false, retryAfterMs: until - now, failures: entry.count } : { allowed: true, retryAfterMs: 0, failures: entry.count };
}

export async function recordThrottleFailure(store: RateLimitStore, scope: string, now = Date.now()): Promise<number> {
    const entry = await store.getEntry(PREFIX + scope, now);
    const failures = (entry?.count ?? 0) + 1;
    await store.setEntry(PREFIX + scope, failures, now + THROTTLE_RESET_MS);
    return failures;
}

export async function clearThrottle(store: RateLimitStore, scope: string): Promise<void> {
    await store.deleteEntry(PREFIX + scope);
}

/** 로그인 범위 키: 테넌트 + 정규화한 로그인 식별자 + IP. */
export function loginThrottleScope(tenantId: string, identifier: string, ipKey: string): string {
    return `login:${tenantId}:${identifier.trim().toLowerCase()}:${ipKey}`;
}

/** MFA 범위 키: 테넌트 + 사용자 + IP. */
export function mfaThrottleScope(tenantId: string, userId: string, ipKey: string): string {
    return `mfa:${tenantId}:${userId}:${ipKey}`;
}
