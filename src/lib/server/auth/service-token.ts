import { error, type RequestEvent } from "@sveltejs/kit";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { checkRateLimit } from "$lib/server/ratelimit";
import { eq } from "drizzle-orm";
import { serviceApiTokens } from "$lib/server/db/schema";
import { b64uEncode } from "$lib/server/crypto/keys";
import type { DB } from "$lib/server/db";

/**
 * stardust dispatcher 같은 신뢰된 서비스가 /api/totp/* 등을 호출할 때 사용하는
 * Bearer 토큰 검증. constant-time 비교로 timing leak 방지.
 *
 * 토큰 미설정 (개발/실수) 시 503 — 인증 우회 자동 거부.
 *
 * ctrls M-SVC-1: 실패한 인증 시도는 IP 단위로 rate-limit 하고 audit 에 남긴다.
 * 정상 dispatcher 는 항상 올바른 토큰을 보내므로 실패 카운터를 건드리지 않는다 —
 * 오직 무차별 대입(brute-force) 시도만 카운트되어 조용한 온라인 추측을 차단한다.
 */

// 실패 시도 throttle: 5분 창에 IP 당 20회. 정상 트래픽은 실패하지 않으므로 영향 없음.
const SVC_TOKEN_FAIL_WINDOW_MS = 5 * 60 * 1000;
const SVC_TOKEN_FAIL_LIMIT = 20;

/** lastUsedAt 갱신 간격. 승인 경로에 매 호출 DB 쓰기를 얹지 않기 위한 것(PLAN §2-3). */
const LAST_USED_THROTTLE_MS = 5 * 60 * 1000;

/** 발급 토큰 접두사 — 로그·목록에서 이 값이 KeyStone 서비스 토큰임을 알아보게 한다. */
export const SERVICE_TOKEN_PREFIX = "kst_";

/** 요청이 통과한 토큰의 신원. 호출부가 감사에 남길 수 있도록 반환한다. */
export interface ServiceTokenIdentity {
    /** DB 토큰이면 행 id, env 토큰이면 null. */
    id: string | null;
    /** 사람이 읽는 호출자 이름. env 토큰은 "dispatcher-env". */
    name: string;
}

/**
 * 서비스 토큰 검증 + **스코프 대조**.
 *
 * 두 경로를 순서대로 본다:
 *   1. `DISPATCHER_SERVICE_TOKEN`(env) — **모든 스코프**를 가진 것으로 취급한다. 기존 dispatcher 가
 *      끊기지 않게 남겨 둔 하위 호환 경로다.
 *   2. `service_api_tokens` — 받은 토큰을 해싱해 행을 찾는다. client_secret 과 달리 Bearer 하나로
 *      오고 식별자가 없으므로 **해시가 조회 키**다.
 *
 * 테넌트가 어긋나면 거부한다 — 토큰 행의 tenantId 와 요청이 해석한 테넌트가 달라야 할 이유가 없고,
 * 허용하면 남의 테넌트 API 가 열린다.
 *
 * @param requiredScope 이 라우트가 요구하는 스코프. env 토큰은 항상 통과한다.
 */
export async function requireServiceToken(event: RequestEvent, requiredScope: string): Promise<ServiceTokenIdentity> {
    const envToken = event.locals.runtimeConfig.dispatcherServiceToken;
    const db = event.locals.db;

    // env 토큰도 없고 DB 도 없으면 열 방법이 없다 → 503(인증 우회 자동 거부, 기존 동작 유지).
    if (!envToken && !db) {
        throw error(503, "service API 비활성 — DISPATCHER_SERVICE_TOKEN 미설정이고 토큰 저장소도 없습니다");
    }

    const header = event.request.headers.get("authorization") ?? "";
    const match = /^Bearer\s+(.+)$/i.exec(header.trim());
    if (!match) {
        await recordServiceTokenFailure(event);
        throw error(401, "Missing or malformed Authorization header (expected: Bearer <token>)");
    }
    const presented = match[1];

    // 1) env 토큰 — 전 스코프.
    if (envToken && (await timingSafeEqualStr(presented, envToken))) {
        return { id: null, name: "dispatcher-env" };
    }

    // 2) DB 토큰.
    const identity = db ? await verifyStoredToken(event, db, presented, requiredScope) : null;
    if (identity) return identity;

    await recordServiceTokenFailure(event);
    throw error(401, "Invalid service token");
}

/**
 * 저장된 토큰을 조회·검증한다. 통과하면 신원, 아니면 null(호출부가 401 로 통일).
 *
 * 스코프 불일치도 401 로 돌려준다 — 403 으로 구분하면 "토큰은 맞는데 권한이 없다" 를 알려 주는
 * oracle 이 된다. 실패 이유는 감사에만 남긴다.
 */
async function verifyStoredToken(event: RequestEvent, db: DB, presented: string, requiredScope: string): Promise<ServiceTokenIdentity | null> {
    const tenantId = event.locals.tenant?.id;
    if (!tenantId) return null;

    const hash = await hashServiceToken(presented);
    const [row] = await db.select().from(serviceApiTokens).where(eq(serviceApiTokens.tokenHash, hash)).limit(1);
    if (!row) return null;

    // 테넌트 불일치 — 다른 테넌트의 토큰으로 이 테넌트 API 를 열 수 없다.
    if (row.tenantId !== tenantId) return null;
    if (row.expiresAt && row.expiresAt.getTime() <= Date.now()) return null;

    // 정확 일치만. 와일드카드/계층은 두지 않는다(스코프가 넷뿐이라 이득이 없다).
    if (!row.scopes.split(/\s+/).filter(Boolean).includes(requiredScope)) return null;

    // lastUsedAt 은 throttle 해서 갱신한다 — 매 호출 쓰기는 승인 경로에 지연·경합을 얹는다.
    const now = Date.now();
    if (!row.lastUsedAt || now - row.lastUsedAt.getTime() > LAST_USED_THROTTLE_MS) {
        await db
            .update(serviceApiTokens)
            .set({ lastUsedAt: new Date(now) })
            .where(eq(serviceApiTokens.id, row.id))
            .catch(() => undefined); // 기록 실패가 검증 결과를 바꾸면 안 된다
    }

    return { id: row.id, name: row.name };
}

/** 저장·조회용 해시. 토큰이 256비트 난수라 SHA-256 으로 충분하다(느린 해시는 비밀번호용). */
export async function hashServiceToken(token: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    return `sha256$${b64uEncode(digest)}`;
}

/** 새 토큰 평문 생성. client_secret 과 같은 강도(32바이트 난수). */
export function generateServiceToken(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const body = btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    return SERVICE_TOKEN_PREFIX + body;
}

/**
 * 서비스 토큰 인증 실패를 audit 에 기록하고 IP 단위 실패 카운터를 증가시킨다.
 * audit 실패는 deny 경로를 막지 않는다(best-effort). throttle 초과 시 429 를 던진다.
 */
async function recordServiceTokenFailure(event: RequestEvent): Promise<void> {
    const meta = getRequestMetadata(event);
    const db = event.locals.db;
    const tenantId = event.locals.tenant?.id ?? null;

    if (db && tenantId) {
        try {
            await recordAuditEvent(db, {
                tenantId,
                kind: "service_token_rejected",
                outcome: "failure",
                ip: meta.ip,
                userAgent: meta.userAgent,
            });
        } catch {
            // audit 실패는 무시 — 인증 거부 자체를 막으면 안 된다.
        }
    }

    const store = event.locals.rateLimitStore;
    if (store) {
        const rl = await checkRateLimit(store, `svc-token-fail:${meta.ipKey}`, { windowMs: SVC_TOKEN_FAIL_WINDOW_MS, limit: SVC_TOKEN_FAIL_LIMIT });
        if (!rl.allowed) {
            throw error(429, "Too many failed service-token attempts");
        }
    }
}

// ctrls LOW: 원문 문자열을 직접 비교하면 길이 불일치 조기 반환으로 토큰 길이가 타이밍으로
// 누출되고, JS 엔진 문자열 비교의 상수시간성도 보장되지 않는다. 양쪽을 고정 길이 SHA-256
// 다이제스트로 만든 뒤 상수시간 비교한다(길이 무관, 32바이트 고정).
async function timingSafeEqualStr(a: string, b: string): Promise<boolean> {
    const enc = new TextEncoder();
    const [da, db] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(a)), crypto.subtle.digest("SHA-256", enc.encode(b))]);
    const ua = new Uint8Array(da);
    const ub = new Uint8Array(db);
    let diff = 0;
    for (let i = 0; i < ua.length; i++) diff |= ua[i] ^ ub[i];
    return diff === 0;
}
