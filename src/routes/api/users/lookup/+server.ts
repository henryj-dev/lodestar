import { error, json, type RequestHandler } from "@sveltejs/kit";
import { eq, and } from "drizzle-orm";
import { requireServiceToken } from "$lib/server/auth/service-token";
import { requireDbContext } from "$lib/server/auth/guards";
import { users } from "$lib/server/db/schema";
import { checkRateLimit } from "$lib/server/ratelimit";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";

// ctrls M-9: service-to-service lookup 의 대량 열거 상한 + 흔적.
// 정상 dispatcher 매핑 조회는 통과하되, service token 유출 시 무제한 PII 디렉터리 덤프를
// 막는다. 초과 시 429 + 감사 로그(kind: service_lookup_throttled)로 abuse 를 탐지 가능하게 한다.
const LOOKUP_WINDOW_MS = 60 * 1000;
const LOOKUP_LIMIT = 120; // IP당 분당 120회

/**
 * Service-to-service user lookup.
 *
 * 신뢰된 다른 서비스 (예: stardust dispatcher) 가 username/email → users.id (uuid)
 * 매핑이 필요할 때 호출. Bearer service-token 으로 보호.
 *
 * 모든 조회는 현재 HTTP 요청 컨텍스트의 tenant 스코프로 강제된다. `tenant` 파라미터는
 * 하위호환을 위해 받을 수 있지만 현재 tenant slug와 다르면 거부한다. 환경변수 기반
 * 전역 dispatcher service-token도 이 라우트의 tenant 경계를 우회할 수 없다.
 *
 * Query 파라미터 (셋 중 하나 + 선택적 tenant):
 *   - `?id=<uuid>&tenant=<slug>`    : user id (현재 tenant 소속일 때만)
 *   - `?username=<u>&tenant=<slug>` : 현재 tenant slug와 일치해야 함
 *   - `?email=<e>&tenant=<slug>`    : email 매칭 (lowercase 비교)
 *
 * 응답: `{ id, tenantId, username, email, displayName, role, status }`
 *       또는 404.
 */
export const GET: RequestHandler = async (event) => {
    const { url, locals } = event;
    await requireServiceToken(event, "users.lookup");
    const { db, tenant, rateLimitStore } = requireDbContext(locals);

    const id = url.searchParams.get("id")?.trim();
    const username = url.searchParams.get("username")?.trim();
    const email = url.searchParams.get("email")?.trim()?.toLowerCase();
    const requestedTenantSlug = url.searchParams.get("tenant")?.trim();

    if (!id && !username && !email) {
        throw error(400, "one of id / username / email required");
    }

    // `DISPATCHER_SERVICE_TOKEN` is intentionally global for backward compatibility, but
    // it must not turn a caller-controlled query parameter into a tenant selector.
    // Multi-tenant routing must bind locals.tenant before this route is reached.
    if (requestedTenantSlug && requestedTenantSlug !== tenant.slug) {
        throw error(403, "tenant scope mismatch");
    }

    // ctrls M-9: IP당 분당 상한 — 유출된 토큰으로 무제한 열거하는 것을 막고 abuse 를 남긴다.
    const meta = getRequestMetadata(event);
    const rl = await checkRateLimit(rateLimitStore, `svc-lookup:${meta.ipKey}`, { windowMs: LOOKUP_WINDOW_MS, limit: LOOKUP_LIMIT });
    if (!rl.allowed) {
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            kind: "service_lookup_throttled",
            outcome: "failure",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { by: id ? "id" : username ? "username" : "email" },
        });
        throw error(429, "rate limited");
    }

    if (id) {
        const [row] = await db
            .select()
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.id, id)))
            .limit(1);
        if (!row) throw error(404, "user not found");
        return json(shape(row));
    }

    if (username) {
        const [row] = await db
            .select()
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.username, normalizeUsername(username))))
            .limit(1);
        if (!row) throw error(404, "user not found");
        return json(shape(row));
    }

    if (email) {
        const [row] = await db
            .select()
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.email, email)))
            .limit(1);
        if (!row) throw error(404, "user not found");
        return json(shape(row));
    }

    throw error(400, "no valid lookup param");
};

function normalizeUsername(u: string): string {
    return u.trim().toLowerCase();
}

function shape(row: typeof users.$inferSelect) {
    return {
        id: row.id,
        tenantId: row.tenantId,
        username: row.username,
        email: row.email,
        displayName: row.displayName,
        role: row.role,
        status: row.status,
    };
}
