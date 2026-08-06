import { error, json, type RequestHandler } from "@sveltejs/kit";
import { eq, and } from "drizzle-orm";
import { requireServiceToken } from "$lib/server/auth/service-token";
import { TOTP_CREDENTIAL_TYPE } from "$lib/server/auth/constants";
import { requireDbContext } from "$lib/server/auth/guards";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";
import { buildOtpAuthUri, generateTotpSecret } from "$lib/server/auth/totp";
import { checkRateLimit } from "$lib/server/ratelimit";
import { credentials, users } from "$lib/server/db/schema";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { translate } from "$lib/i18n/server";

/**
 * Phase 7.3 — TOTP enrollment init.
 * 호출자 (stardust dispatcher) 가 userId 를 알려주면 새 base32 secret + otpauth URI 반환.
 *
 * Stateless: idp 가 DB 에 저장하지 않음. 호출자가 secret 을 보관했다가 confirm 에서 다시 보냄.
 * (확정 전에 자리잡지 않으면 사용자가 QR 스캔 도중 dispatcher 가 재시작돼도 그대로 다시 init 가능.)
 *
 * 이미 등록된 사용자는 409 (운영자가 의도적으로 reset 하려면 별도 admin API).
 */
export const POST: RequestHandler = async (event) => {
    const { request, locals } = event;
    await requireServiceToken(event);
    const { db, tenant, rateLimitStore } = requireDbContext(locals);

    const body = (await request.json().catch(() => null)) as { userId?: string } | null;
    const userId = body?.userId?.trim();
    if (!userId) throw error(400, "userId required");

    // ctrls M-SVC-2: init 응답(200/404/409)이 사용자 존재·enrollment 상태 oracle 이 되지
    // 않도록, 그리고 무한 secret 생성을 막도록 confirm 과 동일하게 사용자당 rate-limit 한다.
    const rl = await checkRateLimit(rateLimitStore, `totp-enroll-init:${userId}`, { windowMs: 5 * 60 * 1000, limit: 10 });
    if (!rl.allowed) {
        throw error(429, translate(locals.locale, "totp.errors.enroll_rate_limited"));
    }

    const [u] = await db.select({ id: users.id, username: users.username }).from(users).where(eq(users.id, userId)).limit(1);
    if (!u) throw error(404, `user ${userId} not found`);

    const [already] = await db
        .select({ id: credentials.id })
        .from(credentials)
        .where(and(eq(credentials.userId, userId), eq(credentials.type, TOTP_CREDENTIAL_TYPE)))
        .limit(1);
    if (already) throw error(409, "TOTP already enrolled for this user");

    const secret = generateTotpSecret();
    const issuer = resolveIssuerUrl(locals.runtimeConfig, new URL(request.url).origin);
    const issuerHost = new URL(issuer).host;
    const username = u.username ?? u.id;
    const otpAuthUri = buildOtpAuthUri(secret, username, issuerHost);

    // TOTP seed 가 발급된 사건. confirm 전이라 크레덴셜은 아직 없지만, 시드가 밖으로 나간 것은
    // 기록할 가치가 있다 — 유출 조사에서 "언제 누구 것이 발급됐나" 를 묻게 된다.
    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId: u.id,
        kind: "service_totp_enroll_started",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
    }).catch(() => undefined);

    return json({ secret, otpAuthUri, userId: u.id, username });
};
