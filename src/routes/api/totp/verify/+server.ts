import { error, json, type RequestHandler } from "@sveltejs/kit";
import { eq, and } from "drizzle-orm";
import { requireServiceToken } from "$lib/server/auth/service-token";
import { TOTP_CREDENTIAL_TYPE } from "$lib/server/auth/constants";
import { requireDbContext } from "$lib/server/auth/guards";
import { decryptTotpSecret, verifyTotp } from "$lib/server/auth/totp";
import { tryWithSecrets } from "$lib/server/crypto/keys";
import { checkRateLimit } from "$lib/server/ratelimit";
import { credentials } from "$lib/server/db/schema";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { translate } from "$lib/i18n/server";

/**
 * Phase 7.3 — TOTP step-up 검증.
 * dispatcher 가 사용자 입력 6자리 code 를 보내면 idp 가 DB 의 암호화된 secret 으로 검증.
 * 검증 통과 시 credential 의 lastUsedAt 갱신.
 */
export const POST: RequestHandler = async (event) => {
    const { request, locals } = event;
    await requireServiceToken(event, "totp.verify");
    const { db, tenant, rateLimitStore } = requireDbContext(locals);

    // 이 호출은 호출자(RP)에게 **2단계 검증**이다 — 방화벽 변경 승인 같은 행위의 보상 통제로
    // 쓰인다. 그런데 requireServiceToken 은 성공 시 조용히 반환하고 여기도 기록이 없어서,
    // "누구의 OTP 가 언제 검증됐는가" 에 답할 자료가 아예 없었다. 성공·실패 모두 남긴다.
    // (서비스 토큰이 하나뿐이라 호출자 신원까지는 아직 구분되지 않는다 — 별도 과제.)
    const meta = getRequestMetadata(event);
    const audit = (outcome: "success" | "failure", userId: string | null, detail?: Record<string, unknown>) =>
        recordAuditEvent(db, {
            tenantId: tenant.id,
            userId,
            kind: "service_totp_verified",
            outcome,
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail,
        }).catch(() => undefined); // 감사 실패가 검증 결과를 바꾸면 안 된다

    const config = locals.runtimeConfig;
    if (!config.signingKeySecret) {
        throw error(503, translate(locals.locale, "totp.errors.signing_key_not_set"));
    }

    const body = (await request.json().catch(() => null)) as { userId?: string; code?: string } | null;
    const userId = body?.userId?.trim();
    const code = body?.code?.replace(/\s/g, "");
    if (!userId || !code) throw error(400, "userId, code required");

    // ctrls C3: TOTP 브루트포스 방어. service-token 경계 안이지만 dispatcher 침해 시
    // 6자리 코드를 무제한 시도해 MFA 를 우회할 수 있으므로 사용자당 시도를 제한한다.
    // (5분 창에 10회 — webauthn-verify 와 동일 강도.)
    const rl = await checkRateLimit(rateLimitStore, `totp-verify:${userId}`, { windowMs: 5 * 60 * 1000, limit: 10 });
    if (!rl.allowed) {
        throw error(429, translate(locals.locale, "totp.errors.verify_rate_limited"));
    }

    const [cred] = await db
        .select({ id: credentials.id, secret: credentials.secret, counter: credentials.counter })
        .from(credentials)
        .where(and(eq(credentials.userId, userId), eq(credentials.type, TOTP_CREDENTIAL_TYPE)))
        .limit(1);
    if (!cred || !cred.secret) {
        await audit("failure", userId, { reason: "not_enrolled" });
        throw error(404, "TOTP not enrolled");
    }

    const plain = await tryWithSecrets(config.signingKeySecrets, (s) => decryptTotpSecret(cred.secret!, s, userId));
    // ctrls C3: counter 컬럼을 마지막 사용 스텝으로 활용해 코드 재사용을 거부한다
    // (웹 (auth)/mfa 경로와 동일 정책).
    const lastUsedStep = cred.counter ?? undefined;
    const step = await verifyTotp(code, plain, lastUsedStep);
    if (step === null) {
        await audit("failure", userId, { reason: "invalid_code" });
        return json({ ok: false }, { status: 401 });
    }

    const now = new Date();
    await db.update(credentials).set({ lastUsedAt: now, usedAt: now, counter: step }).where(eq(credentials.id, cred.id));
    await audit("success", userId);

    return json({ ok: true, verifiedAt: now.toISOString() });
};
