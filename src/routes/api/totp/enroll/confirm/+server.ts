import { error, json, type RequestHandler } from "@sveltejs/kit";
import { eq, and } from "drizzle-orm";
import { requireServiceToken } from "$lib/server/auth/service-token";
import { TOTP_CREDENTIAL_TYPE, BACKUP_CODE_CREDENTIAL_TYPE } from "$lib/server/auth/constants";
import { requireDbContext } from "$lib/server/auth/guards";
import { encryptTotpSecret, generateBackupCodes, hashBackupCode, verifyTotp } from "$lib/server/auth/totp";
import { checkRateLimit } from "$lib/server/ratelimit";
import { credentials, users } from "$lib/server/db/schema";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import type { DB } from "$lib/server/db";
import { runAtomic } from "$lib/server/db/atomic";
import { isUniqueViolation } from "$lib/server/db/errors";
import { translate } from "$lib/i18n/server";

/**
 * Phase 7.3 — TOTP enrollment confirm.
 * 호출자가 init 에서 받은 secret + 사용자가 입력한 6자리 code 를 보내면
 * 검증 후 영구 저장. 백업 코드 10개 생성 후 plaintext 로 응답 (한 번만 보임).
 */
export const POST: RequestHandler = async (event) => {
    const { request, locals } = event;
    await requireServiceToken(event, "totp.enroll");
    const { db, tenant, rateLimitStore } = requireDbContext(locals);

    const config = locals.runtimeConfig;
    if (!config.signingKeySecret) {
        throw error(503, translate(locals.locale, "totp.errors.signing_key_not_set"));
    }

    const body = (await request.json().catch(() => null)) as { userId?: string; secret?: string; code?: string; label?: string } | null;
    const userId = body?.userId?.trim();
    const secret = body?.secret?.trim();
    const code = body?.code?.replace(/\s/g, "");
    const label = body?.label?.trim() || translate(locals.locale, "totp.default_authenticator_label");

    if (!userId || !secret || !code) {
        throw error(400, "userId, secret, code required");
    }

    // ctrls C3: enrollment 코드 브루트포스 방어 (사용자당 5분 창 10회).
    const rl = await checkRateLimit(rateLimitStore, `totp-enroll-confirm:${userId}`, { windowMs: 5 * 60 * 1000, limit: 10 });
    if (!rl.allowed) {
        throw error(429, translate(locals.locale, "totp.errors.enroll_rate_limited"));
    }

    const [u] = await db.select({ id: users.id }).from(users).where(eq(users.id, userId)).limit(1);
    if (!u) throw error(404, `user ${userId} not found`);

    const [already] = await db
        .select({ id: credentials.id })
        .from(credentials)
        .where(and(eq(credentials.userId, userId), eq(credentials.type, TOTP_CREDENTIAL_TYPE)))
        .limit(1);
    if (already) throw error(409, "TOTP already enrolled for this user");

    const verifiedStep = await verifyTotp(code, secret);
    if (verifiedStep === null) {
        throw error(400, "invalid code");
    }

    const encryptedSecret = await encryptTotpSecret(secret, config.signingKeySecret, userId);

    // 백업 코드 해싱(CPU 집약적, argon2id)은 원자적 write 밖에서 미리 수행 —
    // signing-keys rotate 패턴과 동일하게 트랜잭션/배치 창을 짧게 유지한다.
    const backupCodes = generateBackupCodes();
    const backupCodeRows: (typeof credentials.$inferInsert)[] = await Promise.all(
        backupCodes.map(async (c) => ({
            id: crypto.randomUUID(),
            userId,
            type: BACKUP_CODE_CREDENTIAL_TYPE,
            secret: await hashBackupCode(c),
            label: translate(locals.locale, "totp.default_backup_code_label"),
        })),
    );

    // TOTP INSERT + 백업코드 10개 INSERT 를 원자적으로 실행해 부분 실패로 인한
    // 백업코드 고아를 방지한다.
    // - totpOwnerId 에 userId 를 채워 credentials_totp_owner_uidx (unique) 가
    //   사용자당 TOTP 1개를 DB 레벨에서 강제 → 동시 confirm 두 건 중 하나만 성공.
    // - 백업코드 등 다른 INSERT 는 totpOwnerId 미설정(NULL) 이므로 unique 검사 제외.
    // runAtomic 이 d1/sqlite=batch, postgres/mysql=transaction 분기를 흡수한다.
    const buildTotpInsert = (h: Pick<DB, "insert">) =>
        h.insert(credentials).values({
            id: crypto.randomUUID(),
            userId,
            type: TOTP_CREDENTIAL_TYPE,
            secret: encryptedSecret,
            label,
            // ctrls C3: 등록에 사용한 스텝을 last-used 로 기록 — 동일 코드를 곧바로 /verify 로 재사용 불가.
            counter: verifiedStep,
            totpOwnerId: userId,
        });
    const buildBackupInsert = (h: Pick<DB, "insert">) => h.insert(credentials).values(backupCodeRows);

    const meta = getRequestMetadata(event);
    try {
        await runAtomic(db, [buildTotpInsert, buildBackupInsert]);
    } catch (err) {
        // credentials_totp_owner_uidx UNIQUE 위반(동시 이중 등록)일 때만 409 로 매핑한다.
        // 사전 SELECT 를 통과한 두 동시 요청 중 두 번째가 여기서 안전하게 거부된다.
        // 그 외 DB 에러는 재던져 500 으로 전파 — 관측성을 잃지 않는다.
        if (isUniqueViolation(err)) {
            throw error(409, "TOTP already enrolled for this user");
        }
        throw err;
    }

    // 2단계 크레덴셜이 새로 생긴 사건 — 서비스 토큰 경계 안에서 일어나므로 여기서 남기지 않으면
    // 기록이 없다. (이미 등록된 사용자는 위 409 로 막히므로 이 지점은 최초 등록만 도달한다.)
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId,
        kind: "service_totp_enrolled",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
    }).catch(() => undefined);

    return json({ ok: true, backupCodes });
};
