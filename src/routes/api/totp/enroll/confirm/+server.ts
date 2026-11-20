import { error, json, type RequestHandler } from "@sveltejs/kit";
import { eq, and } from "drizzle-orm";
import { requireServiceToken } from "$lib/server/auth/service-token";
import { TOTP_CREDENTIAL_TYPE, BACKUP_CODE_CREDENTIAL_TYPE } from "$lib/server/auth/constants";
import { requireDbContext } from "$lib/server/auth/guards";
import { encryptTotpSecret, generateBackupCodes, hashBackupCode, verifyTotp } from "$lib/server/auth/totp";
import { verifyTotpEnrollTicket } from "$lib/server/auth/totp-enroll-ticket";
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
 *
 * `enrollmentTicket`(init 응답값)으로 secret·userId 가 IdP 가 발급한 그것인지 확인한다.
 * 티켓 없는 요청은 `TOTP_ENROLL_TICKET=required` 일 때 400, 기본(optional)이면 허용하되 감사에
 * 남긴다 — 호출자를 옮기는 동안의 이행 모드다. 티켓이 **오면** 모드와 무관하게 반드시 검증한다.
 * 활성(active)이 아닌 사용자는 403.
 */
export const POST: RequestHandler = async (event) => {
    const { request, locals } = event;
    await requireServiceToken(event, "totp.enroll");
    const { db, tenant, rateLimitStore } = requireDbContext(locals);

    const config = locals.runtimeConfig;
    if (!config.signingKeySecret) {
        throw error(503, translate(locals.locale, "totp.errors.signing_key_not_set"));
    }

    const body = (await request.json().catch(() => null)) as { userId?: string; secret?: string; code?: string; label?: string; enrollmentTicket?: string } | null;
    const userId = body?.userId?.trim();
    const secret = body?.secret?.trim();
    const code = body?.code?.replace(/\s/g, "");
    const label = body?.label?.trim() || translate(locals.locale, "totp.default_authenticator_label");
    const ticket = typeof body?.enrollmentTicket === "string" ? body.enrollmentTicket.trim() : "";

    if (!userId || !secret || !code) {
        throw error(400, "userId, secret, code required");
    }

    // ctrls C3: enrollment 코드 브루트포스 방어 (사용자당 5분 창 10회).
    const rl = await checkRateLimit(rateLimitStore, `totp-enroll-confirm:${tenant.id}:${userId}`, { windowMs: 5 * 60 * 1000, limit: 10 });
    if (!rl.allowed) {
        throw error(429, translate(locals.locale, "totp.errors.enroll_rate_limited"));
    }

    const meta = getRequestMetadata(event);
    const auditFailure = (reason: string) =>
        recordAuditEvent(db, {
            tenantId: tenant.id,
            userId,
            kind: "service_totp_enroll_rejected",
            outcome: "failure",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { reason },
        }).catch(() => undefined);

    const [u] = await db
        .select({ id: users.id, status: users.status })
        .from(users)
        .where(and(eq(users.id, userId), eq(users.tenantId, tenant.id)))
        .limit(1);
    if (!u) throw error(404, `user ${userId} not found`);
    if (u.status !== "active") {
        await auditFailure("user_inactive");
        throw error(403, "user not active");
    }

    // 티켓 검사는 코드 검증보다 먼저 한다 — 발급하지 않은 secret 에 대해 코드 검증 결과를 알려 주지 않는다.
    if (ticket) {
        const check = await verifyTotpEnrollTicket(ticket, { tenantId: tenant.id, userId, totpSecret: secret }, config.signingKeySecrets);
        if (!check.ok) {
            await auditFailure(`ticket_${check.reason}`);
            throw error(400, "invalid enrollment ticket");
        }
    } else if (config.totpEnrollTicketMode === "required") {
        await auditFailure("ticket_missing");
        throw error(400, "enrollmentTicket required");
    }

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

    // 백업 코드 해싱(CPU 집약적, scrypt)은 원자적 write 밖에서 미리 수행 —
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
        // 이행 모드에서 티켓 없이 등록된 건을 찾아낼 수 있게 남긴다(호출자 전환 확인용).
        detail: { ticket: ticket ? "verified" : "missing" },
    }).catch(() => undefined);

    return json({ ok: true, backupCodes });
};
