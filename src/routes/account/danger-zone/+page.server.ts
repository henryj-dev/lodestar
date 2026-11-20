import { fail, redirect } from "@sveltejs/kit";
import { and, eq } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { requireDbContext, assertNotLastAdmin } from "$lib/server/auth/guards";
import { clearSessionCookie } from "$lib/server/auth/session";
import { revokeUserEverywhere } from "$lib/server/oidc/revoke-everywhere";
import { findPasswordCredential } from "$lib/server/auth/users";
import { verifyPassword } from "$lib/server/auth/password";
import { verifyTotp, decryptTotpSecret, encryptTotpSecret, isLegacyTotpCiphertext } from "$lib/server/auth/totp";
import { getRuntimeConfig } from "$lib/server/auth/runtime";
import { tryWithSecrets } from "$lib/server/crypto/keys";
import { TOTP_CREDENTIAL_TYPE } from "$lib/server/auth/constants";
import { dispatchSecurityAlert } from "$lib/server/security-notify";
import { credentials, users } from "$lib/server/db/schema";
import { translate } from "$lib/i18n/server";
import { checkRateLimit } from "$lib/server/ratelimit";

// ctrls M-5: 계정 삭제 step-up(비밀번호/TOTP) 브루트포스 방어. account/mfa 와 동일한
// mfa-stepup:<userId> 키를 공유해 공격자가 엔드포인트를 옮겨가며 시도횟수를 우회하지 못하게 한다.
const STEPUP_WINDOW_MS = 5 * 60 * 1000;
const STEPUP_LIMIT = 10;

// 소프트 삭제 유예기간 = 30일. 이 기간 내 로그인하면 계정을 복구할 수 있고, 경과하면 GC 가
// 하드 삭제한다. (login 복구 흐름·gc.ts 하드삭제 조건과 짝을 이룬다.)
const DELETION_GRACE_MS = 30 * 24 * 60 * 60 * 1000;

export const load: PageServerLoad = async ({ locals, url }) => {
    if (!locals.user) {
        throw redirect(303, `/login?redirectTo=${encodeURIComponent(url.pathname)}`);
    }

    const { db } = requireDbContext(locals);

    // step-up UI 구성용: 비밀번호 크레덴셜/ TOTP 보유 여부.
    const pwCred = await findPasswordCredential(db, locals.user.id);
    const [totpCred] = await db
        .select({ id: credentials.id })
        .from(credentials)
        .where(and(eq(credentials.userId, locals.user.id), eq(credentials.type, TOTP_CREDENTIAL_TYPE)))
        .limit(1);

    return {
        email: locals.user.email,
        hasPassword: Boolean(pwCred?.secret),
        hasTotp: Boolean(totpCred),
        graceDays: Math.round(DELETION_GRACE_MS / (24 * 60 * 60 * 1000)),
    };
};

export const actions: Actions = {
    requestDeletion: async (event) => {
        const { locals } = event;
        if (!locals.user) throw redirect(303, "/login");

        const { db, tenant, rateLimitStore } = requireDbContext(locals);
        const locale = locals.locale;
        const user = locals.user;

        const requestMetadata = getRequestMetadata(event);

        // ctrls M-5: step-up 브루트포스 방어 (5분/10회, 사용자 단위)
        const rl = await checkRateLimit(rateLimitStore, `mfa-stepup:${user.id}`, { windowMs: STEPUP_WINDOW_MS, limit: STEPUP_LIMIT });
        if (!rl.allowed) {
            return fail(429, { error: translate(locale, "errors.rate_limit", { minutes: Math.ceil(rl.retryAfterMs / 60000) }) });
        }

        const formData = await event.request.formData();
        const password = String(formData.get("password") ?? "");
        const totpCode = String(formData.get("totp") ?? "")
            .trim()
            .replace(/\s/g, "");

        // ── step-up 재인증 (비밀번호 또는 TOTP) ─────────────────────────────────
        // 세션 탈취 공격자가 정당 소유자의 계정을 삭제하지 못하도록 재인증을 강제한다.
        // 비밀번호 크레덴셜이 있으면 비밀번호를, 없거나 TOTP 코드를 제출하면 TOTP 를 검증한다.
        let stepUpOk = false;

        const pwCred = await findPasswordCredential(db, user.id);
        if (password && pwCred?.secret) {
            const ok = await verifyPassword(password, pwCred.secret);
            stepUpOk = ok.valid;
        }

        if (!stepUpOk && totpCode) {
            const [totpCred] = await db
                .select()
                .from(credentials)
                .where(and(eq(credentials.userId, user.id), eq(credentials.type, TOTP_CREDENTIAL_TYPE)))
                .limit(1);
            const config = getRuntimeConfig(event.platform);
            if (totpCred?.secret && config.signingKeySecret) {
                try {
                    const plainSecret = await tryWithSecrets(config.signingKeySecrets, (s) => decryptTotpSecret(totpCred.secret!, s, user.id));
                    const lastUsedStep = totpCred.counter ?? undefined;
                    const matchedStep = await verifyTotp(totpCode, plainSecret, lastUsedStep);
                    if (matchedStep !== null) {
                        stepUpOk = true;
                        // v1 형식이면 v2 로 lazy migration + 재사용 방지용 counter 갱신.
                        let nextSecret = totpCred.secret;
                        if (isLegacyTotpCiphertext(totpCred.secret)) {
                            try {
                                nextSecret = await encryptTotpSecret(plainSecret, config.signingKeySecret, user.id);
                            } catch {
                                nextSecret = totpCred.secret;
                            }
                        }
                        await db.update(credentials).set({ lastUsedAt: new Date(), counter: matchedStep, secret: nextSecret }).where(eq(credentials.id, totpCred.id));
                    }
                } catch {
                    stepUpOk = false;
                }
            }
        }

        if (!stepUpOk) {
            await recordAuditEvent(db, {
                tenantId: tenant.id,
                userId: user.id,
                actorId: user.id,
                kind: "user_deletion_stepup_failed",
                outcome: "failure",
                ip: requestMetadata.ip,
                userAgent: requestMetadata.userAgent,
            });
            return fail(401, { error: translate(locale, "account.danger_zone.err_reauth") });
        }

        // ── 마지막 활성 관리자 자기삭제 차단 ─────────────────────────────────────
        const lastAdminBlock = await assertNotLastAdmin(db, tenant.id, user.id);
        if (lastAdminBlock) {
            return fail(400, { error: translate(locale, "account.danger_zone.err_last_admin") });
        }

        // ── 소프트 삭제 전환: status=deletion_pending + 유예 30일 예약 ───────────
        const scheduledAt = new Date(Date.now() + DELETION_GRACE_MS);
        await db
            .update(users)
            .set({ status: "deletion_pending", deletionScheduledAt: scheduledAt, updatedAt: new Date() })
            .where(and(eq(users.id, user.id), eq(users.tenantId, tenant.id)));

        // 전 세션 + refresh token 즉시 폐기(로그아웃). 복구는 유예 내 재로그인으로만 가능.
        // RP 에도 back-channel logout 을 보낸다 — 탈퇴 대기 계정이 RP 세션으로 남지 않게.
        await revokeUserEverywhere(event, { db, tenant, userId: user.id, actorId: user.id, reason: "deletion_requested" });

        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: user.id,
            actorId: user.id,
            kind: "user_deletion_requested",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { scheduledAt: scheduledAt.toISOString() },
        });

        // 탈퇴 접수 알림 메일(best-effort). 세션 만료 전, 쿠키 삭제 이전에 발사한다.
        dispatchSecurityAlert({ to: user.email, locale: user.locale, kind: "account_deletion_requested", platform: event.platform });

        // 로그아웃: 세션 쿠키 삭제 후 로그인으로.
        clearSessionCookie(event.cookies, event.url);
        throw redirect(303, "/login?deletionRequested=1");
    },
};
