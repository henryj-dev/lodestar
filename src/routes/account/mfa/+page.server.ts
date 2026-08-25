import { fail, redirect } from "@sveltejs/kit";
import { eq, and, isNull } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireDbContext } from "$lib/server/auth/guards";
import { getRuntimeConfig } from "$lib/server/auth/runtime";
import { generateTotpSecret, buildOtpAuthUri, verifyTotp, encryptTotpSecret, decryptTotpSecret, generateBackupCodes, hashBackupCode } from "$lib/server/auth/totp";
import { tryWithSecrets, tryWithSecretsNullable } from "$lib/server/crypto/keys";
import { TOTP_CREDENTIAL_TYPE, BACKUP_CODE_CREDENTIAL_TYPE } from "$lib/server/auth/constants";
import { credentials } from "$lib/server/db/schema";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit";
import { clearTrustedDeviceCookie, revokeAllTrustedDevices } from "$lib/server/auth/trusted-device";
import { dispatchSecurityAlert } from "$lib/server/security-notify";
import { checkRateLimit } from "$lib/server/ratelimit";

const TOTP_SETUP_COOKIE = "idp_totp_setup";
const TOTP_SETUP_TTL_MS = 10 * 60 * 1000; // 10분

// ctrls M-5: 계정 self-service MFA step-up(confirm/delete/regenerate) 브루트포스/replay 방어.
// 세션 탈취자가 스로틀 없는 6자리 TOTP 를 무제한 시도해 MFA 를 제거/회전하는 것을 막는다.
// 로그인 /mfa·/api/totp/* 와 동일한 5분/10회 상한.
const MFA_STEPUP_WINDOW_MS = 5 * 60 * 1000;
const MFA_STEPUP_LIMIT = 10;

// ── 등록 중 시크릿 임시 저장용 서명 쿠키 ────────────────────────────────────

async function createSetupToken(base32Secret: string, signingKeySecret: string): Promise<string> {
    const enc = new TextEncoder();
    const b64u = (buf: Uint8Array) =>
        btoa(String.fromCharCode(...buf))
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
    const data = b64u(enc.encode(JSON.stringify({ s: base32Secret, exp: Date.now() + TOTP_SETUP_TTL_MS })));
    const key = await crypto.subtle.importKey("raw", enc.encode(signingKeySecret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
    return `${data}.${b64u(new Uint8Array(sig))}`;
}

async function verifySetupToken(token: string, signingKeySecret: string): Promise<string | null> {
    try {
        const lastDot = token.lastIndexOf(".");
        if (lastDot === -1) return null;
        const data = token.slice(0, lastDot);
        const sigB64 = token.slice(lastDot + 1);
        const b64uDec = (s: string): Uint8Array<ArrayBuffer> => {
            const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
            const bin = atob(b64);
            const arr = new Uint8Array(bin.length) as Uint8Array<ArrayBuffer>;
            for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
            return arr;
        };
        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey("raw", enc.encode(signingKeySecret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
        const valid = await crypto.subtle.verify("HMAC", key, b64uDec(sigB64), enc.encode(data));
        if (!valid) return null;
        const payload = JSON.parse(new TextDecoder().decode(b64uDec(data))) as {
            s: string;
            exp: number;
        };
        if (payload.exp < Date.now()) return null;
        return payload.s;
    } catch {
        return null;
    }
}

// ── Load ──────────────────────────────────────────────────────────────────────

export const load: PageServerLoad = async ({ locals, cookies, platform, url }) => {
    if (!locals.user) {
        throw redirect(303, `/login?redirectTo=${encodeURIComponent(url.pathname)}`);
    }

    const { db } = requireDbContext(locals);
    const config = getRuntimeConfig(platform);

    // TOTP 등록 여부
    const [totpCred] = await db
        .select({ id: credentials.id, createdAt: credentials.createdAt })
        .from(credentials)
        .where(and(eq(credentials.userId, locals.user.id), eq(credentials.type, TOTP_CREDENTIAL_TYPE)))
        .limit(1);

    // 미사용 백업 코드 수
    const backupCreds = await db
        .select({ id: credentials.id })
        .from(credentials)
        .where(and(eq(credentials.userId, locals.user.id), eq(credentials.type, BACKUP_CODE_CREDENTIAL_TYPE), isNull(credentials.usedAt)));

    // 등록 진행 중인지 확인
    let pendingUri: string | null = null;
    if (!totpCred && config.signingKeySecret) {
        const setupToken = cookies.get(TOTP_SETUP_COOKIE);
        if (setupToken) {
            const secret = await tryWithSecretsNullable(config.signingKeySecrets, (s) => verifySetupToken(setupToken, s));
            if (secret) {
                const issuer = config.issuerUrl ? new URL(config.issuerUrl).hostname : "IdP";
                pendingUri = buildOtpAuthUri(secret, locals.user.email, issuer);
            }
        }
    }

    return {
        enrolled: !!totpCred,
        enrolledAt: totpCred?.createdAt ?? null,
        backupCodesRemaining: backupCreds.length,
        pendingUri,
        user: { email: locals.user.email, displayName: locals.user.displayName },
    };
};

// ── Actions ───────────────────────────────────────────────────────────────────

export const actions: Actions = {
    // TOTP 등록 시작 — 시크릿 생성, QR URI 반환
    setup: async ({ locals, cookies, platform, url }) => {
        if (!locals.user) throw redirect(303, "/login");
        const config = getRuntimeConfig(platform);
        if (!config.signingKeySecret) {
            return fail(503, {
                setup: true,
                error: "IDP_SIGNING_KEY_SECRET 이 설정되지 않았습니다.",
            });
        }

        const secret = generateTotpSecret();
        const issuer = config.issuerUrl ? new URL(config.issuerUrl).hostname : "IdP";
        const otpauthUri = buildOtpAuthUri(secret, locals.user.email, issuer);
        const setupToken = await createSetupToken(secret, config.signingKeySecret);

        cookies.set(TOTP_SETUP_COOKIE, setupToken, {
            path: "/",
            httpOnly: true,
            sameSite: "lax",
            secure: url.protocol === "https:",
            maxAge: 10 * 60,
        });

        return { setup: true, otpauthUri };
    },

    // TOTP 등록 확인 — 코드 검증 후 DB 저장, 백업 코드 생성
    confirm: async (event) => {
        const { locals, cookies, platform } = event;
        if (!locals.user) throw redirect(303, "/login");

        const config = getRuntimeConfig(platform);
        if (!config.signingKeySecret) {
            return fail(503, {
                confirm: true,
                error: "IDP_SIGNING_KEY_SECRET 이 설정되지 않았습니다.",
            });
        }

        const setupToken = cookies.get(TOTP_SETUP_COOKIE);
        if (!setupToken) {
            return fail(400, {
                confirm: true,
                error: "등록 세션이 만료되었습니다. 다시 시작해 주세요.",
            });
        }

        const plainSecret = await tryWithSecretsNullable(config.signingKeySecrets, (s) => verifySetupToken(setupToken, s));
        if (!plainSecret) {
            cookies.delete(TOTP_SETUP_COOKIE, { path: "/" });
            return fail(400, {
                confirm: true,
                error: "등록 세션이 만료되었습니다. 다시 시작해 주세요.",
            });
        }

        const formData = await event.request.formData();
        const code = String(formData.get("code") ?? "").trim();

        if (!code) {
            return fail(400, { confirm: true, error: "인증 코드를 입력해 주세요." });
        }

        const { db, tenant, rateLimitStore } = requireDbContext(locals);

        // ctrls M-5: step-up 브루트포스 방어 (5분/10회, 사용자 단위)
        const rl = await checkRateLimit(rateLimitStore, `mfa-stepup:${tenant.id}:${locals.user.id}`, { windowMs: MFA_STEPUP_WINDOW_MS, limit: MFA_STEPUP_LIMIT });
        if (!rl.allowed) {
            return fail(429, { confirm: true, error: `시도가 너무 많습니다. ${Math.ceil(rl.retryAfterMs / 60000)}분 후 다시 시도해 주세요.` });
        }

        const valid = await verifyTotp(code, plainSecret);
        if (!valid) {
            return fail(400, {
                confirm: true,
                error: "코드가 올바르지 않습니다. 다시 확인해 주세요.",
            });
        }

        // 이미 등록된 경우 방지
        const [existing] = await db
            .select({ id: credentials.id })
            .from(credentials)
            .where(and(eq(credentials.userId, locals.user.id), eq(credentials.type, TOTP_CREDENTIAL_TYPE)))
            .limit(1);

        if (existing) {
            cookies.delete(TOTP_SETUP_COOKIE, { path: "/" });
            return fail(409, { confirm: true, error: "이미 인증기가 등록되어 있습니다." });
        }

        // TOTP 시크릿 암호화 저장 — v2 (userId 바인딩)
        const encryptedSecret = await encryptTotpSecret(plainSecret, config.signingKeySecret, locals.user.id);
        await db.insert(credentials).values({
            id: crypto.randomUUID(),
            userId: locals.user.id,
            type: TOTP_CREDENTIAL_TYPE,
            secret: encryptedSecret,
            label: "TOTP 인증기",
        });

        // 백업 코드 10개 생성·저장
        const codes = generateBackupCodes();
        for (const code of codes) {
            const hashed = await hashBackupCode(code);
            await db.insert(credentials).values({
                id: crypto.randomUUID(),
                userId: locals.user.id,
                type: BACKUP_CODE_CREDENTIAL_TYPE,
                secret: hashed,
                label: "백업 코드",
            });
        }

        cookies.delete(TOTP_SETUP_COOKIE, { path: "/" });

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: locals.user.id,
            actorId: locals.user.id,
            kind: "mfa_enrolled",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
        });

        dispatchSecurityAlert({ to: locals.user.email, locale: locals.user.locale, kind: "mfa_enrolled", platform: event.platform });

        return { confirm: true, backupCodes: codes };
    },

    // TOTP 삭제 (백업 코드도 함께 삭제) — 현재 TOTP 코드로 재인증 필수
    delete: async (event) => {
        const { locals, platform } = event;
        if (!locals.user) throw redirect(303, "/login");

        const config = getRuntimeConfig(platform);
        if (!config.signingKeySecret) {
            return fail(503, {
                delete: true,
                error: "IDP_SIGNING_KEY_SECRET 이 설정되지 않았습니다.",
            });
        }

        const formData = await event.request.formData();
        const code = String(formData.get("code") ?? "").trim();
        if (!code) {
            return fail(400, { delete: true, error: "현재 TOTP 코드를 입력해 주세요." });
        }

        const { db, tenant, rateLimitStore } = requireDbContext(locals);

        // ctrls M-5: step-up 브루트포스 방어 (5분/10회, 사용자 단위)
        const rl = await checkRateLimit(rateLimitStore, `mfa-stepup:${tenant.id}:${locals.user.id}`, { windowMs: MFA_STEPUP_WINDOW_MS, limit: MFA_STEPUP_LIMIT });
        if (!rl.allowed) {
            return fail(429, { delete: true, error: `시도가 너무 많습니다. ${Math.ceil(rl.retryAfterMs / 60000)}분 후 다시 시도해 주세요.` });
        }

        const [totpCred] = await db
            .select()
            .from(credentials)
            .where(and(eq(credentials.userId, locals.user.id), eq(credentials.type, TOTP_CREDENTIAL_TYPE)))
            .limit(1);

        if (!totpCred?.secret) {
            return fail(400, { delete: true, error: "TOTP 인증기가 등록되어 있지 않습니다." });
        }

        const plainSecret = await tryWithSecrets(config.signingKeySecrets, (s) => decryptTotpSecret(totpCred.secret!, s, locals.user!.id));
        // ctrls M-5: lastUsedStep 바인딩으로 코드 replay(다른 엔드포인트에서 이미 쓴 코드 재사용) 차단.
        const matchedStep = await verifyTotp(code, plainSecret, totpCred.counter ?? undefined);
        if (matchedStep === null) {
            return fail(400, { delete: true, error: "인증 코드가 올바르지 않습니다." });
        }

        await db.delete(credentials).where(and(eq(credentials.userId, locals.user.id), eq(credentials.type, TOTP_CREDENTIAL_TYPE)));

        await db.delete(credentials).where(and(eq(credentials.userId, locals.user.id), eq(credentials.type, BACKUP_CODE_CREDENTIAL_TYPE)));

        // MFA 를 해제했으므로 "MFA 를 통과한 기기" 라는 신뢰의 근거도 사라진다 — 전부 폐기한다.
        // (재등록 시 이전 신뢰 기기가 되살아나면 안 된다.)
        await revokeAllTrustedDevices(db, locals.user.id);
        clearTrustedDeviceCookie(event.cookies, event.url);

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: locals.user.id,
            actorId: locals.user.id,
            kind: "mfa_deleted",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
        });

        dispatchSecurityAlert({ to: locals.user.email, locale: locals.user.locale, kind: "mfa_disabled", platform: event.platform });

        return { deleted: true };
    },

    // 백업 코드 재생성 — 현재 TOTP 코드로 재인증 필수
    regenerate: async (event) => {
        const { locals, platform } = event;
        if (!locals.user) throw redirect(303, "/login");

        const config = getRuntimeConfig(platform);
        if (!config.signingKeySecret) {
            return fail(503, {
                regenerate: true,
                error: "IDP_SIGNING_KEY_SECRET 이 설정되지 않았습니다.",
            });
        }

        const formData = await event.request.formData();
        const code = String(formData.get("code") ?? "").trim();
        if (!code) {
            return fail(400, { regenerate: true, error: "현재 TOTP 코드를 입력해 주세요." });
        }

        const { db, tenant, rateLimitStore } = requireDbContext(locals);

        // ctrls M-5: step-up 브루트포스 방어 (5분/10회, 사용자 단위)
        const rl = await checkRateLimit(rateLimitStore, `mfa-stepup:${tenant.id}:${locals.user.id}`, { windowMs: MFA_STEPUP_WINDOW_MS, limit: MFA_STEPUP_LIMIT });
        if (!rl.allowed) {
            return fail(429, { regenerate: true, error: `시도가 너무 많습니다. ${Math.ceil(rl.retryAfterMs / 60000)}분 후 다시 시도해 주세요.` });
        }

        // TOTP 등록 여부 확인 및 코드 검증
        const [totpCred] = await db
            .select()
            .from(credentials)
            .where(and(eq(credentials.userId, locals.user.id), eq(credentials.type, TOTP_CREDENTIAL_TYPE)))
            .limit(1);

        if (!totpCred?.secret) {
            return fail(400, { regenerate: true, error: "TOTP 인증기가 등록되어 있지 않습니다." });
        }

        const plainSecret = await tryWithSecrets(config.signingKeySecrets, (s) => decryptTotpSecret(totpCred.secret!, s, locals.user!.id));
        // ctrls M-5: lastUsedStep 바인딩으로 코드 replay 차단. credential 이 유지되므로 성공 시 counter 갱신.
        const matchedStep = await verifyTotp(code, plainSecret, totpCred.counter ?? undefined);
        if (matchedStep === null) {
            return fail(400, { regenerate: true, error: "인증 코드가 올바르지 않습니다." });
        }
        await db.update(credentials).set({ counter: matchedStep }).where(eq(credentials.id, totpCred.id));

        // 기존 백업 코드 전체 삭제
        await db.delete(credentials).where(and(eq(credentials.userId, locals.user.id), eq(credentials.type, BACKUP_CODE_CREDENTIAL_TYPE)));

        // 새 백업 코드 10개 생성
        const codes = generateBackupCodes();
        for (const code of codes) {
            const hashed = await hashBackupCode(code);
            await db.insert(credentials).values({
                id: crypto.randomUUID(),
                userId: locals.user.id,
                type: BACKUP_CODE_CREDENTIAL_TYPE,
                secret: hashed,
                label: "백업 코드",
            });
        }

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: locals.user.id,
            actorId: locals.user.id,
            kind: "backup_codes_regenerated",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
        });

        dispatchSecurityAlert({ to: locals.user.email, locale: locals.user.locale, kind: "backup_codes_regenerated", platform: event.platform });

        return { regenerate: true, backupCodes: codes };
    },
};
