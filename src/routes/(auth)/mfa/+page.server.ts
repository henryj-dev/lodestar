import { fail, redirect } from "@sveltejs/kit";
import { eq, and, isNull } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { dev } from "$app/environment";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { requireDbContext } from "$lib/server/auth/guards";
import { createSessionRecord, elevateSession, setSessionCookie } from "$lib/server/auth/session";
import { createMfaPendingToken, verifyMfaPendingToken, MFA_PENDING_COOKIE } from "$lib/server/auth/mfa";
import { hasTotpCredential } from "$lib/server/auth/users";
import { createTrustedDevice, setTrustedDeviceCookie } from "$lib/server/auth/trusted-device";
import { tryWithSecrets, tryWithSecretsNullable } from "$lib/server/crypto/keys";
import { consumeBackupCode, consumeTotpCredential, verifyTotp, decryptTotpSecret, encryptTotpSecret, isLegacyTotpCiphertext, verifyBackupCode } from "$lib/server/auth/totp";
import { checkRateLimit } from "$lib/server/ratelimit";
import { AMR_PASSWORD, AMR_TOTP, AMR_BACKUP_CODE, amrToAcr, TOTP_CREDENTIAL_TYPE, BACKUP_CODE_CREDENTIAL_TYPE } from "$lib/server/auth/constants";
import { getRuntimeConfig } from "$lib/server/auth/runtime";
import { credentials, users } from "$lib/server/db/schema";
import { resolveSkinHtml, replacePlaceholders, escapeHtml } from "$lib/server/skin/resolver";
import { translate } from "$lib/i18n/server";
import { dispatchSecurityAlert } from "$lib/server/security-notify";

// 백업 코드 저잔량 경고 임계값(이하이면 경고 알림). account/mfa 의 backupCodesRemaining 표시와 정합.
const BACKUP_CODES_LOW_THRESHOLD = 2;

/** 내부 경로만 허용. `//host` · 역슬래시를 걸러 open redirect 를 막는다(login 라우트와 동일 규칙). */
function sanitizeRedirectTarget(target: string | null): string | null {
    if (!target) return null;
    let decoded: string;
    try {
        decoded = decodeURIComponent(target);
    } catch {
        return null;
    }
    if (!decoded.startsWith("/") || decoded.startsWith("//") || decoded.includes("\\")) {
        return null;
    }
    return target;
}

/**
 * step-up 을 진행할 수 없을 때 되돌려 보낼 전체 재인증 URL.
 *
 * `forceAuthn=true` 를 유지하는 것이 중요하다 — 이 경로로 오는 사용자는 이미 "재인증이
 * 필요하다"고 판정된 상태이므로, 신뢰 기기로 MFA 단계를 건너뛰게 하면 안 된다.
 */
function buildFullReauthUrl(redirectTo: string | null, skinHint: string | null): string {
    const params = new URLSearchParams({ forceAuthn: "true" });
    if (redirectTo) params.set("redirectTo", redirectTo);
    if (skinHint) params.set("skinHint", skinHint);
    return `/login?${params.toString()}`;
}

/** `sessions.amr` 의 공백 구분 문자열을 배열로. */
function parseSessionAmr(amr: string | null): string[] {
    return (amr ?? "").split(" ").filter(Boolean);
}

export const load: PageServerLoad = async (event) => {
    const { locals, cookies, platform, url } = event;
    const config = getRuntimeConfig(platform);
    const skinHint = url.searchParams.get("skinHint");
    const requestedRedirect = sanitizeRedirectTarget(url.searchParams.get("redirectTo"));
    let mfaToken = cookies.get(MFA_PENDING_COOKIE);

    // ── step-up 진입 ─────────────────────────────────────────────────────────
    // 클라이언트/SP 의 reauthPolicy=mfa_only 로 넘어온 경우. 1차 인증을 다시 받지 않고
    // 현재 세션을 유지한 채 OTP 만 받기 위해, 이 자리에서 pending 토큰을 직접 발급한다.
    // (다른 발급처와 달리 비밀번호 검증을 거치지 않으므로 sessionId 바인딩이 필수다.)
    if (!mfaToken && url.searchParams.get("stepUp") === "mfa") {
        const fullReauthUrl = buildFullReauthUrl(requestedRedirect, skinHint);

        // 승격할 세션이 없거나 서명 키/DB 가 없으면 step-up 자체가 불가능하다.
        if (!locals.user || !locals.session || !locals.db || !config.signingKeySecret) {
            throw redirect(303, fullReauthUrl);
        }
        // TOTP 미등록 사용자는 OTP 로 승격할 수단이 없다. 전체 재인증 경로로 되돌려 보내면
        // 로그인 후에도 ACR 이 부족한 것이 확인되어 SP 에는 NoAuthnContext 가 나간다
        // (= 기존 동작 유지). 여기서 임의로 통과시키면 요구 ACR 이 조용히 무시된다.
        if (!(await hasTotpCredential(locals.db, locals.user.id))) {
            throw redirect(303, fullReauthUrl);
        }

        const meta = getRequestMetadata(event);
        mfaToken = await createMfaPendingToken(
            {
                userId: locals.user.id,
                tenantId: locals.session.tenantId,
                redirectTo: requestedRedirect,
                ip: meta.ip,
                // step-up 은 RP 가 요구해서 진행되는 것이므로 신뢰 기기로 건너뛰거나
                // 새로 등록하게 해서는 안 된다.
                forced: true,
                // 기존 세션이 이미 통과한 수단을 그대로 이어받는다. 하드코딩하면 소셜
                // 로그인(fed) 세션에 pwd 가 붙어 downstream RP 에 거짓 정보가 나간다.
                baseAmr: parseSessionAmr(locals.session.amr),
                sessionId: locals.session.id,
            },
            config.signingKeySecret,
        );
        cookies.set(MFA_PENDING_COOKIE, mfaToken, {
            path: "/",
            httpOnly: true,
            sameSite: "lax",
            secure: !dev || url.protocol === "https:",
            maxAge: 5 * 60,
        });
    }

    // MFA pending 토큰이 없는 경우에만 자동 리다이렉트.
    // 토큰이 있으면 forceAuthn 등으로 재인증 중인 상태이므로 기존 세션을 무시한다.
    if (locals.user && !mfaToken) {
        throw redirect(302, locals.user.role === "admin" ? "/admin" : "/");
    }
    if (!mfaToken) {
        throw redirect(303, "/login");
    }

    if (!config.signingKeySecret) {
        throw redirect(303, "/login");
    }

    const claims = await tryWithSecretsNullable(config.signingKeySecrets, (s) => verifyMfaPendingToken(mfaToken, s));
    if (!claims) {
        cookies.delete(MFA_PENDING_COOKIE, { path: "/" });
        throw redirect(303, "/login");
    }

    // step-up 토큰은 **발급 당시의 그 세션**에만 쓸 수 있다. 이 검사가 없으면 A 계정으로
    // 받아 둔 step-up 토큰을 들고 B 계정으로 로그인해 B 세션을 승격시킬 수 있다.
    if (claims.sessionId && (locals.user?.id !== claims.userId || locals.session?.id !== claims.sessionId)) {
        cookies.delete(MFA_PENDING_COOKIE, { path: "/" });
        throw redirect(303, "/login");
    }

    let skinHtml: string | null = null;

    if (skinHint && locals.db && locals.tenant) {
        const colonIdx = skinHint.indexOf(":");
        if (colonIdx > 0) {
            const clientType = skinHint.slice(0, colonIdx) as "oidc" | "saml";
            const clientRefId = skinHint.slice(colonIdx + 1);
            if ((clientType === "oidc" || clientType === "saml") && clientRefId) {
                const raw = await resolveSkinHtml(locals.db, platform, locals.tenant.id, clientType, clientRefId, "mfa");
                if (raw) {
                    skinHtml = replacePlaceholders(raw, {
                        IDP_FORM_ACTION: "",
                        IDP_SKIN_HINT: escapeHtml(skinHint),
                        IDP_REDIRECT_TO: "",
                        IDP_FLASH_MSG: "",
                    });
                }
            }
        }
    }

    // 강제 재인증(admin·ForceAuthn·prompt=login 등) 중에는 신뢰 기기 옵션 자체를 노출하지 않는다.
    // stepUp=true 면 로그인이 아니라 "기존 세션에 인증 단계를 추가"하는 흐름이므로 화면 문구가 다르다.
    return {
        skinHtml,
        skinHint,
        redirectTo: claims.redirectTo ?? null,
        canRememberDevice: !claims.forced,
        stepUp: Boolean(claims.sessionId),
    };
};

async function resolveMfaSkinForAction(event: Parameters<Actions["default"]>[0], flashMsg: string): Promise<string | null> {
    const skinHint = event.url.searchParams.get("skinHint");
    if (!skinHint || !event.locals.db || !event.locals.tenant) return null;
    const colonIdx = skinHint.indexOf(":");
    if (colonIdx <= 0) return null;
    const clientType = skinHint.slice(0, colonIdx) as "oidc" | "saml";
    const clientRefId = skinHint.slice(colonIdx + 1);
    if ((clientType !== "oidc" && clientType !== "saml") || !clientRefId) return null;
    const raw = await resolveSkinHtml(event.locals.db, event.platform, event.locals.tenant.id, clientType, clientRefId, "mfa");
    if (!raw) return null;
    return replacePlaceholders(raw, {
        IDP_FORM_ACTION: "",
        IDP_SKIN_HINT: escapeHtml(skinHint),
        IDP_REDIRECT_TO: "",
        IDP_FLASH_MSG: escapeHtml(flashMsg),
    });
}

export const actions: Actions = {
    default: async (event) => {
        const mfaToken = event.cookies.get(MFA_PENDING_COOKIE);
        if (!mfaToken) {
            throw redirect(303, "/login");
        }

        const locale = event.locals.locale;

        const config = getRuntimeConfig(event.platform);
        if (!config.signingKeySecret) {
            const msg = translate(locale, "mfa_login.err_config");
            return fail(503, { error: msg, skinHtml: await resolveMfaSkinForAction(event, msg) });
        }

        const claims = await tryWithSecretsNullable(config.signingKeySecrets, (s) => verifyMfaPendingToken(mfaToken, s));
        if (!claims) {
            event.cookies.delete(MFA_PENDING_COOKIE, { path: "/" });
            throw redirect(303, "/login");
        }

        // step-up 토큰은 발급 당시의 그 세션에만 쓸 수 있다(load 와 동일 검사 — form action 은
        // load 를 거치지 않고 직접 POST 될 수 있으므로 양쪽에 모두 있어야 한다).
        if (claims.sessionId && (event.locals.user?.id !== claims.userId || event.locals.session?.id !== claims.sessionId)) {
            event.cookies.delete(MFA_PENDING_COOKIE, { path: "/" });
            throw redirect(303, "/login");
        }

        const requestMetadata = getRequestMetadata(event);

        // IP 바인딩 검증: MFA 토큰 발급 IP 와 현재 요청 IP 가 다르면 거부
        if (claims.ip && claims.ip !== requestMetadata.ip) {
            event.cookies.delete(MFA_PENDING_COOKIE, { path: "/" });
            throw redirect(303, "/login");
        }

        if (!event.locals.db || !event.locals.rateLimitStore) {
            const msg = translate(locale, "errors.db_not_ready");
            return fail(503, { error: msg, skinHtml: await resolveMfaSkinForAction(event, msg) });
        }

        const rl = await checkRateLimit(event.locals.rateLimitStore, `mfa:${claims.tenantId}:${claims.userId}`, {
            windowMs: 5 * 60 * 1000,
            limit: 10,
        });
        if (!rl.allowed) {
            const msg = translate(locale, "mfa_login.err_rate_limit");
            return fail(429, { error: msg, skinHtml: await resolveMfaSkinForAction(event, msg) });
        }

        const formData = await event.request.formData();
        const code = String(formData.get("code") ?? "")
            .trim()
            .replace(/\s/g, "");
        const useBackup = formData.get("use_backup") === "1";
        // 신뢰 기기 등록 요청. claims.forced 면 폼 값과 무관하게 무시한다(서버측 강제 —
        // 클라이언트가 체크박스를 임의로 제출해도 forceAuthn 흐름을 우회할 수 없다).
        const rememberDevice = !claims.forced && formData.get("remember_device") === "1";
        const ipBound = rememberDevice && formData.get("ip_bound") === "1";

        if (!code) {
            const msg = translate(locale, "mfa_login.err_missing_code");
            return fail(400, { error: msg, skinHtml: await resolveMfaSkinForAction(event, msg) });
        }

        const { db } = requireDbContext(event.locals);

        // 사용자 확인
        const [user] = await db.select().from(users).where(eq(users.id, claims.userId)).limit(1);

        if (!user || user.status !== "active" || user.tenantId !== claims.tenantId) {
            event.cookies.delete(MFA_PENDING_COOKIE, { path: "/" });
            throw redirect(303, "/login");
        }

        let amrMethod: string = AMR_TOTP;
        let verified = false;

        if (useBackup) {
            // 백업 코드 검증: 미사용 backup_code credential 중 일치하는 것 찾기
            const backupCreds = await db
                .select()
                .from(credentials)
                .where(and(eq(credentials.userId, user.id), eq(credentials.type, BACKUP_CODE_CREDENTIAL_TYPE), isNull(credentials.usedAt)));

            for (const cred of backupCreds) {
                if (!cred.secret) continue;
                const match = await verifyBackupCode(code, cred.secret);
                if (match) {
                    // 검증과 소진 사이의 경쟁을 막기 위해 조건부 UPDATE 로 원자 소비한다.
                    const consumed = await consumeBackupCode(db, cred.id, new Date());
                    if (consumed) {
                        amrMethod = AMR_BACKUP_CODE;
                        verified = true;
                    }
                    break;
                }
            }
        } else {
            // TOTP 검증
            const [totpCred] = await db
                .select()
                .from(credentials)
                .where(and(eq(credentials.userId, user.id), eq(credentials.type, TOTP_CREDENTIAL_TYPE)))
                .limit(1);

            if (totpCred?.secret) {
                const plainSecret = await tryWithSecrets(config.signingKeySecrets, (s) => decryptTotpSecret(totpCred.secret!, s, user.id));
                // counter 컬럼을 마지막으로 사용된 TOTP 스텝으로 활용 (재사용 방지)
                const lastUsedStep = totpCred.counter ?? undefined;
                const matchedStep = await verifyTotp(code, plainSecret, lastUsedStep);
                if (matchedStep !== null) {
                    // v1 형식이면 v2 로 lazy migration.
                    let nextSecret = totpCred.secret;
                    if (isLegacyTotpCiphertext(totpCred.secret)) {
                        try {
                            nextSecret = await encryptTotpSecret(plainSecret, config.signingKeySecret, user.id);
                        } catch {
                            nextSecret = totpCred.secret;
                        }
                    }
                    verified = await consumeTotpCredential(db, totpCred.id, matchedStep, new Date(), nextSecret);
                }
            }
        }

        if (!verified) {
            await recordAuditEvent(db, {
                tenantId: claims.tenantId,
                userId: user.id,
                actorId: user.id,
                kind: "mfa_verify",
                outcome: "failure",
                ip: requestMetadata.ip,
                userAgent: requestMetadata.userAgent,
                detail: { method: useBackup ? "backup_code" : "totp" },
            });

            const msg = useBackup ? translate(locale, "mfa_login.err_invalid_backup") : translate(locale, "mfa_login.err_invalid_totp");
            return fail(400, { error: msg, skinHtml: await resolveMfaSkinForAction(event, msg) });
        }

        // 백업 코드로 통과한 경우: 소진 처리 후 남은 미사용 코드 수를 계산해
        // 저잔량(≤임계값) 경고 / 소진(0) 알림을 보안 메일로 발송한다(fire-and-forget).
        // TOTP 로 통과한 경우엔 백업 코드가 소비되지 않으므로 검사하지 않는다(오탐 방지).
        if (useBackup) {
            const remainingRows = await db
                .select({ id: credentials.id })
                .from(credentials)
                .where(and(eq(credentials.userId, user.id), eq(credentials.type, BACKUP_CODE_CREDENTIAL_TYPE), isNull(credentials.usedAt)));
            const remaining = remainingRows.length;
            if (remaining === 0) {
                dispatchSecurityAlert({ to: user.email, locale: user.locale, kind: "backup_codes_depleted", platform: event.platform });
            } else if (remaining <= BACKUP_CODES_LOW_THRESHOLD) {
                dispatchSecurityAlert({ to: user.email, locale: user.locale, kind: "backup_codes_low", platform: event.platform });
            }
        }

        // MFA 통과 — 세션 생성(login 모드) 또는 기존 세션 승격(step-up 모드)
        event.cookies.delete(MFA_PENDING_COOKIE, { path: "/" });

        // 이미 통과한 인증 수단은 pending 토큰이 실어온 값을 쓴다. 로컬 로그인은 pwd, 소셜
        // 연합 로그인은 fed, step-up 은 승격 대상 세션의 기존 amr — 하드코딩하면 비밀번호를
        // 쓴 적 없는 사용자에게 pwd 가 붙는다. 중복은 제거한다(백업코드 재시도 등으로 같은
        // 수단이 두 번 들어오는 경우 amr 배열에 중복이 남지 않도록).
        const baseAmr = claims.baseAmr && claims.baseAmr.length > 0 ? claims.baseAmr : [AMR_PASSWORD];
        const amr = Array.from(new Set([...baseAmr, amrMethod]));

        if (claims.sessionId) {
            // ── step-up: 세션 행을 유지한 채 인증 수단만 승격한다 ──────────────────
            // 세션 쿠키를 재발급하지 않는다 — sessions.id(OIDC sid)와 idpSessionId(로그아웃
            // 통지의 sid)가 그대로여야 이미 로그인된 다른 RP 들의 세션 매핑이 유지된다.
            const elevated = await elevateSession(db, {
                sessionId: claims.sessionId,
                userId: user.id,
                amr,
                acr: amrToAcr(amr),
            });
            if (!elevated) {
                // 승격 도중 세션이 폐기·만료됐다(다른 탭 로그아웃, 관리자 강제 종료 등).
                // 승격할 대상이 없으므로 처음부터 로그인하게 한다.
                throw redirect(303, "/login");
            }

            await recordAuditEvent(db, {
                tenantId: claims.tenantId,
                userId: user.id,
                actorId: user.id,
                // 새 로그인이 아니라 기존 세션의 인증 수준 승격이므로 login 과 구분한다.
                kind: "mfa_stepup",
                outcome: "success",
                ip: requestMetadata.ip,
                userAgent: requestMetadata.userAgent,
                detail: { amr, method: useBackup ? "backup_code" : "totp", sessionId: claims.sessionId },
            });

            const stepUpDest = claims.redirectTo;
            throw redirect(303, user.role === "admin" ? (stepUpDest ?? "/admin") : (stepUpDest ?? "/"));
        }

        const { sessionToken, expiresAt } = await createSessionRecord(db, {
            tenantId: claims.tenantId,
            userId: user.id,
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            amr,
            acr: amrToAcr(amr),
        });

        setSessionCookie(event.cookies, event.url, sessionToken, expiresAt);

        // 신뢰 기기 등록 — MFA 를 실제로 통과한 이 시점에만 발급한다.
        // 백업 코드로 통과한 경우도 허용한다(감사 detail 의 method 로 구분 가능).
        if (rememberDevice) {
            const trusted = await createTrustedDevice(db, {
                tenantId: claims.tenantId,
                userId: user.id,
                ip: requestMetadata.ip,
                userAgent: requestMetadata.userAgent,
                ipBound,
            });
            setTrustedDeviceCookie(event.cookies, event.url, trusted.token, trusted.expiresAt);
        }

        await recordAuditEvent(db, {
            tenantId: claims.tenantId,
            userId: user.id,
            actorId: user.id,
            kind: "login",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { amr, method: useBackup ? "backup_code" : "totp", trustedDevice: rememberDevice },
        });

        const dest = claims.redirectTo;
        throw redirect(303, user.role === "admin" ? (dest ?? "/admin") : (dest ?? "/"));
    },
};
