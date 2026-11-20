import type { RequestEvent } from "@sveltejs/kit";
import { and, eq } from "drizzle-orm";
import { requireAdminContext, assertUserInTenant } from "$lib/server/auth/guards";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";
import { revokeUserEverywhere } from "$lib/server/oidc/revoke-everywhere";
import { requireCsrf } from "$lib/server/admin/errors";
import { credentials, users } from "$lib/server/db/schema";
import { TOTP_CREDENTIAL_TYPE, BACKUP_CODE_CREDENTIAL_TYPE } from "$lib/server/auth/constants";
import { revokeAllTrustedDevices } from "$lib/server/auth/trusted-device";
import { dispatchSecurityAlert } from "$lib/server/security-notify";

// 사용자 상세 페이지의 보안 관련 액션(강제 로그아웃 등).
type UserActionEvent = RequestEvent<{ id: string }, "/admin/users/[id]">;

// ── 강제 로그아웃 ──────────────────────────────────────────────────────────
// 상태/비밀번호 변경 없이 대상 유저의 모든 세션 + OIDC refresh token 을 폐기하고,
// **RP 에도 back-channel logout 을 발행한다.**
//
// 이전에는 IdP 세션과 refresh token 만 끊었다. 그래서 관리자가 "강제 로그아웃" 을 눌러도
// 자체 세션 쿠키로 인가를 들고 가는 RP 는 그대로 살아 있었다 — 버튼의 의미와 실제 효과가
// 달랐고, 아무도 그걸 알 수 없는 형태의 고장이었다.
//
// 타깃은 **주체 단위**로 찾는다(`getOidcBackchannelTargetsForUser`). 세션 단위 탐색은
// grant/refresh 행에 의존하는데 그 행들은 단명하므로, offline_access 를 쓰지 않는 RP 는
// 로그인 몇 분 뒤부터 아예 탐색되지 않는다. 자세한 근거는 그 함수의 주석 참조.
export async function forceLogout(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const userId = params.id;

    // ctrls C-13: cross-tenant IDOR 차단 — 대상이 본 테넌트 user 인지 검증.
    const tenantCheck = await assertUserInTenant(db, tenant.id, userId);
    if (!tenantCheck.ok) return tenantCheck.error;

    // 폼 요청 파싱(사용 값은 없지만 액션 계약 일관성 유지).
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;

    const { sessions: sessionCount, backchannelTargets } = await revokeUserEverywhere(event, {
        db,
        tenant,
        userId,
        actorId: locals.user!.id,
        reason: "force_logout",
    });

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId,
        actorId: locals.user!.id,
        kind: "sessions_revoked",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { backchannelTargets, sessions: sessionCount },
    });

    return { forcedLogout: true };
}

// ── MFA(TOTP) 초기화 ───────────────────────────────────────────────────────
// OTP 분실 시 본인은 account/mfa 의 self-service delete 를 쓸 수 없다(해제 전
// 현재 TOTP 코드 재인증을 요구하는데, 분실했으니 그 코드를 낼 수 없다 — 로그인조차
// MFA 단계에서 막힌다). 관리자가 재인증 없이 대상 유저의 TOTP + 백업코드를 지워
// 다음 로그인부터 MFA 를 다시 등록하게 한다.
//
// self-service delete(account/mfa/+page.server.ts)와 동일하게 신뢰 기기도 전부
// 폐기한다 — MFA 가 사라졌으므로 "MFA 를 통과한 기기" 라는 신뢰의 근거도 사라진다.
export async function resetMfa(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const userId = params.id;

    // ctrls C-13: cross-tenant IDOR 차단 — 대상이 본 테넌트 user 인지 검증.
    const tenantCheck = await assertUserInTenant(db, tenant.id, userId);
    if (!tenantCheck.ok) return tenantCheck.error;

    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;

    const [target] = await db.select({ email: users.email, locale: users.locale }).from(users).where(eq(users.id, userId)).limit(1);

    await db.delete(credentials).where(and(eq(credentials.userId, userId), eq(credentials.type, TOTP_CREDENTIAL_TYPE)));
    await db.delete(credentials).where(and(eq(credentials.userId, userId), eq(credentials.type, BACKUP_CODE_CREDENTIAL_TYPE)));
    await revokeAllTrustedDevices(db, userId);

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId,
        actorId: locals.user!.id,
        kind: "mfa_deleted",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
    });

    if (target) {
        dispatchSecurityAlert({ to: target.email, locale: target.locale, kind: "mfa_reset_by_admin", platform: event.platform });
    }

    return { mfaReset: true };
}
