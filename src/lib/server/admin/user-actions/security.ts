import type { RequestEvent } from "@sveltejs/kit";
import { and, eq, gt, isNull } from "drizzle-orm";
import { requireAdminContext, assertUserInTenant } from "$lib/server/auth/guards";
import { revokeAllUserSessions } from "$lib/server/auth/session";
import { revokeAllUserRefreshTokens } from "$lib/server/oidc/refresh";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";
import { sessions } from "$lib/server/db/schema";
import { getOidcBackchannelTargetsForUser, sendOneBackchannelLogout } from "$lib/server/oidc/logout";
import { getActiveSigningKey } from "$lib/server/crypto/keys";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";
import { requireCsrf } from "$lib/server/admin/errors";

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
    const { locals, params, request, url, platform } = event;
    const { db, tenant } = requireAdminContext(locals);
    const userId = params.id;

    // ctrls C-13: cross-tenant IDOR 차단 — 대상이 본 테넌트 user 인지 검증.
    const tenantCheck = await assertUserInTenant(db, tenant.id, userId);
    if (!tenantCheck.ok) return tenantCheck.error;

    // 폼 요청 파싱(사용 값은 없지만 액션 계약 일관성 유지).
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;

    // 폐기 **전에** 살아 있는 세션의 idpSessionId 를 읽어 둔다. sid 를 요구하는 클라이언트
    // (backchannel_logout_session_required)에는 세션별로 한 건씩 보내야 하는데, 폐기 후에는
    // 그 목록을 다시 만들 수 없다. (revokeAssignment 가 삭제 전에 대상을 읽어 두는 것과 같은 패턴.)
    const liveSessions = await db
        .select({ idpSessionId: sessions.idpSessionId })
        .from(sessions)
        .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt), gt(sessions.expiresAt, new Date())));
    const bcTargets = await getOidcBackchannelTargetsForUser(db, tenant.id, userId);

    await revokeAllUserSessions(db, userId);
    await revokeAllUserRefreshTokens(db, userId);

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId,
        actorId: locals.user!.id,
        kind: "sessions_revoked",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { backchannelTargets: bcTargets.length, sessions: liveSessions.length },
    });

    // back-channel logout 발행 — 전송 실패는 삼킨다(로그아웃 자체는 이미 커밋됐다).
    const signingKeySecrets = locals.runtimeConfig.signingKeySecrets;
    if (bcTargets.length > 0 && signingKeySecrets.length > 0) {
        const issuerUrl = resolveIssuerUrl(locals.runtimeConfig, url.origin);
        const signingKey = await getActiveSigningKey(db, tenant.id, signingKeySecrets);
        if (signingKey) {
            const promises: Promise<unknown>[] = [];
            for (const target of bcTargets) {
                if (target.backchannelLogoutSessionRequired) {
                    // sid 를 요구하는 클라이언트: 끊은 세션마다 한 건씩. 세션이 없었다면 보낼 sid 가
                    // 없으므로 건너뛴다(주체 단위 토큰을 보내면 그 RP 는 sid 부재로 거부한다).
                    for (const s of liveSessions) {
                        promises.push(sendOneBackchannelLogout(target, userId, s.idpSessionId, issuerUrl, signingKey.privateKey, signingKey.kid).catch(() => undefined));
                    }
                } else {
                    // 주체 단위 클라이언트: sub 만 실린다 = "이 사용자의 세션 전부".
                    promises.push(sendOneBackchannelLogout(target, userId, "", issuerUrl, signingKey.privateKey, signingKey.kid).catch(() => undefined));
                }
            }
            const wait = platform?.ctx?.waitUntil?.bind(platform.ctx);
            if (wait) {
                wait(Promise.all(promises));
            } else {
                await Promise.all(promises);
            }
        }
    }

    return { forcedLogout: true };
}
