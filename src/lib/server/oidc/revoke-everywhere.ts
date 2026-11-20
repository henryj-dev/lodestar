/**
 * 사용자의 모든 IdP 세션 + OIDC refresh token 을 폐기하고 **RP 에 back-channel logout 을 보낸다.**
 *
 * 예전에는 관리자 "강제 로그아웃" 만 RP 에 통지했다. 비활성/잠금, 역할 변경, 비밀번호 리셋, 본인의
 * "모든 기기에서 로그아웃", 탈퇴 요청은 IdP 세션만 끊었다. 그래서 자체 세션으로 인가를 들고 가는
 * RP 는 정지된 계정을 RP 세션 수명 동안 계속 살려 두었다. 세션을 철회하는 모든 경로가 이 함수 하나로
 * 같은 일을 하게 한다.
 *
 * 타깃은 **주체 단위**로 찾는다(`getOidcBackchannelTargetsForUser`). 세션 단위 탐색은 단명하는
 * grant/refresh 행에 의존해서 offline_access 를 쓰지 않는 RP 를 놓친다(그 함수 주석 참고).
 *
 * 통지는 최선 노력이다. 폐기는 통지보다 먼저 커밋되고, 전송 실패는 감사(`backchannel_logout_sent`,
 * outcome=failure)로만 남는다. 응답 이후 실행(waitUntil)이 가능하면 그쪽으로 넘긴다.
 */
import type { RequestEvent } from "@sveltejs/kit";
import { and, eq, gt, isNull } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { sessions } from "$lib/server/db/schema";
import { revokeAllUserSessions } from "$lib/server/auth/session";
import { revokeAllUserRefreshTokens } from "$lib/server/oidc/refresh";
import { getOidcBackchannelTargetsForUser, sendOneBackchannelLogout, type BackchannelTarget } from "$lib/server/oidc/logout";
import { getActiveSigningKey } from "$lib/server/crypto/keys";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";

export interface RevokeEverywhereResult {
    /** 폐기 직전에 살아 있던 세션 수. */
    sessions: number;
    /** back-channel logout 을 보낼 클라이언트 수. */
    backchannelTargets: number;
}

export async function revokeUserEverywhere(
    event: RequestEvent,
    params: {
        db: DB;
        tenant: { id: string; slug: string };
        userId: string;
        /** 조치한 사람. 본인 조치면 userId 와 같고, 시스템 조치면 null. */
        actorId: string | null;
        /** 감사 detail 에 남길 사유(예: "user_disabled", "password_reset"). */
        reason: string;
        revokedAt?: Date;
    },
): Promise<RevokeEverywhereResult> {
    const { db, tenant, userId, actorId, reason } = params;
    const { locals, url, platform } = event;

    // 폐기 **전에** 살아 있는 세션 id 를 읽는다. sid 를 요구하는 RP 에는 세션마다 한 건씩 보내야 하는데,
    // 폐기 후에는 목록을 다시 만들 수 없다. sessions.id 가 ID 토큰의 `sid` 와 같은 값이다.
    // 대상 조회가 실패해도 폐기는 반드시 한다 — 통지보다 폐기가 우선이다.
    const { liveSessions, bcTargets } = await loadNotifyTargets(db, tenant.id, userId);

    await revokeAllUserSessions(db, userId, params.revokedAt);
    await revokeAllUserRefreshTokens(db, userId);

    const result = { sessions: liveSessions.length, backchannelTargets: bcTargets.length };
    const signingKeySecrets = locals.runtimeConfig.signingKeySecrets;
    if (bcTargets.length === 0 || signingKeySecrets.length === 0) return result;

    const meta = getRequestMetadata(event);

    // 여기부터는 최선 노력이다. 서명키를 풀지 못하는 등(예: previous 시크릿을 너무 일찍 지움) 예외가
    // 나도 호출자의 나머지 처리(신뢰 기기 폐기·감사·알림)를 깨지 않도록 삼키고 감사에만 남긴다.
    const signer = await loadSigner(db, tenant, locals.runtimeConfig, url.origin, signingKeySecrets);
    if (!signer) {
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId,
            actorId,
            kind: "backchannel_logout_sent",
            outcome: "failure",
            ip: meta.ip,
            userAgent: meta.userAgent,
            detail: { reason, error: "signing_key_unavailable", targets: bcTargets.map((t) => t.clientId) },
        }).catch(() => undefined);
        return result;
    }
    const { key, issuerUrl } = signer;
    const queue = platform?.env?.OIDC_WEBHOOK_QUEUE;

    const deliver = async (target: BackchannelTarget, sessionId: string) => {
        const detail = {
            clientId: target.clientId,
            backchannelLogoutUri: target.backchannelLogoutUri,
            sessionRequired: target.backchannelLogoutSessionRequired,
            reason,
        };
        try {
            const sent = await sendOneBackchannelLogout(target, userId, sessionId, issuerUrl, key.privateKey, key.kid, queue);
            await recordAuditEvent(db, {
                tenantId: tenant.id,
                userId,
                actorId,
                spOrClientId: target.clientId,
                kind: "backchannel_logout_sent",
                outcome: "success",
                ip: meta.ip,
                userAgent: meta.userAgent,
                detail: { ...detail, ...sent },
            });
        } catch {
            await recordAuditEvent(db, {
                tenantId: tenant.id,
                userId,
                actorId,
                spOrClientId: target.clientId,
                kind: "backchannel_logout_sent",
                outcome: "failure",
                ip: meta.ip,
                userAgent: meta.userAgent,
                detail,
            }).catch(() => undefined);
        }
    };

    const deliveries: Promise<void>[] = [];
    for (const target of bcTargets) {
        if (target.backchannelLogoutSessionRequired) {
            // sid 를 요구하는 RP: 끊은 세션마다 한 건. 세션이 없었다면 보낼 sid 가 없으니 건너뛴다
            // (sid 없는 토큰은 그 RP 가 거부한다).
            for (const s of liveSessions) deliveries.push(deliver(target, s.id));
        } else {
            // 주체 단위 RP: sub 만 실린다 = "이 사용자의 세션 전부".
            deliveries.push(deliver(target, ""));
        }
    }

    const wait = platform?.ctx?.waitUntil?.bind(platform.ctx);
    if (wait) wait(Promise.all(deliveries));
    else await Promise.all(deliveries);
    return result;
}

async function loadNotifyTargets(db: DB, tenantId: string, userId: string): Promise<{ liveSessions: { id: string }[]; bcTargets: BackchannelTarget[] }> {
    try {
        const liveSessions = await db
            .select({ id: sessions.id })
            .from(sessions)
            .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt), gt(sessions.expiresAt, new Date())));
        const bcTargets = await getOidcBackchannelTargetsForUser(db, tenantId, userId);
        return { liveSessions, bcTargets };
    } catch {
        return { liveSessions: [], bcTargets: [] };
    }
}

async function loadSigner(
    db: DB,
    tenant: { id: string; slug: string },
    runtimeConfig: App.Locals["runtimeConfig"],
    origin: string,
    signingKeySecrets: string[],
): Promise<{ key: NonNullable<Awaited<ReturnType<typeof getActiveSigningKey>>>; issuerUrl: string } | null> {
    try {
        const key = await getActiveSigningKey(db, tenant.id, signingKeySecrets);
        if (!key) return null;
        return { key, issuerUrl: resolveIssuerUrl(runtimeConfig, origin, tenant.slug) };
    } catch {
        return null;
    }
}
