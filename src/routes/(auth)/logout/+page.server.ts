import { redirect } from "@sveltejs/kit";
import type { RequestEvent } from "@sveltejs/kit";
import type { Actions, PageServerLoad } from "./$types";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { requireDbContext } from "$lib/server/auth/guards";
import { clearSessionCookie, revokeSession } from "$lib/server/auth/session";
import { SESSION_COOKIE_NAME } from "$lib/server/auth/constants";
import { getActiveSigningKey } from "$lib/server/crypto/keys";
import { getOidcBackchannelTargets, sendOneBackchannelLogout } from "$lib/server/oidc/logout";
import { revokeRefreshTokensForSession } from "$lib/server/oidc/refresh";
import { samlSloStates } from "$lib/server/db/schema";
import { collectPendingSpData } from "$lib/server/saml/slo";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";

const SLO_STATE_TTL_MS = 10 * 60 * 1000; // 10 분

/**
 * IdP-initiated 로그아웃.
 *
 * 활성 SAML 세션이 하나라도 있으면 순차 리다이렉트 체인(/saml/slo) 으로 위임하고,
 * 그렇지 않으면 곧바로 세션을 폐기한다.
 *
 * - SAML 체인에 넘기는 경우: IdP 세션과 쿠키는 체인 종료 시점(/saml/slo) 에서 정리된다.
 * - OIDC back-channel 로그아웃은 양쪽 경로에서 waitUntil 로 발사된다.
 *
 * 반환값: SAML 체인을 타야 하면 samlSloStates.id, 아니면 null.
 */
async function performLogout(event: RequestEvent): Promise<string | null> {
    const sessionToken = event.cookies.get(SESSION_COOKIE_NAME);

    if (!sessionToken || !event.locals.db || !event.locals.tenant || !event.locals.session || !event.locals.user) {
        clearSessionCookie(event.cookies, event.url);
        return null;
    }

    const { db, tenant } = requireDbContext(event.locals);
    const requestMetadata = getRequestMetadata(event);

    // 세션 값 캡처 (폐기 전)
    const sessionId = event.locals.session.id;
    const idpSessionId = event.locals.session.idpSessionId;
    const userId = event.locals.user.id;

    // OIDC back-channel 로그아웃 발송 (waitUntil)
    const issuerUrl = resolveIssuerUrl(event.locals.runtimeConfig, event.url.origin, tenant.slug);
    const signingKeySecrets = event.locals.runtimeConfig.signingKeySecrets;
    if (signingKeySecrets.length > 0) {
        const bcTargets = await getOidcBackchannelTargets(db, tenant.id, sessionId);
        if (bcTargets.length > 0) {
            const signingKey = await getActiveSigningKey(db, tenant.id, signingKeySecrets);
            if (signingKey) {
                const bcPromises = bcTargets.map((t) =>
                    sendOneBackchannelLogout(t, userId, idpSessionId, issuerUrl, signingKey.privateKey, signingKey.kid, event.platform?.env?.OIDC_WEBHOOK_QUEUE).catch(() => undefined),
                );
                const wait = event.platform?.ctx?.waitUntil?.bind(event.platform.ctx);
                if (wait) {
                    wait(Promise.all(bcPromises));
                } else {
                    await Promise.all(bcPromises);
                }
            }
        }
    }

    // SAML 세션이 활성인 경우 → SLO 체인 개시를 위해 state 를 만들어 두고,
    // 실제 세션/쿠키 폐기는 체인 종료 시점으로 미룬다.
    const samlPending = await collectPendingSpData(db, sessionId);
    if (samlPending.length > 0) {
        const stateId = crypto.randomUUID();
        await db.insert(samlSloStates).values({
            id: stateId,
            tenantId: tenant.id,
            idpSessionRecordId: sessionId,
            userId,
            initiatingSpEntityId: null,
            inResponseTo: null,
            initiatorSloUrl: null,
            completionUri: "/login",
            pendingSpDataJson: JSON.stringify(samlPending),
            expiresAt: new Date(Date.now() + SLO_STATE_TTL_MS),
        });

        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId,
            actorId: userId,
            kind: "logout",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { chained: true, pending: samlPending.length },
        });

        return stateId;
    }

    // SAML 세션이 없으면 즉시 로그아웃 완료
    await revokeSession(db, idpSessionId);
    // 이 세션으로 발급된 OIDC refresh token 도 함께 폐기 (offline_access 무효화).
    await revokeRefreshTokensForSession(db, sessionId);

    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId,
        actorId: userId,
        kind: "logout",
        outcome: "success",
        ip: requestMetadata.ip,
        userAgent: requestMetadata.userAgent,
    });

    clearSessionCookie(event.cookies, event.url);
    return null;
}

export const load: PageServerLoad = async ({ locals }) => {
    if (!locals.user) throw redirect(303, "/login");
    return {};
};

export const actions: Actions = {
    default: async (event) => {
        const sloStateId = await performLogout(event);
        if (sloStateId) {
            throw redirect(303, `/saml/slo?state=${sloStateId}`);
        }
        throw redirect(303, "/login");
    },
};
