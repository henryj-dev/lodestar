/**
 * SAML 2.0 Single Logout (SLO) 엔드포인트 — 순차 리다이렉트 체인 구현.
 *
 * 한 번의 브라우저 네비게이션에서 여러 SP 를 로그아웃시키기 위해, 체인 상태를
 * `samlSloStates` 테이블에 저장하고 RelayState 로 `samlSloStates.id` 를 전달해
 * 각 SP 의 응답을 받아 다음 SP 로 이어간다.
 *
 * 처리 분기 (쿼리 파라미터 기준):
 *   A. SAMLResponse + RelayState : 체인 진행 중인 SP 로부터의 LogoutResponse 수신
 *      → 다음 pending SP 로 리다이렉트하거나, 없으면 체인 종료
 *   B. state            : IdP-initiated SLO 체인 시작 (로그아웃 페이지에서 진입)
 *   C. SAMLRequest      : SP-initiated SLO 시작
 *   D. 그 외             : 세션만 폐기하고 /
 */

import { error, redirect } from "@sveltejs/kit";
import type { RequestEvent, RequestHandler } from "./$types";
import { and, eq, gt } from "drizzle-orm";
import { samlAuthnRequestIds, samlSessions, samlSloStates, samlSps, sessions } from "$lib/server/db/schema";
import { getRequestMetadata, recordAuditEvent } from "$lib/server/audit";
import { requireDbContext } from "$lib/server/auth/guards";
import { SESSION_COOKIE_NAME } from "$lib/server/auth/constants";
import { getActiveSigningKey } from "$lib/server/crypto/keys";
import { getOidcBackchannelTargets, sendOneBackchannelLogout } from "$lib/server/oidc/logout";
import { revokeRefreshTokensForSession } from "$lib/server/oidc/refresh";
import {
    buildSamlLogoutRequest,
    buildSamlLogoutResponse,
    buildSamlSloRedirectUrl,
    collectPendingSpData,
    parseSamlLogoutRequest,
    parseSamlLogoutResponseInResponseTo,
    type PendingSpData,
} from "$lib/server/saml/slo";
import { verifySamlRedirectSignature } from "$lib/server/saml/parse-authn-request";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";
import { translate } from "$lib/i18n/server";

const SLO_STATE_TTL_MS = 10 * 60 * 1000; // 10 분
const SLO_REQUEST_ID_TTL_MS = 10 * 60 * 1000; // LogoutRequest replay 가드 보존 기간

function parsePendingSpData(json: string): PendingSpData[] {
    try {
        const parsed = JSON.parse(json);
        if (!Array.isArray(parsed)) return [];
        return parsed as PendingSpData[];
    } catch {
        return [];
    }
}

async function fireOidcBackchannelLogout(event: RequestEvent, idpSession: typeof sessions.$inferSelect): Promise<void> {
    const { locals, platform, url } = event;
    const { db, tenant } = requireDbContext(locals);
    const signingKeySecrets = locals.runtimeConfig.signingKeySecrets;
    if (signingKeySecrets.length === 0) return;

    const bcTargets = await getOidcBackchannelTargets(db, tenant.id, idpSession.id);
    if (bcTargets.length === 0) return;

    const signingKey = await getActiveSigningKey(db, tenant.id, signingKeySecrets);
    if (!signingKey) return;

    const issuerUrl = resolveIssuerUrl(locals.runtimeConfig, url.origin, locals.tenant?.slug ?? undefined);
    const bcPromises = bcTargets.map((t) =>
        sendOneBackchannelLogout(t, idpSession.userId, idpSession.idpSessionId, issuerUrl, signingKey.privateKey, signingKey.kid, event.platform?.env?.OIDC_WEBHOOK_QUEUE).catch(() => undefined),
    );
    const wait = platform?.ctx?.waitUntil?.bind(platform.ctx);
    if (wait) {
        wait(Promise.all(bcPromises));
    } else {
        await Promise.all(bcPromises);
    }
}

/**
 * 체인의 다음 SP 에게 서명된 LogoutRequest 를 보낸다.
 * pendingSpDataJson 을 먼저 업데이트한 뒤(처리할 SP 를 맨 앞에서 제거) 리다이렉트한다.
 * 이렇게 해야 사용자가 새로 고침해도 같은 SP 가 중복 처리되지 않는다.
 */
async function redirectToNextSp(event: RequestEvent, stateId: string, remaining: PendingSpData[], opts: { trackInResponseTo?: boolean } = {}): Promise<never> {
    const { locals, url } = event;
    const { db, tenant } = requireDbContext(locals);

    if (remaining.length === 0) {
        throw error(500, translate(locals.locale, "saml.errors.slo_no_remaining_sp"));
    }

    const next = remaining[0];
    const rest = remaining.slice(1);

    // 이번 hop 에 보낼 LogoutRequest ID — 반환 LogoutResponse 의 InResponseTo 와 매칭되어야 한다.
    const requestId = `_l${crypto.randomUUID().replace(/-/g, "")}`;

    // 먼저 DB 를 업데이트한다 (next SP 를 pending 에서 제거).
    // ctrls M-6: IdP-initiated 체인은 서명 검증이 없으므로(SP-initiated 는 Case A 에서
    // cert 서명 검증됨), 이번 hop 의 requestId 를 inResponseTo 컬럼에 저장해 두고 응답의
    // InResponseTo 와 대조한다. SP-initiated 체인에서는 inResponseTo 가 최초 SP 응답용으로
    // 쓰이므로 덮어쓰지 않는다(trackInResponseTo=false).
    await db
        .update(samlSloStates)
        .set(opts.trackInResponseTo ? { pendingSpDataJson: JSON.stringify(rest), inResponseTo: requestId } : { pendingSpDataJson: JSON.stringify(rest) })
        .where(eq(samlSloStates.id, stateId));

    const signingKeySecrets = locals.runtimeConfig.signingKeySecrets;
    if (signingKeySecrets.length === 0) {
        throw error(500, translate(locals.locale, "saml.errors.slo_signing_key_not_configured"));
    }
    const signingKey = await getActiveSigningKey(db, tenant.id, signingKeySecrets);
    if (!signingKey) {
        throw error(500, translate(locals.locale, "saml.errors.slo_active_signing_key_missing"));
    }

    const issuerUrl = resolveIssuerUrl(locals.runtimeConfig, url.origin, locals.tenant?.slug ?? undefined);
    const lrXml = buildSamlLogoutRequest({
        id: requestId,
        issuerUrl,
        destination: next.sloUrl,
        nameId: next.nameId,
        nameIdFormat: next.nameIdFormat,
        sessionIndex: next.sessionIndex,
    });

    const redirectUrl = await buildSamlSloRedirectUrl({
        sloUrl: next.sloUrl,
        xml: lrXml,
        param: "SAMLRequest",
        relayState: stateId,
        privateKey: signingKey.privateKey,
    });

    throw redirect(302, redirectUrl);
}

/**
 * 체인 종료 처리: IdP 세션을 폐기하고 쿠키를 제거한 뒤, OIDC BC 로그아웃을
 * waitUntil 로 발송하고 state 행을 삭제한다. 최종 리다이렉트는 호출자가 수행한다.
 */
async function completeSloChain(event: RequestEvent, state: typeof samlSloStates.$inferSelect): Promise<void> {
    const { locals, cookies } = event;
    const { db, tenant } = requireDbContext(locals);

    // 1. 연결된 IdP 세션 조회 (아직 revoke 되지 않았다면)
    const [idpSession] = await db.select().from(sessions).where(eq(sessions.id, state.idpSessionRecordId)).limit(1);

    // 2. 남아있는 SAML 세션 전체를 endedAt 으로 표시 (일관성 유지)
    if (idpSession) {
        await db.update(samlSessions).set({ endedAt: new Date() }).where(eq(samlSessions.sessionId, idpSession.id));
    }

    // 3. OIDC BC 로그아웃 발송 (waitUntil)
    if (idpSession) {
        await fireOidcBackchannelLogout(event, idpSession);
    }

    // 4. IdP 세션 폐기
    if (idpSession && !idpSession.revokedAt) {
        await db
            .update(sessions)
            .set({ revokedAt: new Date() })
            .where(and(eq(sessions.id, idpSession.id), eq(sessions.tenantId, tenant.id)));
    }
    // 이 세션으로 발급된 OIDC refresh token 폐기 (offline_access 무효화).
    if (idpSession) await revokeRefreshTokensForSession(db, idpSession.id);

    // 5. 쿠키 제거
    cookies.delete(SESSION_COOKIE_NAME, { path: "/" });

    // 6. state 행 삭제
    await db.delete(samlSloStates).where(eq(samlSloStates.id, state.id));
}

export const GET: RequestHandler = async (event) => {
    const { locals, url, cookies } = event;
    const { db, tenant } = requireDbContext(locals);

    const samlRequest = url.searchParams.get("SAMLRequest");
    const samlResponse = url.searchParams.get("SAMLResponse");
    const relayState = url.searchParams.get("RelayState");
    const stateParam = url.searchParams.get("state");

    // ── Case A: SAMLResponse + RelayState → 체인 진행 중인 SP 의 응답 처리 ─────
    if (samlResponse && relayState) {
        const [state] = await db
            .select()
            .from(samlSloStates)
            .where(and(eq(samlSloStates.id, relayState), eq(samlSloStates.tenantId, tenant.id), gt(samlSloStates.expiresAt, new Date())))
            .limit(1);
        if (!state) {
            throw error(400, translate(locals.locale, "saml.errors.slo_state_invalid"));
        }

        // ctrls C-9: SP-initiated 흐름의 LogoutResponse 는 반드시 initiatingSp 의 cert
        // 로 서명 검증되어야 한다. cert 미등록이거나 Signature 파라미터 누락이면 응답을
        // 신뢰할 수 없으므로 거부.
        if (state.initiatingSpEntityId) {
            const [initiatingSp] = await db
                .select({ cert: samlSps.cert })
                .from(samlSps)
                .where(and(eq(samlSps.tenantId, tenant.id), eq(samlSps.entityId, state.initiatingSpEntityId)))
                .limit(1);
            if (!initiatingSp?.cert) {
                throw error(400, translate(locals.locale, "saml.errors.slo_initiating_sp_cert_missing"));
            }
            if (!url.searchParams.has("Signature")) {
                throw error(400, translate(locals.locale, "saml.errors.slo_logout_response_must_be_signed"));
            }
            const rawQuery = url.search.replace(/^\?/, "");
            const valid = await verifySamlRedirectSignature(rawQuery, initiatingSp.cert);
            if (!valid) {
                throw error(400, translate(locals.locale, "saml.errors.slo_logout_response_sig_invalid"));
            }
        } else if (state.inResponseTo) {
            // ctrls M-6: IdP-initiated 체인은 SP cert 서명 검증이 없다. 대신 응답의 InResponseTo 가
            // 직전에 이 SP 에게 보낸 LogoutRequest ID(state.inResponseTo)와 일치해야 한다.
            // stateId(RelayState)만 아는 제3자(체인 내 악성 SP 포함)가 임의 SAMLResponse 로
            // 체인을 순서 밖에서 구동/조기 종료(로그아웃 DoS)하는 것을 막는다. requestId 는
            // 122-bit 랜덤이며 해당 SP 에게만 전달된다.
            let respInResponseTo: string | null;
            try {
                respInResponseTo = await parseSamlLogoutResponseInResponseTo(samlResponse);
            } catch {
                throw error(400, translate(locals.locale, "saml.errors.slo_state_invalid"));
            }
            if (respInResponseTo !== state.inResponseTo) {
                throw error(400, translate(locals.locale, "saml.errors.slo_state_invalid"));
            }
        }

        // pendingSpDataJson 에 남아 있는 SP 목록 (현재 응답을 보낸 SP 는 이미 제거된 상태)
        const remaining = parsePendingSpData(state.pendingSpDataJson);

        // 다음 SP 가 있으면 이어서 진행
        if (remaining.length > 0) {
            await redirectToNextSp(event, state.id, remaining, { trackInResponseTo: !state.initiatingSpEntityId });
            // 위에서 redirect throw
        }

        // 남은 SP 가 없으면 체인 종료
        await completeSloChain(event, state);

        // SP-initiated 였다면 최초 SP 로 LogoutResponse 를 돌려준다.
        if (state.initiatorSloUrl && state.inResponseTo) {
            const signingKeySecrets = locals.runtimeConfig.signingKeySecrets;
            if (signingKeySecrets.length > 0) {
                const signingKey = await getActiveSigningKey(db, tenant.id, signingKeySecrets);
                if (signingKey) {
                    const issuerUrl = resolveIssuerUrl(locals.runtimeConfig, url.origin, locals.tenant?.slug ?? undefined);
                    const responseXml = buildSamlLogoutResponse({
                        id: `_lr${crypto.randomUUID().replace(/-/g, "")}`,
                        inResponseTo: state.inResponseTo,
                        issuerUrl,
                        destination: state.initiatorSloUrl,
                        status: "Success",
                    });
                    const redirectUrl = await buildSamlSloRedirectUrl({
                        sloUrl: state.initiatorSloUrl,
                        xml: responseXml,
                        param: "SAMLResponse",
                        privateKey: signingKey.privateKey,
                    });
                    throw redirect(302, redirectUrl);
                }
            }
            // 서명 키가 없으면 completionUri 로 폴백
        }

        throw redirect(302, state.completionUri);
    }

    // ── Case B: state 파라미터 → IdP-initiated 체인 시작 ────────────────────────
    if (stateParam) {
        const [state] = await db
            .select()
            .from(samlSloStates)
            .where(and(eq(samlSloStates.id, stateParam), eq(samlSloStates.tenantId, tenant.id), gt(samlSloStates.expiresAt, new Date())))
            .limit(1);
        if (!state) {
            throw error(400, translate(locals.locale, "saml.errors.slo_state_invalid"));
        }

        const pending = parsePendingSpData(state.pendingSpDataJson);

        if (pending.length === 0) {
            // 엣지 케이스: pending 이 없는데 state 만 있음 → 바로 종료
            await completeSloChain(event, state);
            throw redirect(302, state.completionUri);
        }

        await redirectToNextSp(event, state.id, pending, { trackInResponseTo: !state.initiatingSpEntityId });
        // redirect throw
    }

    // ── Case C: SAMLRequest → SP-initiated SLO 시작 ─────────────────────────────
    if (samlRequest) {
        let parsed;
        try {
            // 파서가 DOCTYPE/ENTITY 차단 + onErrorStopParsing + IssueInstant skew(±5분) 를 강제한다.
            parsed = await parseSamlLogoutRequest(samlRequest);
        } catch {
            throw error(400, translate(locals.locale, "saml.errors.slo_invalid_saml_request"));
        }

        // Destination 검증: SP 가 명시했으면 IdP 의 SLO endpoint 와 정확히 일치해야 한다.
        const cfgIssuer = resolveIssuerUrl(locals.runtimeConfig, url.origin, locals.tenant?.slug ?? undefined);
        if (parsed.destination) {
            const expectedDestination = `${cfgIssuer.replace(/\/+$/, "")}/saml/slo`;
            if (parsed.destination !== expectedDestination) {
                throw error(400, translate(locals.locale, "saml.errors.slo_destination_mismatch"));
            }
        }

        // SP 조회
        const [sp] = await db
            .select()
            .from(samlSps)
            .where(and(eq(samlSps.tenantId, tenant.id), eq(samlSps.entityId, parsed.issuer), eq(samlSps.enabled, true)))
            .limit(1);
        if (!sp) {
            throw error(400, translate(locals.locale, "saml.errors.slo_unknown_sp"));
        }

        // ctrls C-8: 모든 SP-initiated LogoutRequest 는 SP cert 로 서명 검증되어야
        // 한다. cert 미등록 SP 의 LogoutRequest 를 신뢰하면 공격자가 임의 entityId 로
        // 위조한 LogoutRequest 로 임의 사용자 강제 로그아웃 + SLO 체인을 트리거할 수
        // 있다. Signature 파라미터 누락도 동일하게 거부.
        if (!sp.cert) {
            throw error(400, translate(locals.locale, "saml.errors.slo_sp_cert_missing"));
        }
        if (!url.searchParams.has("Signature")) {
            throw error(400, translate(locals.locale, "saml.errors.slo_logout_request_must_be_signed"));
        }
        const rawQuery = url.search.replace(/^\?/, "");
        const valid = await verifySamlRedirectSignature(rawQuery, sp.cert);
        if (!valid) {
            throw error(400, translate(locals.locale, "saml.errors.slo_saml_request_sig_invalid"));
        }

        // Replay 가드: 서명 검증 성공 후 LogoutRequest ID 를 1회용으로 소비한다.
        // (서명 검증 뒤에 소비하므로, 미인증 요청으로 replay 테이블을 오염시키는 것을 막는다.)
        // AuthnRequest 와 동일한 saml_authn_request_ids 테이블을 공유 nonce 저장소로 사용.
        if (parsed.id) {
            const now = new Date();
            const [seen] = await db
                .select({ requestId: samlAuthnRequestIds.requestId })
                .from(samlAuthnRequestIds)
                .where(and(eq(samlAuthnRequestIds.tenantId, tenant.id), eq(samlAuthnRequestIds.requestId, parsed.id), gt(samlAuthnRequestIds.expiresAt, now)))
                .limit(1);
            if (seen) {
                throw error(400, translate(locals.locale, "saml.errors.slo_logout_request_replay"));
            }
            try {
                await db.insert(samlAuthnRequestIds).values({
                    tenantId: tenant.id,
                    requestId: parsed.id,
                    spEntityId: parsed.issuer,
                    expiresAt: new Date(Date.now() + SLO_REQUEST_ID_TTL_MS),
                });
            } catch {
                // unique 충돌 → replay 와 동일 처리
                throw error(400, translate(locals.locale, "saml.errors.slo_logout_request_replay"));
            }
        }

        // SessionIndex → SAML 세션 및 IdP 세션 식별
        const targetSessionIndex = parsed.sessionIndexes[0];
        let idpSession: typeof sessions.$inferSelect | null = null;
        let linkedSamlSessionId: string | null = null;
        if (targetSessionIndex) {
            const [row] = await db
                .select({ samlSessionId: samlSessions.id, idpSessionId: samlSessions.sessionId })
                .from(samlSessions)
                .where(and(eq(samlSessions.tenantId, tenant.id), eq(samlSessions.spId, sp.id), eq(samlSessions.sessionIndex, targetSessionIndex)))
                .limit(1);
            if (row) {
                linkedSamlSessionId = row.samlSessionId;
                if (row.idpSessionId) {
                    const [s] = await db.select().from(sessions).where(eq(sessions.id, row.idpSessionId)).limit(1);
                    idpSession = s ?? null;
                }
            }
        }
        if (!idpSession && locals.session) idpSession = locals.session;

        // 초기 SP 의 SAML 세션 종료
        if (linkedSamlSessionId) {
            await db.update(samlSessions).set({ endedAt: new Date() }).where(eq(samlSessions.id, linkedSamlSessionId));
        }

        // 감사 로그
        if (idpSession && locals.user) {
            const requestMetadata = getRequestMetadata(event);
            await recordAuditEvent(db, {
                tenantId: tenant.id,
                userId: locals.user.id,
                actorId: locals.user.id,
                kind: "saml_slo",
                outcome: "success",
                ip: requestMetadata.ip,
                userAgent: requestMetadata.userAgent,
                detail: { spEntityId: parsed.issuer },
            });
        }

        // 남은 SP 수집 (초기 요청 SP 제외)
        const pending: PendingSpData[] = idpSession ? await collectPendingSpData(db, idpSession.id, parsed.issuer) : [];

        // 남은 SP 가 없으면: 세션 폐기, BC 로그아웃 발송, sp 로 LogoutResponse 반환
        if (pending.length === 0) {
            // IdP 세션 일괄 종료 표시
            if (idpSession) {
                await db.update(samlSessions).set({ endedAt: new Date() }).where(eq(samlSessions.sessionId, idpSession.id));
                await fireOidcBackchannelLogout(event, idpSession);
                if (!idpSession.revokedAt) {
                    await db
                        .update(sessions)
                        .set({ revokedAt: new Date() })
                        .where(and(eq(sessions.id, idpSession.id), eq(sessions.tenantId, tenant.id)));
                }
                // 이 세션으로 발급된 OIDC refresh token 폐기 (offline_access 무효화).
                await revokeRefreshTokensForSession(db, idpSession.id);
            }
            cookies.delete(SESSION_COOKIE_NAME, { path: "/" });

            if (!sp.sloUrl) {
                throw redirect(302, "/");
            }
            const signingKeySecrets = locals.runtimeConfig.signingKeySecrets;
            if (signingKeySecrets.length === 0) {
                throw redirect(302, "/");
            }
            const signingKey = await getActiveSigningKey(db, tenant.id, signingKeySecrets);
            if (!signingKey) {
                throw redirect(302, "/");
            }
            const issuerUrl = resolveIssuerUrl(locals.runtimeConfig, url.origin, locals.tenant?.slug ?? undefined);
            const responseXml = buildSamlLogoutResponse({
                id: `_lr${crypto.randomUUID().replace(/-/g, "")}`,
                inResponseTo: parsed.id,
                issuerUrl,
                destination: sp.sloUrl,
                status: "Success",
            });
            const redirectUrl = await buildSamlSloRedirectUrl({
                sloUrl: sp.sloUrl,
                xml: responseXml,
                param: "SAMLResponse",
                relayState,
                privateKey: signingKey.privateKey,
            });
            throw redirect(302, redirectUrl);
        }

        // 남은 SP 가 있으면: samlSloState 생성 후 첫 SP 로 체인 시작
        if (!idpSession) {
            // 이론적으로 pending.length > 0 이려면 idpSession 이 있었어야 한다.
            throw error(500, translate(locals.locale, "saml.errors.slo_chain_init_failed"));
        }

        const stateId = crypto.randomUUID();
        const nowMs = Date.now();
        await db.insert(samlSloStates).values({
            id: stateId,
            tenantId: tenant.id,
            idpSessionRecordId: idpSession.id,
            userId: idpSession.userId,
            initiatingSpEntityId: parsed.issuer,
            inResponseTo: parsed.id,
            initiatorSloUrl: sp.sloUrl ?? null,
            completionUri: sp.sloUrl ?? "/login",
            pendingSpDataJson: JSON.stringify(pending),
            expiresAt: new Date(nowMs + SLO_STATE_TTL_MS),
        });

        await redirectToNextSp(event, stateId, pending);
        // redirect throw
    }

    // ── Case D: 그 외 fallback — 세션만 폐기하고 / 로 ───────────────────────────
    // ctrls LOW: 이 fallback 은 state-changing GET(세션 폐기)이라 <img src=".../saml/slo">
    // 같은 cross-site 임베드로 강제 로그아웃(CSRF)이 가능했다. 진짜 SAML 로그아웃은 Case C
    // (서명 검증된 SAMLRequest)로 처리되므로, 파라미터 없는 fallback 은 same-site 최상위
    // 네비게이션(로그아웃 링크 클릭)에서만 세션을 폐기한다. Sec-Fetch 미지원 구형 브라우저는
    // 통과. cross-site 임베드(image/iframe/empty 등)는 세션을 건드리지 않고 홈으로만 보낸다.
    const fetchSite = event.request.headers.get("sec-fetch-site");
    const fetchDest = event.request.headers.get("sec-fetch-dest");
    const embeddedCrossSite = (fetchSite && fetchSite !== "same-origin" && fetchSite !== "same-site" && fetchSite !== "none") || (fetchDest && fetchDest !== "document");
    if (locals.session && !embeddedCrossSite) {
        await db.update(sessions).set({ revokedAt: new Date() }).where(eq(sessions.id, locals.session.id));
        cookies.delete(SESSION_COOKIE_NAME, { path: "/" });
    }
    throw redirect(302, "/");
};

export const POST: RequestHandler = (event) => GET(event);
