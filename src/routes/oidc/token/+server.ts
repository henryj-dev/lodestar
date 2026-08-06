import { json } from "@sveltejs/kit";
import { eq } from "drizzle-orm";
import type { RequestHandler } from "./$types";
import { oidcClients, sessions } from "$lib/server/db/schema";
import { requireDbContext } from "$lib/server/auth/guards";
import { findActiveUserById } from "$lib/server/auth/users";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit";
import { checkRateLimit } from "$lib/server/ratelimit";
import { findOidcClient, isValidClientSecret, parseBasicAuth } from "$lib/server/oidc/client";
import { buildAddressClaim, buildOrganizationClaims, parseOrganizationClaimConfig } from "$lib/server/oidc/claims";
import { findAndConsumeGrant } from "$lib/server/oidc/grant";
import { verifyPkce } from "$lib/server/oidc/pkce";
import { issueRefreshToken, rotateRefreshToken, revokeRefreshTokenFamily } from "$lib/server/oidc/refresh";
import { generateAccessToken, getActiveSigningKey, signJwt } from "$lib/server/crypto/keys";
import { getActiveAssignment, hasServiceAccess, listActiveEntitlements, parseAssignmentAttributes } from "$lib/server/access/service-permissions";
import { getUserMembership, membershipToGroups } from "$lib/server/org/membership";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";
import type { DB } from "$lib/server/db";
import type { OidcClientRecord } from "$lib/server/oidc/client";

// ID Token 표준 클레임 — assignment.attributesJson 의 키와 충돌 시 표준 클레임이 우선한다.
//
// 표준 클레임이 아닌 셋(`entitlements`·`roles`·`roles_label`)도 여기 넣는다. **인가 판정에 쓰이는
// 값**이기 때문이다 — attributesJson 은 관리 화면의 자유 입력 텍스트인데, 그걸로 권한 클레임을
// 덮어쓸 수 있으면 권한 모델 자체가 무의미해진다. `roles` 는 원래 빠져 있어서
// `{"roles":["approver"]}` 한 줄로 실제 역할을 위조할 수 있었다(이 커밋에서 닫는다).
// `groups` 는 대입 순서상 지금도 덮이지 않지만, 순서에 의존하지 않도록 같이 예약한다.
const RESERVED_ID_TOKEN_CLAIMS = new Set([
    "iss",
    "sub",
    "aud",
    "azp",
    "iat",
    "exp",
    "auth_time",
    "jti",
    "nonce",
    "sid",
    "acr",
    "amr",
    "at_hash",
    "c_hash",
    "entitlements",
    "roles",
    "roles_label",
    "groups",
]);

const ACCESS_TOKEN_TTL_S = 300; // 5분
const ID_TOKEN_TTL_S = 600; // 10분

function tokenError(code: string, description: string, status = 400): Response {
    return new Response(JSON.stringify({ error: code, error_description: description }), {
        status,
        headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store, private",
            Pragma: "no-cache",
        },
    });
}

function clientAllowsGrant(client: OidcClientRecord, grantType: string): boolean {
    return client.grantTypes
        .split(",")
        .map((g) => g.trim())
        .includes(grantType);
}

interface GrantSessionCheck {
    row: typeof sessions.$inferSelect | null;
    revoked: boolean;
    expired: boolean;
}

/**
 * grant/refresh 에 연결된 IdP 세션을 조회하고 폐기(revoked)·만료(expired) 여부를 판정한다.
 * authorization_code / refresh_token 두 grant 경로에서 공통으로 사용한다.
 * 세션 row 가 없으면(예: onDelete set null 이전에 삭제) revoked/expired 모두 false 로 두어
 * 호출부의 기존 관례(row 부재 시 거부하지 않음)를 보존한다.
 */
async function checkGrantSession(db: DB, sessionId: string): Promise<GrantSessionCheck> {
    const [row] = await db.select().from(sessions).where(eq(sessions.id, sessionId)).limit(1);
    const session = row ?? null;
    return {
        row: session,
        revoked: Boolean(session?.revokedAt),
        expired: Boolean(session && session.expiresAt.getTime() <= Date.now()),
    };
}

interface BuildTokenParams {
    db: DB;
    tenantId: string;
    issuer: string;
    signingKeySecret: string;
    signingKey: Awaited<ReturnType<typeof getActiveSigningKey>>;
    user: NonNullable<Awaited<ReturnType<typeof findActiveUserById>>>;
    clientId: string; // 공개 client_id (aud/azp/access token 용)
    clientDbId: string; // oidcClients.id PK (서비스 권한 조회용)
    organizationClaimConfig: string | null; // oidcClients.organizationClaimConfig(JSON text). null=전량 노출.
    scope: string;
    sessionId: string | null;
    nonce: string | null;
    acr: string | null;
    amr: string | null;
    authTimeSec: number;
}

/**
 * ID Token(RS256 JWT) + opaque access token 을 생성한다.
 * authorization_code / refresh_token 두 grant 에서 공통으로 사용한다.
 */
async function buildTokens(params: BuildTokenParams): Promise<{ idToken: string; accessToken: string }> {
    const { db, tenantId, issuer, signingKeySecret, signingKey, user, clientId, scope } = params;
    if (!signingKey) throw new Error("signingKey required");

    const nowSec = Math.floor(Date.now() / 1000);
    const scopes = new Set(scope.split(" "));

    const idTokenPayload: Record<string, unknown> = {
        iss: issuer,
        // 계약: sub === users.id. 이 동일성에 외부 소비자가 의존한다 —
        // Service-to-Service TOTP API(`/api/totp/{enroll,verify,status}`)가 받는 `userId` 가
        // 바로 이 값이고, RP 는 로그인에서 얻은 sub 를 그대로 그 body 에 넣는다.
        // 불투명 식별자(pairwise 등)로 바꾸려면 그 API 와 RP 연동을 함께 옮겨야 한다.
        // 그냥 바꾸면 TOTP 검증이 조용히 404(TOTP not enrolled)로 떨어진다.
        sub: user.id,
        aud: clientId,
        azp: clientId,
        iat: nowSec,
        exp: nowSec + ID_TOKEN_TTL_S,
        auth_time: params.authTimeSec,
        jti: crypto.randomUUID(),
    };

    if (scopes.has("email")) {
        idTokenPayload.email = user.email;
        idTokenPayload.email_verified = Boolean(user.emailVerifiedAt);
    }
    if (scopes.has("profile")) {
        idTokenPayload.name = user.displayName;
        idTokenPayload.given_name = user.givenName;
        idTokenPayload.family_name = user.familyName;
        idTokenPayload.preferred_username = user.username ?? user.email.split("@")[0];
        idTokenPayload.picture = user.avatarUrl;
        idTokenPayload.locale = user.locale;
        idTokenPayload.zoneinfo = user.zoneinfo;
        idTokenPayload.birthdate = user.birthdate;
    }
    if (scopes.has("phone")) {
        idTokenPayload.phone_number = user.phoneNumber;
        idTokenPayload.phone_number_verified = Boolean(user.phoneVerifiedAt);
    }
    if (scopes.has("address")) {
        const address = buildAddressClaim(user);
        if (address) idTokenPayload.address = address;
    }

    if (params.nonce) idTokenPayload.nonce = params.nonce;
    if (params.sessionId) idTokenPayload.sid = params.sessionId;
    if (params.acr) idTokenPayload.acr = params.acr;
    if (params.amr) idTokenPayload.amr = params.amr.split(" ").filter(Boolean);

    // 서비스 권한 매핑 — role / 추가 attributes 를 ID Token 에 머지한다.
    const assignment = await getActiveAssignment(db, { tenantId, userId: user.id, serviceType: "oidc", serviceRefId: params.clientDbId });
    if (assignment?.role) {
        idTokenPayload.roles = [assignment.role.key];
        idTokenPayload.roles_label = assignment.role.label;
    }
    if (assignment) {
        // entitlement 클레임 — roles 와 직교하는 권한 축. scope 게이트가 없다(roles 와 동일 규칙,
        // groups/organization 과 다름). **0개면 키를 아예 넣지 않는다** — 빈 배열도 넣지 않으므로
        // entitlement 를 정의하지 않은 기존 RP 의 페이로드는 키 단위로 변경 전과 동일하다.
        //
        // attributesJson 머지 **앞에** 둔다. 뒤에 두면 순서가 우연히 보호해 주는 상태가 되어
        // RESERVED_ID_TOKEN_CLAIMS 가 실제로는 아무 일도 하지 않게 되고, 나중에 이 줄을 옮긴
        // 사람이 위조 경로를 되살릴 수 있다. 앞에 두면 예약 목록이 유일한 방어이고 테스트가 그것을 검증한다.
        const entitlements = await listActiveEntitlements(db, assignment, tenantId);
        if (entitlements.length > 0) idTokenPayload.entitlements = entitlements;

        const extra = parseAssignmentAttributes(assignment.attributesJson);
        for (const [k, v] of Object.entries(extra)) {
            if (RESERVED_ID_TOKEN_CLAIMS.has(k)) continue;
            idTokenPayload[k] = v;
        }
    }

    // groups / organization scope — 활성 조직 멤버십 기반. userinfo 응답과 동일 로직
    // (membershipToGroups / buildOrganizationClaims)을 공유한다. 표준 claim 이므로 assignment
    // 머지 이후에 설정. 두 scope 모두 요청돼도 멤버십은 한 번만 조회한다.
    if (scopes.has("groups") || scopes.has("organization")) {
        const membership = await getUserMembership(db, user.id);
        if (scopes.has("groups")) {
            idTokenPayload.groups = membershipToGroups(membership);
        }
        if (scopes.has("organization")) {
            Object.assign(idTokenPayload, buildOrganizationClaims(membership, parseOrganizationClaimConfig(params.organizationClaimConfig)));
        }
    }

    const idToken = await signJwt(idTokenPayload, signingKey.privateKey, signingKey.kid);

    const accessToken = await generateAccessToken(
        {
            sub: user.id,
            tenantId,
            clientId,
            scope,
            iat: nowSec,
            exp: nowSec + ACCESS_TOKEN_TTL_S,
            jti: crypto.randomUUID(),
            aud: clientId,
            iss: issuer,
        },
        signingKeySecret,
    );

    return { idToken, accessToken };
}

function tokenResponse(body: Record<string, unknown>): Response {
    return json(body, {
        headers: {
            "Cache-Control": "no-store, private",
            Pragma: "no-cache",
        },
    });
}

export const POST: RequestHandler = async (event) => {
    const { locals, request, url } = event;
    const { db, tenant, rateLimitStore } = requireDbContext(locals);
    // signingKeySecret = current (발급 전용), signingKeySecrets = 복호 fallback 용.
    const { signingKeySecret, signingKeySecrets } = locals.runtimeConfig;

    // 레이트 리밋: IP당 30회/분
    const { ip, ipKey, userAgent } = getRequestMetadata(event);
    const rl = await checkRateLimit(rateLimitStore, `token:${ipKey}`, { windowMs: 60 * 1000, limit: 30 });
    if (!rl.allowed) {
        return new Response(
            JSON.stringify({
                error: "rate_limit_exceeded",
                error_description: "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.",
            }),
            {
                status: 429,
                headers: {
                    "Content-Type": "application/json",
                    "Retry-After": String(Math.ceil(rl.retryAfterMs / 1000)),
                },
            },
        );
    }

    if (!signingKeySecret) {
        return tokenError("server_error", "IDP_SIGNING_KEY_SECRET 가 설정되지 않았습니다.", 503);
    }

    const issuer = resolveIssuerUrl(locals.runtimeConfig, url.origin);
    const body = await request.formData();

    const recordTokenFailure = async (clientIdForAudit: string | null, errorCode: string, description: string): Promise<void> => {
        try {
            await recordAuditEvent(db, {
                tenantId: tenant.id,
                spOrClientId: clientIdForAudit,
                kind: "oidc_token",
                outcome: "failure",
                ip,
                userAgent,
                detail: { error: errorCode, description },
            });
        } catch {
            /* audit 기록 실패는 무시 */
        }
    };

    const grantType = String(body.get("grant_type") ?? "");
    if (grantType !== "authorization_code" && grantType !== "refresh_token") {
        await recordTokenFailure(null, "unsupported_grant_type", `지원하지 않는 grant_type: ${grantType}`);
        return tokenError("unsupported_grant_type", "authorization_code, refresh_token 만 지원합니다.");
    }

    // ── 클라이언트 인증 (Basic 헤더 또는 body params) — 두 grant 공통 ────────────
    let clientId: string;
    let clientSecret: string;

    const authHeader = request.headers.get("Authorization");
    if (authHeader) {
        const parsed = parseBasicAuth(authHeader);
        if (!parsed) {
            await recordTokenFailure(null, "invalid_client", "잘못된 Authorization 헤더");
            return tokenError("invalid_client", "잘못된 Authorization 헤더입니다.", 401);
        }
        clientId = parsed.clientId;
        clientSecret = parsed.clientSecret;
    } else {
        clientId = String(body.get("client_id") ?? "");
        clientSecret = String(body.get("client_secret") ?? "");
    }

    if (!clientId) {
        await recordTokenFailure(null, "invalid_client", "client_id 누락");
        return tokenError("invalid_client", "client_id 가 필요합니다.", 401);
    }

    const client = await findOidcClient(db, tenant.id, clientId);
    if (!client) {
        await recordTokenFailure(clientId, "invalid_client", "등록되지 않은 client_id");
        return tokenError("invalid_client", "등록되지 않은 클라이언트입니다.", 401);
    }

    const secretCheck = await isValidClientSecret(client, clientSecret, !!authHeader);
    if (!secretCheck.valid) {
        await recordTokenFailure(clientId, "invalid_client", "client_secret 검증 실패");
        return tokenError("invalid_client", "클라이언트 인증에 실패했습니다.", 401);
    }
    // 레거시 형식(argon2/pbkdf2) 해시는 검증 성공 시 sha256 으로 업그레이드 (best-effort)
    if (secretCheck.rehash) {
        try {
            await db.update(oidcClients).set({ clientSecretHash: secretCheck.rehash, updatedAt: new Date() }).where(eq(oidcClients.id, client.id));
        } catch (error) {
            console.error("client_secret 해시 업그레이드 실패", { clientId }, error);
        }
    }

    // per-client 레이트 리밋: 인증 성공한 클라이언트당 60회/분.
    // IP 기반 리밋과 별개로, 자격증명을 아는 남용 클라이언트를 격리한다.
    const clientRl = await checkRateLimit(rateLimitStore, `token-client:${clientId}`, { windowMs: 60 * 1000, limit: 60 });
    if (!clientRl.allowed) {
        await recordTokenFailure(clientId, "rate_limit_exceeded", "client 요청이 너무 많습니다");
        return new Response(
            JSON.stringify({
                error: "rate_limit_exceeded",
                error_description: "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.",
            }),
            {
                status: 429,
                headers: {
                    "Content-Type": "application/json",
                    "Retry-After": String(Math.ceil(clientRl.retryAfterMs / 1000)),
                },
            },
        );
    }

    if (!clientAllowsGrant(client, grantType)) {
        await recordTokenFailure(clientId, "unauthorized_client", `클라이언트에 허용되지 않은 grant_type: ${grantType}`);
        return tokenError("unauthorized_client", "이 클라이언트에 허용되지 않은 grant_type 입니다.");
    }

    const signingKey = await getActiveSigningKey(db, tenant.id, signingKeySecrets);
    if (!signingKey) {
        return tokenError("server_error", "활성 서명 키를 찾을 수 없습니다.", 503);
    }

    // ── refresh_token grant ─────────────────────────────────────────────────────
    if (grantType === "refresh_token") {
        const presented = String(body.get("refresh_token") ?? "");
        if (!presented) {
            await recordTokenFailure(clientId, "invalid_request", "refresh_token 누락");
            return tokenError("invalid_request", "refresh_token 이 필요합니다.");
        }

        const rotation = await rotateRefreshToken(db, tenant.id, clientId, presented);
        if (!rotation.ok) {
            const desc = rotation.reason === "reuse" ? "refresh_token 재사용이 감지되어 관련 토큰을 모두 폐기했습니다." : "유효하지 않거나 만료된 refresh_token 입니다.";
            await recordTokenFailure(clientId, "invalid_grant", `${rotation.reason}`);
            return tokenError("invalid_grant", desc);
        }

        const record = rotation.record;

        // 연결된 IdP 세션이 명시적으로 폐기(로그아웃)됐으면 거부한다.
        // 세션의 자연 만료/정리는 거부하지 않는다 — offline_access refresh token 은
        // 브라우저 세션보다 오래 살아야 하기 때문. (로그아웃 시 refresh token 은 별도 폐기됨.)
        let sessionRow: typeof sessions.$inferSelect | null = null;
        if (record.sessionId) {
            const check = await checkGrantSession(db, record.sessionId);
            sessionRow = check.row;
            // 명시적 폐기(revoked)만 거부한다 — 세션의 자연 만료(expired)는 위 주석대로 거부하지 않는다.
            if (check.revoked) {
                // 방금 회전된 토큰을 포함해 family 를 폐기하고 거부.
                await revokeRefreshTokenFamily(db, tenant.id, record.userId, clientId);
                await recordTokenFailure(clientId, "invalid_grant", "연결된 세션이 로그아웃됨");
                return tokenError("invalid_grant", "로그아웃된 세션입니다. 다시 로그인해 주세요.");
            }
        }

        // scope 축소 요청 지원 (RFC 6749 §6): 요청 scope 는 원 scope 의 부분집합이어야 한다.
        const originalScopes = new Set(record.scope.split(" ").filter(Boolean));
        const requestedScopeRaw = String(body.get("scope") ?? "").trim();
        let effectiveScope = record.scope;
        if (requestedScopeRaw) {
            const requested = requestedScopeRaw.split(/\s+/).filter(Boolean);
            for (const s of requested) {
                if (!originalScopes.has(s)) {
                    await recordTokenFailure(clientId, "invalid_scope", `요청 scope 가 원 scope 를 벗어남: ${s}`);
                    return tokenError("invalid_scope", "요청한 scope 는 원 refresh_token 의 scope 를 벗어날 수 없습니다.");
                }
            }
            effectiveScope = requested.join(" ");
        }

        const user = await findActiveUserById(db, record.userId);
        if (!user) {
            await recordTokenFailure(clientId, "invalid_grant", "사용자 조회 실패");
            return tokenError("invalid_grant", "사용자를 찾을 수 없습니다.");
        }

        // ctrls M-3: 매 refresh 마다 서비스 접근 권한을 재확인한다(authorize 와 동일 게이트).
        // assignment 회수 시 refresh token 을 직접 폐기하지만(service.ts), 놓친 폐기 경로가
        // 있어도 access token TTL(5분) 안에 fail-closed 되도록 이중 방어한다. allowAllUsers
        // 클라이언트는 매핑 없이 전체 허용이므로 예외.
        if (!client.allowAllUsers) {
            const stillAllowed = await hasServiceAccess(db, {
                tenantId: tenant.id,
                userId: user.id,
                serviceType: "oidc",
                serviceRefId: client.id,
            });
            if (!stillAllowed) {
                await revokeRefreshTokenFamily(db, tenant.id, user.id, clientId);
                await recordTokenFailure(clientId, "invalid_grant", "서비스 접근 권한이 회수됨");
                return tokenError("invalid_grant", "서비스 접근 권한이 없습니다. 다시 로그인해 주세요.");
            }
        }

        const authTimeSec = sessionRow ? Math.floor(sessionRow.createdAt.getTime() / 1000) : Math.floor(record.createdAt.getTime() / 1000);
        const { idToken, accessToken } = await buildTokens({
            db,
            tenantId: tenant.id,
            issuer,
            signingKeySecret,
            signingKey,
            user,
            clientId,
            clientDbId: client.id,
            organizationClaimConfig: client.organizationClaimConfig,
            scope: effectiveScope,
            sessionId: record.sessionId,
            nonce: null, // refresh 로 재발급되는 id_token 에는 nonce 를 넣지 않는다 (원 요청 전용)
            acr: sessionRow?.acr ?? null,
            amr: sessionRow?.amr ?? null,
            authTimeSec,
        });

        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: user.id,
            actorId: user.id,
            spOrClientId: clientId,
            kind: "oidc_token",
            outcome: "success",
            ip,
            userAgent,
            detail: { clientId, scope: effectiveScope, grant: "refresh_token" },
        });

        return tokenResponse({
            access_token: accessToken,
            token_type: "Bearer",
            expires_in: ACCESS_TOKEN_TTL_S,
            scope: effectiveScope,
            id_token: idToken,
            refresh_token: rotation.newToken,
        });
    }

    // ── authorization_code grant ────────────────────────────────────────────────
    const code = String(body.get("code") ?? "");
    const redirectUri = String(body.get("redirect_uri") ?? "");
    const codeVerifier = String(body.get("code_verifier") ?? "");

    if (!code || !redirectUri) {
        await recordTokenFailure(clientId, "invalid_request", "code 또는 redirect_uri 누락");
        return tokenError("invalid_request", "code 와 redirect_uri 는 필수입니다.");
    }

    // 조회와 소진을 원자적으로 처리 (replay 방지)
    const grant = await findAndConsumeGrant(db, tenant.id, clientId, code);
    if (!grant) {
        await recordTokenFailure(clientId, "invalid_grant", "유효하지 않거나 만료된 code");
        return tokenError("invalid_grant", "유효하지 않거나 만료된 authorization code 입니다.");
    }

    if (grant.redirectUri !== redirectUri) {
        await recordTokenFailure(clientId, "invalid_grant", "redirect_uri mismatch");
        return tokenError("invalid_grant", "redirect_uri 가 일치하지 않습니다.");
    }

    // PKCE 검증
    if (grant.codeChallenge) {
        if (!codeVerifier) {
            await recordTokenFailure(clientId, "invalid_grant", "code_verifier 누락");
            return tokenError("invalid_grant", "code_verifier 가 필요합니다.");
        }
        const valid = await verifyPkce(grant.codeChallenge, grant.codeChallengeMethod ?? "plain", codeVerifier);
        if (!valid) {
            await recordTokenFailure(clientId, "invalid_grant", "code_verifier 검증 실패");
            return tokenError("invalid_grant", "code_verifier 검증에 실패했습니다.");
        }
    }

    // 연결된 IdP 세션이 로그아웃(폐기)됐거나 만료됐으면 거부한다.
    // 로그아웃 후에도 5분 TTL 안의 미소진 code 로 토큰이 발급되는 것을 막는다.
    // sessionId 가 null 인 grant(세션 삭제로 set null 된 경우 등)는 검사를 건너뛰어 기존 동작을 보존한다.
    let acSessionRow: typeof sessions.$inferSelect | null = null;
    if (grant.sessionId) {
        const sessionCheck = await checkGrantSession(db, grant.sessionId);
        acSessionRow = sessionCheck.row;
        if (sessionCheck.revoked || sessionCheck.expired) {
            await recordTokenFailure(clientId, "invalid_grant", sessionCheck.revoked ? "연결된 세션이 로그아웃됨" : "연결된 세션이 만료됨");
            return tokenError("invalid_grant", "로그아웃되었거나 만료된 세션입니다. 다시 로그인해 주세요.");
        }
    }

    const user = await findActiveUserById(db, grant.userId);
    if (!user) {
        await recordTokenFailure(clientId, "invalid_grant", "사용자 조회 실패");
        return tokenError("invalid_grant", "사용자를 찾을 수 없습니다.");
    }

    // ctrls LOW: auth_time 은 실제 인증(세션 생성) 시각이어야 한다. code 발급 시각(grant.createdAt)이
    // 아니라 세션의 createdAt 을 쓴다(refresh grant 와 정합). RP 의 max_age 검증 정확도 향상.
    const authTimeSec = acSessionRow ? Math.floor(acSessionRow.createdAt.getTime() / 1000) : Math.floor(grant.createdAt.getTime() / 1000);
    const { idToken, accessToken } = await buildTokens({
        db,
        tenantId: tenant.id,
        issuer,
        signingKeySecret,
        signingKey,
        user,
        clientId,
        clientDbId: client.id,
        organizationClaimConfig: client.organizationClaimConfig,
        scope: grant.scope,
        sessionId: grant.sessionId,
        nonce: grant.nonce,
        acr: grant.acr ?? null,
        amr: null,
        authTimeSec,
    });

    // offline_access scope + 클라이언트가 refresh_token grant 허용 시 refresh token 발급.
    const grantScopes = new Set(grant.scope.split(" ").filter(Boolean));
    let refreshToken: string | null = null;
    if (grantScopes.has("offline_access") && clientAllowsGrant(client, "refresh_token")) {
        refreshToken = await issueRefreshToken(db, {
            tenantId: tenant.id,
            clientId,
            userId: user.id,
            sessionId: grant.sessionId,
            scope: grant.scope,
        });
    }

    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId: user.id,
        actorId: user.id,
        spOrClientId: clientId,
        kind: "oidc_token",
        outcome: "success",
        ip,
        userAgent,
        detail: { clientId, scope: grant.scope, grant: "authorization_code", refresh: Boolean(refreshToken) },
    });

    const responseBody: Record<string, unknown> = {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_S,
        scope: grant.scope,
        id_token: idToken,
    };
    if (refreshToken) responseBody.refresh_token = refreshToken;

    return tokenResponse(responseBody);
};
