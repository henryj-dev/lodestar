import { json } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { and, eq } from "drizzle-orm";
import { requireDbContext } from "$lib/server/auth/guards";
import { oidcClients, users } from "$lib/server/db/schema";
import { verifyAccessToken, tryWithSecretsNullable } from "$lib/server/crypto/keys";
import { getUserMembership, membershipToGroups } from "$lib/server/org/membership";
import { getActiveAssignment, listActiveEntitlements, parseAssignmentAttributes } from "$lib/server/access/service-permissions";
import { buildAddressClaim, buildOrganizationClaims, parseOrganizationClaimConfig } from "$lib/server/oidc/claims";
import { translate } from "$lib/i18n/server";

// `entitlements` 는 표준 클레임은 아니지만 인가 판정에 쓰이는 값이라 예약한다 —
// attributesJson(자유 입력)이 권한을 덮어쓸 수 있으면 권한 모델 자체가 무의미해진다.
const RESERVED_USERINFO_CLAIMS = new Set(["sub", "iss", "aud", "iat", "exp", "auth_time", "entitlements"]);

function bearerError(code: string, description: string): Response {
    return new Response(JSON.stringify({ error: code, error_description: description }), {
        status: 401,
        headers: {
            "Content-Type": "application/json",
            "WWW-Authenticate": `Bearer error="${code}", error_description="${description}"`,
        },
    });
}

async function handleUserinfo(locals: App.Locals, request: Request): Promise<Response> {
    const { db, tenant } = requireDbContext(locals);
    const { signingKeySecrets } = locals.runtimeConfig;

    if (signingKeySecrets.length === 0) {
        return new Response(translate(locals.locale, "oidc.errors.signing_key_not_set"), { status: 503 });
    }

    const authHeader = request.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
        return bearerError("invalid_token", translate(locals.locale, "oidc.errors.bearer_token_required"));
    }

    const token = authHeader.slice(7);
    const claims = await tryWithSecretsNullable(signingKeySecrets, (s) => verifyAccessToken(token, s, tenant.id));

    if (!claims) {
        return bearerError("invalid_token", translate(locals.locale, "oidc.errors.access_token_invalid"));
    }

    // ctrls H-OIDC-2: aud 강제. claims.aud (있을 경우) 가 claims.clientId 와 일치해야 한다.
    // 또한 발급 클라이언트가 현재도 등록되어 있고 enabled 인지 확인 — 비활성/삭제된
    // 클라이언트의 토큰은 더 이상 userinfo 접근 불가.
    if (claims.aud && claims.aud !== claims.clientId) {
        return bearerError("invalid_token", translate(locals.locale, "oidc.errors.token_aud_mismatch"));
    }
    const [issuingClient] = await db
        .select({ id: oidcClients.id, organizationClaimConfig: oidcClients.organizationClaimConfig })
        .from(oidcClients)
        .where(and(eq(oidcClients.tenantId, tenant.id), eq(oidcClients.clientId, claims.clientId), eq(oidcClients.enabled, true)))
        .limit(1);
    if (!issuingClient) {
        return bearerError("invalid_token", translate(locals.locale, "oidc.errors.issuing_client_invalid"));
    }

    const [user] = await db
        .select()
        .from(users)
        .where(and(eq(users.id, claims.sub), eq(users.tenantId, tenant.id), eq(users.status, "active")))
        .limit(1);

    if (!user) {
        return bearerError("invalid_token", translate(locals.locale, "oidc.errors.user_not_found"));
    }

    const scopes = new Set(claims.scope.split(" "));
    const response: Record<string, unknown> = { sub: user.id };

    if (scopes.has("email")) {
        response.email = user.email;
        response.email_verified = Boolean(user.emailVerifiedAt);
    }

    if (scopes.has("profile")) {
        response.name = user.displayName;
        response.given_name = user.givenName;
        response.family_name = user.familyName;
        response.preferred_username = user.username ?? user.email.split("@")[0];
        response.picture = user.avatarUrl;
        response.locale = user.locale;
        response.zoneinfo = user.zoneinfo;
        response.birthdate = user.birthdate;
        response.updated_at = user.updatedAt ? Math.floor(user.updatedAt.getTime() / 1000) : undefined;
    }

    if (scopes.has("phone")) {
        response.phone_number = user.phoneNumber;
        response.phone_number_verified = Boolean(user.phoneVerifiedAt);
    }

    if (scopes.has("address")) {
        const address = buildAddressClaim(user);
        if (address) response.address = address;
    }

    // 서비스 권한 매핑 — role / 추가 attributes 머지 (위에서 검증된 issuingClient 재사용)
    {
        const assignment = await getActiveAssignment(db, {
            tenantId: tenant.id,
            userId: user.id,
            serviceType: "oidc",
            serviceRefId: issuingClient.id,
        });
        if (assignment?.role) {
            response.roles = [assignment.role.key];
            response.roles_label = assignment.role.label;
        }
        if (assignment) {
            // entitlement 클레임 — id_token 과 **같은 값**이어야 한다(같은 함수를 쓴다).
            // 0개면 키를 아예 넣지 않는다. attributesJson 머지 앞에 두는 이유는 token/+server.ts 와 동일 —
            // 예약 목록이 유일한 방어가 되게 해서 테스트가 그것을 실제로 검증하게 한다.
            const entitlements = await listActiveEntitlements(db, assignment.id);
            if (entitlements.length > 0) response.entitlements = entitlements;

            const extra = parseAssignmentAttributes(assignment.attributesJson);
            for (const [k, v] of Object.entries(extra)) {
                if (RESERVED_USERINFO_CLAIMS.has(k)) continue;
                response[k] = v;
            }
        }
    }

    if (scopes.has("organization") || scopes.has("groups")) {
        const membership = await getUserMembership(db, user.id);

        if (scopes.has("groups")) {
            response.groups = membershipToGroups(membership);
        }

        if (scopes.has("organization")) {
            Object.assign(response, buildOrganizationClaims(membership, parseOrganizationClaimConfig(issuingClient.organizationClaimConfig)));
        }
    }

    return json(response, {
        headers: {
            "Cache-Control": "no-store, private",
            Pragma: "no-cache",
            Vary: "Authorization",
        },
    });
}

export const GET: RequestHandler = ({ locals, request }) => handleUserinfo(locals, request);
export const POST: RequestHandler = ({ locals, request }) => handleUserinfo(locals, request);
