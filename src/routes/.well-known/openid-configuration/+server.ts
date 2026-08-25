import { json } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";

export const GET: RequestHandler = async ({ locals, url }) => {
    const issuer = resolveIssuerUrl(locals.runtimeConfig, url.origin, locals.tenant?.slug ?? undefined);

    return json(
        {
            issuer,
            authorization_endpoint: `${issuer}/oidc/authorize`,
            token_endpoint: `${issuer}/oidc/token`,
            userinfo_endpoint: `${issuer}/oidc/userinfo`,
            jwks_uri: `${issuer}/oidc/jwks`,
            end_session_endpoint: `${issuer}/oidc/end-session`,
            introspection_endpoint: `${issuer}/oidc/introspect`,
            revocation_endpoint: `${issuer}/oidc/revoke`,
            introspection_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
            revocation_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
            scopes_supported: ["openid", "profile", "email", "phone", "address", "organization", "groups", "offline_access"],
            response_types_supported: ["code"],
            grant_types_supported: ["authorization_code", "refresh_token"],
            subject_types_supported: ["public"],
            id_token_signing_alg_values_supported: ["RS256"],
            token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
            code_challenge_methods_supported: ["S256"],
            // 실제 token(+id_token)/userinfo 가 발급하는 클레임과 일치시킨다.
            claims_supported: [
                "sub",
                "iss",
                "aud",
                "azp",
                "exp",
                "iat",
                "auth_time",
                "jti",
                "nonce",
                "sid",
                "acr",
                "email",
                "email_verified",
                "name",
                "given_name",
                "family_name",
                "preferred_username",
                "picture",
                "locale",
                "zoneinfo",
                "birthdate",
                "updated_at",
                "phone_number",
                "phone_number_verified",
                "address",
                "department",
                "team",
                "position",
                "job_title",
                "groups",
                "roles",
                "roles_label",
                "entitlements",
            ],
            frontchannel_logout_supported: true,
            frontchannel_logout_session_supported: true,
            backchannel_logout_supported: true,
            backchannel_logout_session_supported: true,
        },
        {
            headers: {
                "Cache-Control": "public, max-age=3600",
            },
        },
    );
};
