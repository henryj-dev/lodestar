import { sql } from "drizzle-orm";
import { pgTable, text, integer, boolean, timestamp, index, uniqueIndex, foreignKey, type AnyPgColumn } from "drizzle-orm/pg-core";

// ---------- Tenancy ----------

export const tenants = pgTable(
    "tenants",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        slug: text("slug").notNull(),
        name: text("name").notNull(),
        status: text("status", { enum: ["active", "suspended"] })
            .notNull()
            .default("active"),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [uniqueIndex("tenants_slug_uidx").on(t.slug)],
);

// ---------- Directory ----------

export const users = pgTable(
    "users",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        username: text("username"),
        email: text("email").notNull(),
        emailVerifiedAt: timestamp("email_verified_at", { mode: "date", withTimezone: true, precision: 3 }),
        // F3: 이메일 변경 대기 상태. 새 주소 확인(email_change_tokens) 전까지 여기 보관하고,
        // 확인 완료 시 email 로 승격 후 NULL 로 클리어한다. requestedAt 은 대기 시작 시각.
        pendingEmail: text("pending_email"),
        pendingEmailRequestedAt: timestamp("pending_email_requested_at", { mode: "date", withTimezone: true, precision: 3 }),
        displayName: text("display_name"),
        role: text("role", { enum: ["admin", "user"] })
            .notNull()
            .default("user"),
        status: text("status", { enum: ["active", "disabled", "locked", "deletion_pending"] })
            .notNull()
            .default("active"),
        // 셀프서비스 계정 삭제(소프트 삭제) 예정 시각. status='deletion_pending' 일 때만 값이 있으며,
        // 이 시각이 지나면 GC 가 하드 삭제한다. 복구(로그인) 시 status='active' 환원 + 이 값 NULL.
        deletionScheduledAt: timestamp("deletion_scheduled_at", { mode: "date", withTimezone: true, precision: 3 }),
        // 프로필
        givenName: text("given_name"),
        familyName: text("family_name"),
        phoneNumber: text("phone_number"),
        phoneVerifiedAt: timestamp("phone_verified_at", { mode: "date", withTimezone: true, precision: 3 }),
        avatarUrl: text("avatar_url"),
        locale: text("locale").default("ko-KR"),
        zoneinfo: text("zoneinfo").default("Asia/Seoul"),
        bio: text("bio"),
        birthdate: text("birthdate"), // ISO 8601 날짜 문자열 (YYYY-MM-DD)
        // 주소 (OIDC address 클레임 구성요소). formatted 는 저장하지 않고 발급 시 조합.
        addressStreet: text("address_street"),
        addressLocality: text("address_locality"),
        addressRegion: text("address_region"),
        addressPostalCode: text("address_postal_code"),
        addressCountry: text("address_country"),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [
        uniqueIndex("users_tenant_email_uidx").on(t.tenantId, t.email),
        uniqueIndex("users_tenant_username_uidx").on(t.tenantId, t.username),
        index("users_tenant_idx").on(t.tenantId),
        // GC(하드삭제) 조회 지원 — status='deletion_pending' & deletionScheduledAt 경과분만 스캔한다.
        // 부분 인덱스(WHERE status='deletion_pending')로 삭제 예정 계정만 색인해 공간을 아낀다.
        // (mysql 은 부분 인덱스 미지원 → users_deletion_gc_idx 복합 인덱스로 대체; parity 예외 등재.)
        index("users_deletion_pending_idx")
            .on(t.deletionScheduledAt)
            .where(sql`${t.status} = 'deletion_pending'`),
    ],
);

/**
 * 인증 수단. 한 유저가 여러 credential 을 가질 수 있음 (password + TOTP + WebAuthn 복수).
 * - type='password': secret = scrypt hash(레거시 argon2id/pbkdf2 는 로그인 시 자동 업그레이드), publicKey=NULL (gitleaks:allow — 해시 형식 설명일 뿐 시크릿 아님)
 * - type='totp': secret = encrypted TOTP seed, publicKey=NULL
 * - type='webauthn': secret=NULL, publicKey = CBOR-encoded COSE key, credentialId 별도, counter
 * - type='backup_code': secret = hash of one-time code, usedAt 로 소진 관리
 */
export const credentials = pgTable(
    "credentials",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        type: text("type", { enum: ["password", "totp", "webauthn", "backup_code"] }).notNull(),
        label: text("label"),
        secret: text("secret"),
        publicKey: text("public_key"),
        credentialId: text("credential_id"),
        counter: integer("counter").notNull().default(0),
        transports: text("transports"),
        // 섀도 컬럼. TOTP 크레덴셜에만 userId 를 채워, 사용자당 TOTP 1개를 DB unique
        // index 로 강제(TOCTOU 동시 이중 등록 차단). webauthn/backup_code/password 행은
        // NULL 로 두면 unique 검사에서 제외되어 무영향(NULL 다중 허용).
        totpOwnerId: text("totp_owner_id"),
        lastUsedAt: timestamp("last_used_at", { mode: "date", withTimezone: true, precision: 3 }),
        usedAt: timestamp("used_at", { mode: "date", withTimezone: true, precision: 3 }),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [
        index("credentials_user_idx").on(t.userId),
        index("credentials_user_type_idx").on(t.userId, t.type),
        uniqueIndex("credentials_webauthn_credential_id_uidx").on(t.credentialId),
        uniqueIndex("credentials_totp_owner_uidx").on(t.totpOwnerId),
    ],
);

/**
 * 인증 소스. MVP 는 provider='local' 만 사용. federation 추가 시 google/github/saml:<entity> 등으로 확장.
 * (tenantId, provider, subject) 는 unique — 같은 외부 IdP 의 같은 subject 가 중복되지 않도록.
 */
export const identities = pgTable(
    "identities",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        provider: text("provider").notNull(),
        subject: text("subject").notNull(),
        email: text("email"),
        rawProfileJson: text("raw_profile_json"),
        linkedAt: timestamp("linked_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        lastLoginAt: timestamp("last_login_at", { mode: "date", withTimezone: true, precision: 3 }),
    },
    (t) => [uniqueIndex("identities_tenant_provider_subject_uidx").on(t.tenantId, t.provider, t.subject), index("identities_user_idx").on(t.userId)],
);

/**
 * 테넌트별 upstream IdP 설정. `kind='ldap'` 은 로그인 액션에서 인라인 bind 로 쓰이고,
 * `kind='oauth2'|'oidc'` 는 소셜 로그인(네이버/카카오/깃허브/Microsoft 등) 리다이렉트 플로우에 쓰인다.
 */
export const identityProviders = pgTable(
    "identity_providers",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        kind: text("kind", { enum: ["oidc", "saml", "oauth2", "ldap"] }).notNull(),
        name: text("name").notNull(),
        // 소셜 로그인 콜백 URL(/auth/oauth/{slug}/callback)에 쓰이는 안정적 식별자.
        // UUID(id)를 URL 에 쓰면 환경마다 Redirect URI 가 달라져 프로바이더 콘솔 등록이 깨진다.
        // LDAP 행은 콜백이 없으므로 NULL (NULL 다중 허용 → unique 검사에서 제외).
        slug: text("slug"),
        clientId: text("client_id"),
        clientSecretEnc: text("client_secret_enc"),
        discoveryUrl: text("discovery_url"),
        metadataXml: text("metadata_xml"),
        scopes: text("scopes"),
        configJson: text("config_json"),
        enabled: boolean("enabled").notNull().default(false),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("idp_tenant_idx").on(t.tenantId), uniqueIndex("idp_tenant_name_uidx").on(t.tenantId, t.name), uniqueIndex("idp_tenant_slug_uidx").on(t.tenantId, t.slug)],
);

// ---------- Session ----------

/**
 * IdP 자체 SSO 세션. 브라우저 쿠키가 가리키는 단일 세션이며,
 * 이 아래에 oidc_grants / saml_sessions 가 묶인다.
 */
export const sessions = pgTable(
    "sessions",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        /** IdP-level session id, SAML SessionIndex / OIDC sid 로도 사용 */
        idpSessionId: text("idp_session_id").notNull(),
        amr: text("amr"),
        acr: text("acr"),
        /**
         * 마지막 **인증 이벤트** 시각 — OIDC `auth_time` 클레임과 재인증 판정(max_age,
         * prompt=login 복귀 확인, SAML isPostReauth)의 기준. `createdAt` 과 분리한 이유:
         * MFA step-up 은 세션 행을 유지한 채 인증 수단만 승격하므로 "세션이 시작된 시각"과
         * "마지막으로 인증한 시각"이 갈라진다. createdAt 을 덮어쓰면 세션 목록의 시작 시각이
         * 승격 시점으로 밀려 사용자에게 거짓 정보가 표시된다.
         * NULL 인 구행(마이그레이션 이전 세션)은 읽는 쪽에서 `createdAt` 으로 폴백한다.
         */
        authTime: timestamp("auth_time", { mode: "date", withTimezone: true, precision: 3 }),
        ip: text("ip"),
        userAgent: text("user_agent"),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        lastSeenAt: timestamp("last_seen_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
        revokedAt: timestamp("revoked_at", { mode: "date", withTimezone: true, precision: 3 }),
    },
    (t) => [uniqueIndex("sessions_idp_session_id_uidx").on(t.idpSessionId), index("sessions_user_idx").on(t.userId), index("sessions_expires_idx").on(t.expiresAt)],
);

/**
 * 신뢰 기기("이 기기에서 다시 인증하지 않기"). 로그인 시 MFA 단계를 건너뛸 수 있는 기기를
 * 기록한다. 쿠키에는 랜덤 토큰 원본을, DB 에는 SHA-256 해시만 저장해 DB 유출만으로는
 * 기기를 위장할 수 없게 한다(sessions.idp_session_id 와 동일한 모델).
 *
 * `ip_bound` 는 사용자가 등록 시 선택하는 옵트인 옵션이다. true 면 저장된 ip 와 다른 곳에서의
 * 재사용을 거부한다(모바일 등 IP 가 자주 바뀌는 환경에서는 false 가 기본).
 */
export const trustedDevices = pgTable(
    "trusted_devices",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        /** 쿠키 토큰의 SHA-256 해시(base64url). 원본은 저장하지 않는다. */
        tokenHash: text("token_hash").notNull(),
        ip: text("ip"),
        userAgent: text("user_agent"),
        /** true 면 등록 시점 ip 와 다른 요청에서는 신뢰를 적용하지 않는다. */
        ipBound: boolean("ip_bound").notNull().default(false),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        lastUsedAt: timestamp("last_used_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
        revokedAt: timestamp("revoked_at", { mode: "date", withTimezone: true, precision: 3 }),
    },
    (t) => [uniqueIndex("trusted_devices_token_hash_uidx").on(t.tokenHash), index("trusted_devices_user_idx").on(t.userId), index("trusted_devices_expires_idx").on(t.expiresAt)],
);

// ---------- OIDC ----------

export const oidcClients = pgTable(
    "oidc_clients",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        clientId: text("client_id").notNull(),
        clientSecretHash: text("client_secret_hash"),
        name: text("name").notNull(),
        redirectUris: text("redirect_uris").notNull(),
        postLogoutRedirectUris: text("post_logout_redirect_uris"),
        frontchannelLogoutUri: text("frontchannel_logout_uri"),
        frontchannelLogoutSessionRequired: boolean("frontchannel_logout_session_required").notNull().default(false),
        backchannelLogoutUri: text("backchannel_logout_uri"),
        backchannelLogoutSessionRequired: boolean("backchannel_logout_session_required").notNull().default(false),
        // role 변경 시 서명된 Security Event Token(SET)을 POST 할 RP 엔드포인트.
        // null 이면 이 클라이언트는 role-change SET 을 받지 않는다 (back-channel logout 과 동일한 서명/봉투).
        roleChangeUri: text("role_change_uri"),
        scopes: text("scopes").notNull().default("openid"),
        grantTypes: text("grant_types").notNull().default("authorization_code,refresh_token"),
        responseTypes: text("response_types").notNull().default("code"),
        tokenEndpointAuthMethod: text("token_endpoint_auth_method", {
            enum: ["client_secret_basic", "client_secret_post", "none", "private_key_jwt"],
        })
            .notNull()
            .default("client_secret_basic"),
        requirePkce: boolean("require_pkce").notNull().default(true),
        // ctrls H-OIDC-4: wildcard redirect_uri 등록을 client 별 opt-in 으로.
        // 기본 false — 정확 일치 redirect_uri 만 허용. 와일드카드 패턴이 redirectUris 에
        // 등록돼 있어도 이 플래그가 true 가 아니면 매칭 자체를 거부.
        // subdomain takeover (dangling CNAME, 만료된 cloud subdomain) 위험 표면을 사전 차단.
        allowWildcardRedirectUri: boolean("allow_wildcard_redirect_uri").notNull().default(false),
        // ctrls R6: 이 클라이언트로 로그인할 때 이메일 인증(emailVerifiedAt)을 요구한다.
        // 기본 false — 미인증 계정도 로그인 가능(email_verified 클레임은 그대로 전파). true 면
        // /oidc/authorize 에서 미인증 사용자를 access_denied(email_verification_required)로 거부.
        requireVerifiedEmail: boolean("require_verified_email").notNull().default(false),
        /**
         * 이 클라이언트로 SSO 하려면 세션이 MFA 수준(ACR `refeds/mfa`)이어야 한다. 기본 false.
         *
         * RP 가 매번 `prompt=login` 을 보내는 것과 다르다 — `prompt=login` 은 세션이 이미 MFA 여도
         * 무조건 재인증을 요구하므로, 같은 패밀리 앱 사이를 오갈 때마다 인증 화면이 뜬다. 이 플래그는
         * **부족할 때만** 요구하므로 한 번 승격된 뒤의 재방문은 그대로 통과한다.
         */
        requireMfa: boolean("require_mfa").notNull().default(false),
        /**
         * 이미 인증된 세션에 재인증이 필요할 때 그것을 **무엇으로 충족시킬지**.
         *
         * - `full`(기본): `/login` 으로 보내 1차 인증(비밀번호 등)부터 다시 받는다.
         * - `mfa_only`: 세션을 유지한 채 `/mfa` 에서 OTP 만 받아 세션 ACR/AMR 을 승격한다.
         *
         * `mfa_only` 는 `prompt=login` · `max_age` 초과 · `requireMfa` 미충족에 적용된다.
         * `id_token_hint` 의 sub 불일치는 **계정 전환** 요구이므로 정책과 무관하게 항상 전체 로그인이다.
         *
         * 보안 트레이드오프: `mfa_only` 는 "비밀번호를 최근에 다시 제시했다"는 보증을 포기하고 세션에
         * 남은 1차 인증 증명을 재사용한다. OIDC `prompt=login` 의 재인증 의도를 완화하는 선택이므로,
         * 서로 신뢰하는 동일 패밀리 앱 사이에서만 켜는 것을 전제로 한 opt-in 이다.
         */
        reauthPolicy: text("reauth_policy", { enum: ["full", "mfa_only"] })
            .notNull()
            .default("full"),
        idTokenSignedResponseAlg: text("id_token_signed_response_alg").notNull().default("RS256"),
        jwksUri: text("jwks_uri"),
        jwks: text("jwks"),
        // organization scope 클레임의 클라이언트별 노출 토글(JSON). null=미설정=전량 노출(하위호환).
        // 예: {"department":true,"team":true,"position":false,"jobTitle":true}
        organizationClaimConfig: text("organization_claim_config"),
        // true 면 user_service_assignments 매핑 없이도 테넌트의 모든 사용자가 SSO 가능 (기본 deny 게이트 우회 opt-in).
        allowAllUsers: boolean("allow_all_users").notNull().default(false),
        enabled: boolean("enabled").notNull().default(true),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [uniqueIndex("oidc_clients_tenant_client_id_uidx").on(t.tenantId, t.clientId), index("oidc_clients_tenant_idx").on(t.tenantId)],
);

export const oidcGrants = pgTable(
    "oidc_grants",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        clientId: text("client_id").notNull(),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        sessionId: text("session_id").references(() => sessions.id, { onDelete: "set null" }),
        // ctrls C-6: authorization code 평문 저장 제거. 신규/기존 grant 모두 codeHash
        // (SHA-256) 만 저장한다. (legacy code 평문 컬럼은 본 PR 에서 drop 완료.)
        codeHash: text("code_hash"),
        codeChallenge: text("code_challenge"),
        codeChallengeMethod: text("code_challenge_method", { enum: ["S256", "plain"] }),
        redirectUri: text("redirect_uri").notNull(),
        scope: text("scope").notNull(),
        nonce: text("nonce"),
        state: text("state"),
        acr: text("acr"),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
        usedAt: timestamp("used_at", { mode: "date", withTimezone: true, precision: 3 }),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [
        // codeHash unique — grant 의 1회용 invariant. NULL 다중 허용 (legacy row).
        uniqueIndex("oidc_grants_code_hash_uidx").on(t.codeHash),
        index("oidc_grants_tenant_client_idx").on(t.tenantId, t.clientId),
        index("oidc_grants_expires_idx").on(t.expiresAt),
    ],
);

export const oidcRefreshTokens = pgTable(
    "oidc_refresh_tokens",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        clientId: text("client_id").notNull(),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        sessionId: text("session_id").references(() => sessions.id, { onDelete: "set null" }),
        tokenHash: text("token_hash").notNull(),
        scope: text("scope").notNull(),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
        revokedAt: timestamp("revoked_at", { mode: "date", withTimezone: true, precision: 3 }),
        replacedById: text("replaced_by_id"),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [uniqueIndex("oidc_refresh_tokens_hash_uidx").on(t.tokenHash), index("oidc_refresh_tokens_user_idx").on(t.userId)],
);

// ---------- SAML ----------

export const samlSps = pgTable(
    "saml_sps",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        entityId: text("entity_id").notNull(),
        name: text("name").notNull(),
        acsUrl: text("acs_url").notNull(),
        acsBinding: text("acs_binding").notNull().default("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
        sloUrl: text("slo_url"),
        sloBinding: text("slo_binding"),
        cert: text("cert"),
        nameIdFormat: text("name_id_format").notNull().default("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
        signAssertion: boolean("sign_assertion").notNull().default(true),
        signResponse: boolean("sign_response").notNull().default(true),
        encryptAssertion: boolean("encrypt_assertion").notNull().default(false),
        // ctrls R8: 신규 SP 는 서명된 AuthnRequest 를 요구하도록 기본 true(secure-by-default).
        wantAuthnRequestsSigned: boolean("want_authn_requests_signed").notNull().default(true),
        // ctrls R6: 이 SP 로 SSO 할 때 이메일 인증을 요구한다(기본 false). true 면 /saml/sso 에서
        // 미인증 사용자를 명확한 오류로 거부한다.
        requireVerifiedEmail: boolean("require_verified_email").notNull().default(false),
        /**
         * 이 SP 로 SSO 하려면 세션이 MFA 수준(ACR `refeds/mfa`)이어야 한다. 기본 false.
         * SP 가 `RequestedAuthnContext` 를 보내지 않아도 IdP 측에서 강제할 수 있게 한다.
         */
        requireMfa: boolean("require_mfa").notNull().default(false),
        /**
         * 이미 인증된 세션에 재인증이 필요할 때 그것을 무엇으로 충족시킬지.
         * `full`(기본) = `/login` 전체 재인증, `mfa_only` = 세션 유지 + `/mfa` OTP 승격.
         *
         * `mfa_only` 는 `RequestedAuthnContext` 미충족 · `requireMfa` 미충족 · `ForceAuthn` 에 적용된다.
         * `ForceAuthn` 에 대한 적용은 SAML Core 3.4.1.1 의 "기존 세션에 의존하지 말 것"을 완화하는
         * 선택이므로, SP 운영자가 명시적으로 켜는 opt-in 으로만 허용한다.
         */
        reauthPolicy: text("reauth_policy", { enum: ["full", "mfa_only"] })
            .notNull()
            .default("full"),
        attributeMappingJson: text("attribute_mapping_json"),
        // JSON 배열 문자열 (예: ["email","department"]). NULL 이면 기본 최소 집합만 허용.
        allowedAttributes: text("allowed_attributes"),
        // true 면 user_service_assignments 매핑 없이도 테넌트의 모든 사용자가 SSO 가능 (기본 deny 게이트 우회 opt-in).
        allowAllUsers: boolean("allow_all_users").notNull().default(false),
        enabled: boolean("enabled").notNull().default(true),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [uniqueIndex("saml_sps_tenant_entity_id_uidx").on(t.tenantId, t.entityId), index("saml_sps_tenant_idx").on(t.tenantId)],
);

export const samlSessions = pgTable(
    "saml_sessions",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        spId: text("sp_id")
            .notNull()
            .references(() => samlSps.id, { onDelete: "cascade" }),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        sessionId: text("session_id").references(() => sessions.id, { onDelete: "set null" }),
        sessionIndex: text("session_index").notNull(),
        nameId: text("name_id").notNull(),
        nameIdFormat: text("name_id_format"),
        notOnOrAfter: timestamp("not_on_or_after", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        endedAt: timestamp("ended_at", { mode: "date", withTimezone: true, precision: 3 }),
    },
    (t) => [uniqueIndex("saml_sessions_session_index_uidx").on(t.sessionIndex), index("saml_sessions_tenant_sp_idx").on(t.tenantId, t.spId)],
);

/**
 * SAML SLO 체인 상태. 여러 SP 를 순차적으로 로그아웃하기 위한 리다이렉트 체인을
 * DB 에 저장해 둔다. id 값이 RelayState 로 전달되어 체인 전반에 걸쳐 식별자 역할을 한다.
 */
export const samlSloStates = pgTable("saml_slo_states", {
    id: text("id")
        .primaryKey()
        .$defaultFn(() => crypto.randomUUID()),
    tenantId: text("tenant_id")
        .notNull()
        .references(() => tenants.id, { onDelete: "cascade" }),
    // sessions.id — FK 로 걸지 않는다 (체인 중간에 세션이 revoke 될 수 있음)
    idpSessionRecordId: text("idp_session_record_id").notNull(),
    userId: text("user_id")
        .notNull()
        .references(() => users.id, { onDelete: "cascade" }),
    // SP-initiated SLO 일 때만 값이 있다.
    initiatingSpEntityId: text("initiating_sp_entity_id"),
    // 최초 SP 가 보낸 LogoutRequest ID (InResponseTo 에 사용)
    inResponseTo: text("in_response_to"),
    // 체인 종료 시 LogoutResponse 를 보낼 SP 의 SLO URL (SP-initiated)
    initiatorSloUrl: text("initiator_slo_url"),
    // 체인 종료 시 최종적으로 리다이렉트할 URI (예: "/login")
    completionUri: text("completion_uri").notNull(),
    // JSON array: [{spId, entityId, sloUrl, nameId, nameIdFormat, sessionIndex}]
    pendingSpDataJson: text("pending_sp_data_json").notNull(),
    createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
});

// ---------- Service Permissions ----------

/**
 * 서비스(OIDC client / SAML SP) 별 role 정의.
 * serviceRefId 는 oidcClients.id 또는 samlSps.id 를 가리키지만 두 테이블 중 하나라
 * FK 는 걸지 않는다. 삭제 시 별도 application-level cleanup 필요.
 */
export const serviceRoles = pgTable(
    "service_roles",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        serviceType: text("service_type", { enum: ["oidc", "saml"] }).notNull(),
        serviceRefId: text("service_ref_id").notNull(),
        key: text("key").notNull(),
        label: text("label").notNull(),
        description: text("description"),
        isDefault: boolean("is_default").notNull().default(false),
        displayOrder: integer("display_order").notNull().default(0),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [uniqueIndex("service_roles_service_key_uidx").on(t.serviceType, t.serviceRefId, t.key), index("service_roles_tenant_service_idx").on(t.tenantId, t.serviceType, t.serviceRefId)],
);

/**
 * 사용자에게 부여된 서비스 접근 권한.
 * 기본 deny. 매핑이 없으면 SSO 거부. role 은 nullable — 단순 access 만 부여하는 경우 허용.
 * attributesJson 은 SSO 시 추가로 머지될 클레임/속성을 표현한다.
 */
export const userServiceAssignments = pgTable(
    "user_service_assignments",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        serviceType: text("service_type", { enum: ["oidc", "saml"] }).notNull(),
        serviceRefId: text("service_ref_id").notNull(),
        serviceRoleId: text("service_role_id").references(() => serviceRoles.id, { onDelete: "set null" }),
        attributesJson: text("attributes_json"),
        grantedBy: text("granted_by"),
        grantedAt: timestamp("granted_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [
        uniqueIndex("user_service_assignments_user_service_uidx").on(t.tenantId, t.userId, t.serviceType, t.serviceRefId),
        index("user_service_assignments_tenant_user_idx").on(t.tenantId, t.userId),
        index("user_service_assignments_tenant_service_idx").on(t.tenantId, t.serviceType, t.serviceRefId),
    ],
);

/**
 * 서비스가 정의하는 권한(entitlement) 키. `groups`(조직 소속)·`roles`(단일 역할)와 직교하는 세 번째 축.
 * `serviceRoles` 를 본떴으나 두 가지가 다르다:
 *   - `isDefault` 없음 — 권한의 기본 부여는 "누가 줬는가" 에 답이 없는 권한을 만든다. 전부 명시 부여.
 *   - `displayOrder` 가 장식이 아니다 — 권한 간 의존(B 를 켜려면 A 도 필요)은 RP 의 의미론이라
 *     모델에 넣지 않는 대신, 관리 UI 가 이 순서로 체크박스를 세워 관리자에게 안내한다.
 * serviceRefId 는 oidcClients.id 또는 samlSps.id 를 가리키지만 FK 는 걸지 않는다(serviceRoles 와 동일).
 */
export const serviceEntitlements = pgTable(
    "service_entitlements",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        serviceType: text("service_type", { enum: ["oidc", "saml"] }).notNull(),
        serviceRefId: text("service_ref_id").notNull(),
        key: text("key").notNull(),
        label: text("label").notNull(),
        description: text("description"),
        displayOrder: integer("display_order").notNull().default(0),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [
        uniqueIndex("service_entitlements_service_key_uidx").on(t.serviceType, t.serviceRefId, t.key),
        index("service_entitlements_tenant_service_idx").on(t.tenantId, t.serviceType, t.serviceRefId),
    ],
);

/**
 * 사용자에게 부여된 서비스 권한(다대다). 역할(`roles`)과 직교한다.
 *
 * userId/serviceType/serviceRefId 대신 **assignmentId 를 FK 로** 거는 이유:
 *   - 접근 배정 없이 권한만 가진 상태가 표현 불가능해진다(기본 deny 를 구조로 강제).
 *   - 배정 회수는 하드 삭제이므로(`revokeAssignment()`) 권한이 그대로 cascade 된다 — 회수 경로에 코드 추가 불필요.
 *   - 배정의 expiresAt/revokedAt 필터가 `getActiveAssignment()` 에 이미 있어, 배정이 죽으면 권한 조회가 시작되지 않는다.
 * 대가: 접근을 회수했다가 재부여하면 이전 권한은 복구되지 않는다(새 배정 행 = 새 id). 접근 재부여가
 * 이전 권한을 조용히 되살리는 것보다 안전하다고 보고 수용한다 — 관리 UI 가 이 점을 명시한다.
 *
 * **revokedAt 을 두지 않는다.** userServiceAssignments 의 같은 컬럼은 읽히기만 하고 쓰는 곳이 없는
 * 죽은 컬럼이다(회수 = 하드 삭제). 같은 것을 복제하지 않고, 회수 이력은 감사 이벤트에 남긴다.
 */
export const userServiceEntitlements = pgTable(
    "user_service_entitlements",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        assignmentId: text("assignment_id").notNull(),
        serviceEntitlementId: text("service_entitlement_id").notNull(),
        grantedBy: text("granted_by"),
        grantedAt: timestamp("granted_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [
        // 이 두 FK 만 `.references()` 대신 명시 이름을 준다. drizzle 자동 이름
        // (`<table>_<col>_<ftable>_<fcol>_fk`)이 두 긴 테이블명을 이어 붙여 70·75자가 되는데,
        // **PostgreSQL 은 63자에서 조용히 잘라내지만 MySQL 은 64자 초과를 에러로 거부**한다
        // (ER_TOO_LONG_IDENT). 방언 간 적용 가능성이 갈리므로 이름을 직접 고정한다.
        foreignKey({ columns: [t.assignmentId], foreignColumns: [userServiceAssignments.id], name: "user_service_entitlements_assignment_fk" }).onDelete("cascade"),
        foreignKey({ columns: [t.serviceEntitlementId], foreignColumns: [serviceEntitlements.id], name: "user_service_entitlements_entitlement_fk" }).onDelete("cascade"),
        uniqueIndex("user_service_entitlements_assignment_ent_uidx").on(t.assignmentId, t.serviceEntitlementId),
        index("user_service_entitlements_tenant_ent_idx").on(t.tenantId, t.serviceEntitlementId),
    ],
);

// ---------- Keys & Audit ----------

/**
 * 서명 키. 테넌트별 독립. kid 로 선택하며, rotation 시 active 는 한 번에 하나,
 * 구 키는 `rotatedAt` 이 설정된 채로 검증용으로 남는다.
 */
export const signingKeys = pgTable(
    "signing_keys",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        kid: text("kid").notNull(),
        use: text("use", { enum: ["sig", "enc"] })
            .notNull()
            .default("sig"),
        alg: text("alg").notNull(),
        publicJwk: text("public_jwk").notNull(),
        privateJwkEncrypted: text("private_jwk_encrypted").notNull(),
        certPem: text("cert_pem"),
        active: boolean("active").notNull().default(true),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        rotatedAt: timestamp("rotated_at", { mode: "date", withTimezone: true, precision: 3 }),
        notAfter: timestamp("not_after", { mode: "date", withTimezone: true, precision: 3 }),
    },
    (t) => [
        uniqueIndex("signing_keys_tenant_kid_uidx").on(t.tenantId, t.kid),
        index("signing_keys_tenant_active_idx").on(t.tenantId, t.active),
        // ctrls H-ADMIN-5: tenant 당 active=true 인 signing key 는 최대 1개. partial
        // unique index 로 DB 레벨에서 race 차단 (두 admin 이 동시에 rotate 해도 두 번째
        // INSERT 가 UNIQUE 위반으로 실패하고 rotation 시도 자체가 안전하게 거부됨).
        uniqueIndex("signing_keys_tenant_one_active_uidx")
            .on(t.tenantId)
            .where(sql`${t.active}`),
    ],
);

export const auditEvents = pgTable(
    "audit_events",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: text("user_id").references(() => users.id, { onDelete: "set null" }),
        actorId: text("actor_id"),
        spOrClientId: text("sp_or_client_id"),
        kind: text("kind").notNull(),
        outcome: text("outcome", { enum: ["success", "failure"] }).notNull(),
        ip: text("ip"),
        userAgent: text("user_agent"),
        detailJson: text("detail_json"),
        // ctrls H-ADMIN-2: 행 단위 무결성 HMAC. IDP_SIGNING_KEY_SECRET 파생 키로 계산되어
        // DB write 권한만으로는 필드 변조/위조 불가(삭제 탐지는 Logpush 미러 권장).
        hash: text("hash"),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("audit_events_tenant_kind_idx").on(t.tenantId, t.kind), index("audit_events_tenant_created_idx").on(t.tenantId, t.createdAt), index("audit_events_user_idx").on(t.userId)],
);

// ---------- Organization ----------

/**
 * 직급 마스터. 테넌트별 독립 관리.
 * 예: 사원(10) → 대리(20) → 과장(30) → 차장(40) → 부장(50) → 이사(60)
 */
export const positions = pgTable(
    "positions",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        name: text("name").notNull(),
        code: text("code"),
        level: integer("level").notNull().default(0), // 높을수록 고위직
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("positions_tenant_idx").on(t.tenantId), uniqueIndex("positions_tenant_code_uidx").on(t.tenantId, t.code)],
);

/**
 * 부서. parentId 로 계층 구조(트리) 표현.
 * 최상위 부서는 parentId=NULL.
 */
export const departments = pgTable(
    "departments",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        parentId: text("parent_id").references((): AnyPgColumn => departments.id, {
            onDelete: "set null",
        }),
        name: text("name").notNull(),
        code: text("code"),
        description: text("description"),
        managerId: text("manager_id").references(() => users.id, { onDelete: "set null" }),
        displayOrder: integer("display_order").notNull().default(0),
        status: text("status", { enum: ["active", "inactive"] })
            .notNull()
            .default("active"),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("departments_tenant_idx").on(t.tenantId), index("departments_parent_idx").on(t.parentId), uniqueIndex("departments_tenant_code_uidx").on(t.tenantId, t.code)],
);

/**
 * 팀. 부서 하위에 속하거나(departmentId 있음), 독립적으로 존재 가능.
 */
export const teams = pgTable(
    "teams",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        departmentId: text("department_id").references(() => departments.id, {
            onDelete: "set null",
        }),
        name: text("name").notNull(),
        code: text("code"),
        description: text("description"),
        leaderId: text("leader_id").references(() => users.id, { onDelete: "set null" }),
        status: text("status", { enum: ["active", "inactive"] })
            .notNull()
            .default("active"),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("teams_tenant_idx").on(t.tenantId), index("teams_department_idx").on(t.departmentId), uniqueIndex("teams_tenant_code_uidx").on(t.tenantId, t.code)],
);

/**
 * 유저↔부서 소속 (N:M). 겸직·복수 소속 지원.
 * isPrimary=true 인 행이 주소속 부서.
 * endedAt=NULL 이면 현재 소속.
 */
export const userDepartments = pgTable(
    "user_departments",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        departmentId: text("department_id")
            .notNull()
            .references(() => departments.id, { onDelete: "cascade" }),
        positionId: text("position_id").references(() => positions.id, { onDelete: "set null" }),
        jobTitle: text("job_title"), // 직책 (팀장, 파트장, 실장 …)
        isPrimary: boolean("is_primary").notNull().default(false),
        startedAt: timestamp("started_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        endedAt: timestamp("ended_at", { mode: "date", withTimezone: true, precision: 3 }),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("user_departments_user_idx").on(t.userId), index("user_departments_dept_idx").on(t.departmentId), index("user_departments_tenant_idx").on(t.tenantId)],
);

/**
 * 파트. 팀 하위 단위. teamId(nullable)로 팀 소속 또는 독립 구성.
 */
export const parts = pgTable(
    "parts",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        teamId: text("team_id").references(() => teams.id, { onDelete: "set null" }),
        name: text("name").notNull(),
        code: text("code"),
        description: text("description"),
        leaderId: text("leader_id").references(() => users.id, { onDelete: "set null" }),
        status: text("status", { enum: ["active", "inactive"] })
            .notNull()
            .default("active"),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        updatedAt: timestamp("updated_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("parts_tenant_idx").on(t.tenantId), index("parts_team_idx").on(t.teamId), uniqueIndex("parts_tenant_code_uidx").on(t.tenantId, t.code)],
);

/**
 * 유저↔파트 소속 (N:M).
 */
export const userParts = pgTable(
    "user_parts",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        partId: text("part_id")
            .notNull()
            .references(() => parts.id, { onDelete: "cascade" }),
        jobTitle: text("job_title"),
        isPrimary: boolean("is_primary").notNull().default(false),
        startedAt: timestamp("started_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        endedAt: timestamp("ended_at", { mode: "date", withTimezone: true, precision: 3 }),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("user_parts_user_idx").on(t.userId), index("user_parts_part_idx").on(t.partId), index("user_parts_tenant_idx").on(t.tenantId)],
);

/**
 * 유저↔팀 소속 (N:M). 복수 팀 동시 소속 지원.
 * isPrimary=true 인 행이 주소속 팀.
 * endedAt=NULL 이면 현재 소속.
 */
export const userTeams = pgTable(
    "user_teams",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        teamId: text("team_id")
            .notNull()
            .references(() => teams.id, { onDelete: "cascade" }),
        jobTitle: text("job_title"), // 팀 내 역할 (팀장, 멤버 …)
        isPrimary: boolean("is_primary").notNull().default(false),
        startedAt: timestamp("started_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        endedAt: timestamp("ended_at", { mode: "date", withTimezone: true, precision: 3 }),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("user_teams_user_idx").on(t.userId), index("user_teams_team_idx").on(t.teamId), index("user_teams_tenant_idx").on(t.tenantId)],
);

// ---------- SAML AuthnRequest ID replay cache ----------

/**
 * SAML AuthnRequest ID 1회용 캐시. parseAuthnRequest 통과 후 INSERT;
 * 동일 ID 가 이미 존재하면 replay 로 간주하고 거부한다. expiresAt 이 지난 행은
 * cleanup job 또는 DELETE WHERE expiresAt < now() 로 정리.
 */
export const samlAuthnRequestIds = pgTable(
    "saml_authn_request_ids",
    {
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        // 외부에서 들어온 SAML AuthnRequest ID 값 그대로 저장.
        requestId: text("request_id").notNull(),
        // SP entityId (디버깅/감사용)
        spEntityId: text("sp_entity_id").notNull(),
        seenAt: timestamp("seen_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
    },
    (t) => [uniqueIndex("saml_authn_request_ids_tenant_req_uidx").on(t.tenantId, t.requestId), index("saml_authn_request_ids_expires_idx").on(t.expiresAt)],
);

// ---------- WebAuthn Challenges ----------

/**
 * WebAuthn 1회용 챌린지. options 응답 시 INSERT, verify 시 atomic UPDATE 로 usedAt 마킹.
 * 만료/재사용 챌린지는 거부된다.
 */
export const webauthnChallenges = pgTable(
    "webauthn_challenges",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        // 마이그레이션 호환을 위해 nullable. 신규 row 는 항상 not null 로 INSERT 되며,
        // 조회/소진 시 tenantId 일치를 강제해 (다른 테넌트 challenge 매칭 차단) NULL 인
        // 레거시 row 는 어떤 쿼리에도 잡히지 않는다 (5분 TTL 후 purge).
        tenantId: text("tenant_id").references(() => tenants.id, { onDelete: "cascade" }),
        userId: text("user_id").references(() => users.id, { onDelete: "cascade" }),
        challenge: text("challenge").notNull(),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
        usedAt: timestamp("used_at", { mode: "date", withTimezone: true, precision: 3 }),
    },
    (t) => [uniqueIndex("webauthn_challenges_tenant_challenge_uidx").on(t.tenantId, t.challenge), index("webauthn_challenges_tenant_expires_idx").on(t.tenantId, t.expiresAt)],
);

// ---------- Types ----------

export type Tenant = typeof tenants.$inferSelect;
// ---------- Rate Limits ----------

export const rateLimits = pgTable("rate_limits", {
    key: text("key").primaryKey(),
    count: integer("count").notNull().default(1),
    expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
});

export const clientSkins = pgTable(
    "client_skins",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        clientType: text("client_type", { enum: ["oidc", "saml", "tenant"] }).notNull(),
        clientRefId: text("client_ref_id").notNull(),
        skinType: text("skin_type", { enum: ["login", "signup", "find_id", "find_password", "mfa", "reset_password", "verify_email", "accept_invite", "confirm_email_change", "logout"] })
            .notNull()
            .default("login"),
        fetchUrl: text("fetch_url").notNull(),
        fetchSecret: text("fetch_secret"),
        cacheTtlSeconds: integer("cache_ttl_seconds").notNull().default(3600),
        enabled: boolean("enabled").notNull().default(true),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 })
            .notNull()
            .$defaultFn(() => new Date()),
    },
    (t) => [uniqueIndex("client_skins_unique").on(t.tenantId, t.clientType, t.clientRefId, t.skinType)],
);

// ---------- Password Reset ----------

export const passwordResetTokens = pgTable(
    "password_reset_tokens",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        tokenHash: text("token_hash").notNull(),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
        usedAt: timestamp("used_at", { mode: "date", withTimezone: true, precision: 3 }),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("password_reset_tokens_user_idx").on(t.userId), uniqueIndex("password_reset_tokens_hash_uidx").on(t.tokenHash)],
);

export type PasswordResetToken = typeof passwordResetTokens.$inferSelect;

// ---------- Email Verification ----------
// password_reset_tokens 와 동일 패턴(SHA-256 해시 저장, TTL, 1회용). TTL 24시간.

export const emailVerificationTokens = pgTable(
    "email_verification_tokens",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        tokenHash: text("token_hash").notNull(),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
        usedAt: timestamp("used_at", { mode: "date", withTimezone: true, precision: 3 }),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("email_verification_tokens_user_idx").on(t.userId), uniqueIndex("email_verification_tokens_hash_uidx").on(t.tokenHash)],
);

export type EmailVerificationToken = typeof emailVerificationTokens.$inferSelect;

// ---------- Invite ----------
// email_verification_tokens 와 동일 패턴(SHA-256 해시 저장, TTL, 1회용). TTL 72시간.
// 초대는 관리자가 비밀번호 없이 계정을 선생성하고, 이 토큰 링크로 최초 비밀번호를 설정한다.

export const inviteTokens = pgTable(
    "invite_tokens",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        tokenHash: text("token_hash").notNull(),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
        usedAt: timestamp("used_at", { mode: "date", withTimezone: true, precision: 3 }),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("invite_tokens_user_idx").on(t.userId), uniqueIndex("invite_tokens_hash_uidx").on(t.tokenHash)],
);

export type InviteToken = typeof inviteTokens.$inferSelect;

// ---------- Email change ----------
// F3: 프로필 이메일 변경 확인 토큰. email_verification_tokens 와 분리한다 — 변경 대상 주소
// (targetEmail)를 토큰에 바인딩해야 하고(확인 링크가 다른 주소로 재사용되지 않도록), 확인
// 라우트/시맨틱도 다르기 때문이다. SHA-256 해시 저장, TTL 24시간, 1회용(usedAt).
export const emailChangeTokens = pgTable(
    "email_change_tokens",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        userId: text("user_id")
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        tokenHash: text("token_hash").notNull(),
        // 변경하려는 새 이메일 주소(토큰에 바인딩). 확인 시 이 값으로 users.email 을 교체한다.
        targetEmail: text("target_email").notNull(),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }).notNull(),
        usedAt: timestamp("used_at", { mode: "date", withTimezone: true, precision: 3 }),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [index("email_change_tokens_user_idx").on(t.userId), uniqueIndex("email_change_tokens_hash_uidx").on(t.tokenHash)],
);

export type EmailChangeToken = typeof emailChangeTokens.$inferSelect;

export type User = typeof users.$inferSelect;
export type Credential = typeof credentials.$inferSelect;
export type Identity = typeof identities.$inferSelect;
export type IdentityProvider = typeof identityProviders.$inferSelect;
export type Session = typeof sessions.$inferSelect;
export type TrustedDevice = typeof trustedDevices.$inferSelect;
export type OidcClient = typeof oidcClients.$inferSelect;
export type OidcGrant = typeof oidcGrants.$inferSelect;
export type OidcRefreshToken = typeof oidcRefreshTokens.$inferSelect;
export type SamlSp = typeof samlSps.$inferSelect;
export type SamlSession = typeof samlSessions.$inferSelect;
export type SamlSloState = typeof samlSloStates.$inferSelect;
export type SigningKey = typeof signingKeys.$inferSelect;
export type AuditEvent = typeof auditEvents.$inferSelect;
export type Position = typeof positions.$inferSelect;
export type Department = typeof departments.$inferSelect;
export type Team = typeof teams.$inferSelect;
export type UserDepartment = typeof userDepartments.$inferSelect;
export type UserTeam = typeof userTeams.$inferSelect;
export type Part = typeof parts.$inferSelect;
export type UserPart = typeof userParts.$inferSelect;
export type WebauthnChallenge = typeof webauthnChallenges.$inferSelect;
export type ClientSkin = typeof clientSkins.$inferSelect;
/**
 * IdP 세션 ↔ OIDC 클라이언트 연결 기록.
 *
 * back-channel / front-channel logout 의 **세션 단위** 타깃을 찾기 위한 것이다. 예전에는
 * `oidcGrants` 와 `oidcRefreshTokens` 로 대상을 역추적했는데 둘 다 오래 살지 않는다:
 *   - oidcGrants 는 authorization code(수 분 TTL)이고 만료되면 GC 가 삭제한다.
 *   - oidcRefreshTokens 는 `offline_access` scope 가 있어야 발급된다.
 * 그래서 **offline_access 를 쓰지 않고 자체 세션을 오래 유지하는 RP 는 로그인 몇 분 뒤부터
 * 로그아웃 통지를 받지 못했다** — 사용자가 로그아웃해도 그 RP 세션은 그대로 남았다.
 *
 * 이 테이블은 토큰을 실제로 발급한 시점에 한 번 쓰고 세션이 사라질 때까지 남는다.
 * clientId 는 공개 client_id 문자열(oidcGrants.clientId 와 같은 값)이라 조회가 그대로 호환된다.
 */
export const oidcClientSessions = pgTable(
    "oidc_client_sessions",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        sessionId: text("session_id")
            .notNull()
            .references(() => sessions.id, { onDelete: "cascade" }),
        clientId: text("client_id").notNull(),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
    },
    (t) => [uniqueIndex("oidc_client_sessions_session_client_uidx").on(t.sessionId, t.clientId), index("oidc_client_sessions_tenant_session_idx").on(t.tenantId, t.sessionId)],
);

/**
 * 서비스 API 토큰 — `/api/totp/*` · `/api/users/lookup` 같은 service-to-service 호출용.
 *
 * 예전에는 `DISPATCHER_SERVICE_TOKEN`(env) **단일 공유 시크릿** 하나로 다섯 엔드포인트가 전부
 * 열렸다. 호출자를 구분할 수 없고, 회전하면 그것을 쓰는 모든 서비스가 동시에 끊기며,
 * `/api/totp/verify` 하나만 필요한 호출자도 등록·조회 권한까지 받았다.
 *
 * 검증 방향이 client_secret 과 반대다 — client_secret 은 clientId 로 "누구인지" 를 먼저 알고
 * 그 행의 해시와 비교하지만, 서비스 토큰은 Bearer 하나로 오고 식별자가 없다. 그래서
 * **받은 토큰을 해싱해 tokenHash 로 행을 찾는다**(unique 인덱스가 조회 키다).
 *
 * 해시는 SHA-256 으로 충분하다. 토큰이 256비트 난수라 사전 공격 대상이 아니다 —
 * 느린 해시(scrypt)는 비밀번호용이고, 이 저장소가 client_secret 에 이미 같은 판단을 했다.
 *
 * **revokedAt 을 두지 않는다.** 폐기는 행 삭제 + 감사 이벤트다(revokeAssignment 와 같은 방식).
 * 쓰는 코드가 없는 소프트 회수 컬럼은 "안전 검사처럼 보이는 죽은 코드" 가 된다.
 * expiresAt / lastUsedAt 은 각각 발급 폼과 검증 경로가 **실제로 쓴다**.
 */
export const serviceApiTokens = pgTable(
    "service_api_tokens",
    {
        id: text("id")
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: text("tenant_id")
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        /** 사람이 읽는 호출자 이름 — 감사에서 "누가 불렀는가" 의 답이 된다. */
        name: text("name").notNull(),
        tokenHash: text("token_hash").notNull(),
        /** 평문 앞 8자. 목록에서 어느 토큰인지 구분하는 표시용(비밀이 아니다). */
        tokenPrefix: text("token_prefix").notNull(),
        /** 공백 구분 — oidcClients.scopes 와 같은 저장 방식. */
        scopes: text("scopes").notNull(),
        createdBy: text("created_by"),
        createdAt: timestamp("created_at", { mode: "date", withTimezone: true, precision: 3 }).notNull().defaultNow(),
        expiresAt: timestamp("expires_at", { mode: "date", withTimezone: true, precision: 3 }),
        lastUsedAt: timestamp("last_used_at", { mode: "date", withTimezone: true, precision: 3 }),
    },
    (t) => [uniqueIndex("service_api_tokens_token_hash_uidx").on(t.tokenHash), index("service_api_tokens_tenant_idx").on(t.tenantId)],
);

export type OidcClientSession = typeof oidcClientSessions.$inferSelect;
export type ServiceApiToken = typeof serviceApiTokens.$inferSelect;
export type ServiceRole = typeof serviceRoles.$inferSelect;
export type UserServiceAssignment = typeof userServiceAssignments.$inferSelect;
export type ServiceEntitlement = typeof serviceEntitlements.$inferSelect;
export type UserServiceEntitlement = typeof userServiceEntitlements.$inferSelect;
