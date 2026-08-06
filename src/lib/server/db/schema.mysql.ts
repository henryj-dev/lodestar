import { sql } from "drizzle-orm";
import { mysqlTable, varchar, text, int, boolean, datetime, index, uniqueIndex, foreignKey, type AnyMySqlColumn } from "drizzle-orm/mysql-core";

// ---------- Tenancy ----------

export const tenants = mysqlTable(
    "tenants",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        slug: varchar("slug", { length: 255 }).notNull(),
        name: text("name").notNull(),
        status: varchar("status", { length: 64, enum: ["active", "suspended"] })
            .notNull()
            .default("active"),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        updatedAt: datetime("updated_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [uniqueIndex("tenants_slug_uidx").on(t.slug)],
);

// ---------- Directory ----------

export const users = mysqlTable(
    "users",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        username: varchar("username", { length: 255 }),
        email: varchar("email", { length: 320 }).notNull(),
        emailVerifiedAt: datetime("email_verified_at", { mode: "date", fsp: 3 }),
        // F3: 이메일 변경 대기 상태. 새 주소 확인(email_change_tokens) 전까지 여기 보관하고,
        // 확인 완료 시 email 로 승격 후 NULL 로 클리어한다. requestedAt 은 대기 시작 시각.
        // (email 과 동일 계열 타입 유지를 위해 varchar(320) — parity 는 string 계열로 정규화됨.)
        pendingEmail: varchar("pending_email", { length: 320 }),
        pendingEmailRequestedAt: datetime("pending_email_requested_at", { mode: "date", fsp: 3 }),
        displayName: text("display_name"),
        role: varchar("role", { length: 64, enum: ["admin", "user"] })
            .notNull()
            .default("user"),
        status: varchar("status", { length: 64, enum: ["active", "disabled", "locked", "deletion_pending"] })
            .notNull()
            .default("active"),
        // 셀프서비스 계정 삭제(소프트 삭제) 예정 시각. status='deletion_pending' 일 때만 값이 있으며,
        // 이 시각이 지나면 GC 가 하드 삭제한다. 복구(로그인) 시 status='active' 환원 + 이 값 NULL.
        deletionScheduledAt: datetime("deletion_scheduled_at", { mode: "date", fsp: 3 }),
        // 프로필
        givenName: text("given_name"),
        familyName: text("family_name"),
        phoneNumber: text("phone_number"),
        phoneVerifiedAt: datetime("phone_verified_at", { mode: "date", fsp: 3 }),
        avatarUrl: text("avatar_url"),
        locale: text("locale").default("ko-KR"),
        zoneinfo: text("zoneinfo").default("Asia/Seoul"),
        bio: text("bio"),
        birthdate: text("birthdate"), // ISO 8601 날짜 문자열 (YYYY-MM-DD)
        // 주소 (OIDC address 클레임 구성요소). formatted 는 저장하지 않고 발급 시 조합.
        // text 로 충분 — unique index 를 걸지 않으므로 키 길이 제약 무관. 3방언 parity 유지.
        addressStreet: text("address_street"),
        addressLocality: text("address_locality"),
        addressRegion: text("address_region"),
        addressPostalCode: text("address_postal_code"),
        addressCountry: text("address_country"),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        updatedAt: datetime("updated_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [
        uniqueIndex("users_tenant_email_uidx").on(t.tenantId, t.email),
        uniqueIndex("users_tenant_username_uidx").on(t.tenantId, t.username),
        index("users_tenant_idx").on(t.tenantId),
        // GC(하드삭제) 조회 지원. MySQL 은 부분(WHERE) 인덱스를 지원하지 않으므로 sqlite/pg 의
        // 부분 인덱스(users_deletion_pending_idx) 대신 (status, deletionScheduledAt) 복합 인덱스로
        // 동일 조회(status='deletion_pending' & deletionScheduledAt < now)를 지원한다. parity 예외 등재.
        index("users_deletion_gc_idx").on(t.status, t.deletionScheduledAt),
    ],
);

/**
 * 인증 수단. 한 유저가 여러 credential 을 가질 수 있음 (password + TOTP + WebAuthn 복수).
 * - type='password': secret = pbkdf2/argon2id hash, publicKey=NULL (gitleaks:allow — 해시 형식 설명일 뿐 시크릿 아님)
 * - type='totp': secret = encrypted TOTP seed, publicKey=NULL
 * - type='webauthn': secret=NULL, publicKey = CBOR-encoded COSE key, credentialId 별도, counter
 * - type='backup_code': secret = hash of one-time code, usedAt 로 소진 관리
 */
export const credentials = mysqlTable(
    "credentials",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        type: varchar("type", { length: 64, enum: ["password", "totp", "webauthn", "backup_code"] }).notNull(),
        label: text("label"),
        secret: text("secret"),
        publicKey: text("public_key"),
        credentialId: varchar("credential_id", { length: 255 }),
        counter: int("counter").notNull().default(0),
        transports: text("transports"),
        // 섀도 컬럼. TOTP 크레덴셜에만 userId 를 채워, 사용자당 TOTP 1개를 DB unique
        // index 로 강제(TOCTOU 동시 이중 등록 차단). webauthn/backup_code/password 행은
        // NULL 로 두면 unique 검사에서 제외되어 무영향(NULL 다중 허용).
        // MySQL 은 TEXT 컬럼에 unique index 를 걸 수 없어(키 길이 필요) userId 와 동일한
        // varchar(64) 로 둔다 — 컬럼명·nullable string 추론 타입은 3방언 동일(parity 유지).
        totpOwnerId: varchar("totp_owner_id", { length: 64 }),
        lastUsedAt: datetime("last_used_at", { mode: "date", fsp: 3 }),
        usedAt: datetime("used_at", { mode: "date", fsp: 3 }),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
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
export const identities = mysqlTable(
    "identities",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        provider: varchar("provider", { length: 255 }).notNull(),
        subject: varchar("subject", { length: 255 }).notNull(),
        email: text("email"),
        rawProfileJson: text("raw_profile_json"),
        linkedAt: datetime("linked_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        lastLoginAt: datetime("last_login_at", { mode: "date", fsp: 3 }),
    },
    (t) => [uniqueIndex("identities_tenant_provider_subject_uidx").on(t.tenantId, t.provider, t.subject), index("identities_user_idx").on(t.userId)],
);

/**
 * MVP 에선 빈 테이블. federation 활성 시 테넌트별 IdP 설정을 행으로 추가.
 */
export const identityProviders = mysqlTable(
    "identity_providers",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        kind: varchar("kind", { length: 64, enum: ["oidc", "saml", "oauth2", "ldap"] }).notNull(),
        name: varchar("name", { length: 255 }).notNull(),
        clientId: text("client_id"),
        clientSecretEnc: text("client_secret_enc"),
        discoveryUrl: text("discovery_url"),
        metadataXml: text("metadata_xml"),
        scopes: text("scopes"),
        configJson: text("config_json"),
        enabled: boolean("enabled").notNull().default(false),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        updatedAt: datetime("updated_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [index("idp_tenant_idx").on(t.tenantId), uniqueIndex("idp_tenant_name_uidx").on(t.tenantId, t.name)],
);

// ---------- Session ----------

/**
 * IdP 자체 SSO 세션. 브라우저 쿠키가 가리키는 단일 세션이며,
 * 이 아래에 oidc_grants / saml_sessions 가 묶인다.
 */
export const sessions = mysqlTable(
    "sessions",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        /** IdP-level session id, SAML SessionIndex / OIDC sid 로도 사용 */
        idpSessionId: varchar("idp_session_id", { length: 255 }).notNull(),
        amr: text("amr"),
        acr: text("acr"),
        ip: text("ip"),
        userAgent: text("user_agent"),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        lastSeenAt: datetime("last_seen_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
        revokedAt: datetime("revoked_at", { mode: "date", fsp: 3 }),
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
export const trustedDevices = mysqlTable(
    "trusted_devices",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        /** 쿠키 토큰의 SHA-256 해시(base64url). 원본은 저장하지 않는다. */
        tokenHash: varchar("token_hash", { length: 255 }).notNull(),
        ip: text("ip"),
        userAgent: text("user_agent"),
        /** true 면 등록 시점 ip 와 다른 요청에서는 신뢰를 적용하지 않는다. */
        ipBound: boolean("ip_bound").notNull().default(false),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        lastUsedAt: datetime("last_used_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
        revokedAt: datetime("revoked_at", { mode: "date", fsp: 3 }),
    },
    (t) => [uniqueIndex("trusted_devices_token_hash_uidx").on(t.tokenHash), index("trusted_devices_user_idx").on(t.userId), index("trusted_devices_expires_idx").on(t.expiresAt)],
);

// ---------- OIDC ----------

export const oidcClients = mysqlTable(
    "oidc_clients",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        clientId: varchar("client_id", { length: 255 }).notNull(),
        clientSecretHash: varchar("client_secret_hash", { length: 255 }),
        name: varchar("name", { length: 255 }).notNull(),
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
        tokenEndpointAuthMethod: varchar("token_endpoint_auth_method", {
            length: 64,
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
        idTokenSignedResponseAlg: text("id_token_signed_response_alg").notNull().default("RS256"),
        jwksUri: text("jwks_uri"),
        jwks: text("jwks"),
        // organization scope 클레임의 클라이언트별 노출 토글(JSON). null=미설정=전량 노출(하위호환).
        // 예: {"department":true,"team":true,"position":false,"jobTitle":true}
        organizationClaimConfig: text("organization_claim_config"),
        // true 면 user_service_assignments 매핑 없이도 테넌트의 모든 사용자가 SSO 가능 (기본 deny 게이트 우회 opt-in).
        allowAllUsers: boolean("allow_all_users").notNull().default(false),
        enabled: boolean("enabled").notNull().default(true),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        updatedAt: datetime("updated_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [uniqueIndex("oidc_clients_tenant_client_id_uidx").on(t.tenantId, t.clientId), index("oidc_clients_tenant_idx").on(t.tenantId)],
);

export const oidcGrants = mysqlTable(
    "oidc_grants",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        clientId: varchar("client_id", { length: 255 }).notNull(),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        sessionId: varchar("session_id", { length: 64 }).references(() => sessions.id, { onDelete: "set null" }),
        // ctrls C-6: authorization code 평문 저장 제거. 신규/기존 grant 모두 codeHash
        // (SHA-256) 만 저장한다. (legacy code 평문 컬럼은 본 PR 에서 drop 완료.)
        codeHash: varchar("code_hash", { length: 255 }),
        codeChallenge: text("code_challenge"),
        codeChallengeMethod: varchar("code_challenge_method", { length: 64, enum: ["S256", "plain"] }),
        redirectUri: text("redirect_uri").notNull(),
        scope: text("scope").notNull(),
        nonce: text("nonce"),
        state: text("state"),
        acr: text("acr"),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
        usedAt: datetime("used_at", { mode: "date", fsp: 3 }),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [
        // codeHash unique — grant 의 1회용 invariant. NULL 다중 허용 (legacy row).
        uniqueIndex("oidc_grants_code_hash_uidx").on(t.codeHash),
        index("oidc_grants_tenant_client_idx").on(t.tenantId, t.clientId),
        index("oidc_grants_expires_idx").on(t.expiresAt),
    ],
);

export const oidcRefreshTokens = mysqlTable(
    "oidc_refresh_tokens",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        clientId: varchar("client_id", { length: 255 }).notNull(),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        sessionId: varchar("session_id", { length: 64 }).references(() => sessions.id, { onDelete: "set null" }),
        tokenHash: varchar("token_hash", { length: 255 }).notNull(),
        scope: text("scope").notNull(),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
        revokedAt: datetime("revoked_at", { mode: "date", fsp: 3 }),
        replacedById: varchar("replaced_by_id", { length: 64 }),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [uniqueIndex("oidc_refresh_tokens_hash_uidx").on(t.tokenHash), index("oidc_refresh_tokens_user_idx").on(t.userId)],
);

// ---------- SAML ----------

export const samlSps = mysqlTable(
    "saml_sps",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        entityId: varchar("entity_id", { length: 255 }).notNull(),
        name: varchar("name", { length: 255 }).notNull(),
        acsUrl: text("acs_url").notNull(),
        acsBinding: varchar("acs_binding", { length: 255 }).notNull().default("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
        sloUrl: text("slo_url"),
        sloBinding: varchar("slo_binding", { length: 255 }),
        cert: text("cert"),
        nameIdFormat: varchar("name_id_format", { length: 255 }).notNull().default("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
        signAssertion: boolean("sign_assertion").notNull().default(true),
        signResponse: boolean("sign_response").notNull().default(true),
        encryptAssertion: boolean("encrypt_assertion").notNull().default(false),
        // ctrls R8: 신규 SP 는 서명된 AuthnRequest 를 요구하도록 기본 true(secure-by-default).
        wantAuthnRequestsSigned: boolean("want_authn_requests_signed").notNull().default(true),
        // ctrls R6: 이 SP 로 SSO 할 때 이메일 인증을 요구한다(기본 false). true 면 /saml/sso 에서
        // 미인증 사용자를 명확한 오류로 거부한다.
        requireVerifiedEmail: boolean("require_verified_email").notNull().default(false),
        attributeMappingJson: text("attribute_mapping_json"),
        // JSON 배열 문자열 (예: ["email","department"]). NULL 이면 기본 최소 집합만 허용.
        allowedAttributes: text("allowed_attributes"),
        // true 면 user_service_assignments 매핑 없이도 테넌트의 모든 사용자가 SSO 가능 (기본 deny 게이트 우회 opt-in).
        allowAllUsers: boolean("allow_all_users").notNull().default(false),
        enabled: boolean("enabled").notNull().default(true),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        updatedAt: datetime("updated_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [uniqueIndex("saml_sps_tenant_entity_id_uidx").on(t.tenantId, t.entityId), index("saml_sps_tenant_idx").on(t.tenantId)],
);

export const samlSessions = mysqlTable(
    "saml_sessions",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        spId: varchar("sp_id", { length: 64 })
            .notNull()
            .references(() => samlSps.id, { onDelete: "cascade" }),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        sessionId: varchar("session_id", { length: 64 }).references(() => sessions.id, { onDelete: "set null" }),
        sessionIndex: varchar("session_index", { length: 255 }).notNull(),
        nameId: text("name_id").notNull(),
        nameIdFormat: varchar("name_id_format", { length: 255 }),
        notOnOrAfter: datetime("not_on_or_after", { mode: "date", fsp: 3 }).notNull(),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        endedAt: datetime("ended_at", { mode: "date", fsp: 3 }),
    },
    (t) => [uniqueIndex("saml_sessions_session_index_uidx").on(t.sessionIndex), index("saml_sessions_tenant_sp_idx").on(t.tenantId, t.spId)],
);

/**
 * SAML SLO 체인 상태. 여러 SP 를 순차적으로 로그아웃하기 위한 리다이렉트 체인을
 * DB 에 저장해 둔다. id 값이 RelayState 로 전달되어 체인 전반에 걸쳐 식별자 역할을 한다.
 */
export const samlSloStates = mysqlTable("saml_slo_states", {
    id: varchar("id", { length: 64 })
        .primaryKey()
        .$defaultFn(() => crypto.randomUUID()),
    tenantId: varchar("tenant_id", { length: 64 })
        .notNull()
        .references(() => tenants.id, { onDelete: "cascade" }),
    // sessions.id — FK 로 걸지 않는다 (체인 중간에 세션이 revoke 될 수 있음)
    idpSessionRecordId: varchar("idp_session_record_id", { length: 64 }).notNull(),
    userId: varchar("user_id", { length: 64 })
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
    createdAt: datetime("created_at", { mode: "date", fsp: 3 })
        .notNull()
        .default(sql`(CURRENT_TIMESTAMP(3))`),
    expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
});

// ---------- Service Permissions ----------

/**
 * 서비스(OIDC client / SAML SP) 별 role 정의.
 * serviceRefId 는 oidcClients.id 또는 samlSps.id 를 가리키지만 두 테이블 중 하나라
 * FK 는 걸지 않는다. 삭제 시 별도 application-level cleanup 필요.
 */
export const serviceRoles = mysqlTable(
    "service_roles",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        serviceType: varchar("service_type", { length: 64, enum: ["oidc", "saml"] }).notNull(),
        serviceRefId: varchar("service_ref_id", { length: 64 }).notNull(),
        key: varchar("key", { length: 255 }).notNull(),
        label: varchar("label", { length: 255 }).notNull(),
        description: text("description"),
        isDefault: boolean("is_default").notNull().default(false),
        displayOrder: int("display_order").notNull().default(0),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        updatedAt: datetime("updated_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [uniqueIndex("service_roles_service_key_uidx").on(t.serviceType, t.serviceRefId, t.key), index("service_roles_tenant_service_idx").on(t.tenantId, t.serviceType, t.serviceRefId)],
);

/**
 * 사용자에게 부여된 서비스 접근 권한.
 * 기본 deny. 매핑이 없으면 SSO 거부. role 은 nullable — 단순 access 만 부여하는 경우 허용.
 * attributesJson 은 SSO 시 추가로 머지될 클레임/속성을 표현한다.
 */
export const userServiceAssignments = mysqlTable(
    "user_service_assignments",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        serviceType: varchar("service_type", { length: 64, enum: ["oidc", "saml"] }).notNull(),
        serviceRefId: varchar("service_ref_id", { length: 64 }).notNull(),
        serviceRoleId: varchar("service_role_id", { length: 64 }).references(() => serviceRoles.id, { onDelete: "set null" }),
        attributesJson: text("attributes_json"),
        grantedBy: text("granted_by"),
        grantedAt: datetime("granted_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
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
export const serviceEntitlements = mysqlTable(
    "service_entitlements",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        serviceType: varchar("service_type", { length: 64, enum: ["oidc", "saml"] }).notNull(),
        serviceRefId: varchar("service_ref_id", { length: 64 }).notNull(),
        key: varchar("key", { length: 255 }).notNull(),
        label: varchar("label", { length: 255 }).notNull(),
        description: text("description"),
        displayOrder: int("display_order").notNull().default(0),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        updatedAt: datetime("updated_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
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
export const userServiceEntitlements = mysqlTable(
    "user_service_entitlements",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        assignmentId: varchar("assignment_id", { length: 64 }).notNull(),
        serviceEntitlementId: varchar("service_entitlement_id", { length: 64 }).notNull(),
        grantedBy: text("granted_by"),
        grantedAt: datetime("granted_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [
        // 이 두 FK 만 `.references()` 대신 명시 이름을 준다. drizzle 자동 이름
        // (`<table>_<col>_<ftable>_<fcol>_fk`)이 두 긴 테이블명을 이어 붙여 70·75자가 되는데,
        // **MySQL 은 64자 초과 식별자를 에러로 거부**한다(ER_TOO_LONG_IDENT). PostgreSQL 은
        // 63자에서 조용히 자를 뿐이라 방언 간 적용 가능성이 갈린다. 이름을 직접 고정한다.
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
export const signingKeys = mysqlTable(
    "signing_keys",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        kid: varchar("kid", { length: 255 }).notNull(),
        use: varchar("use", { length: 64, enum: ["sig", "enc"] })
            .notNull()
            .default("sig"),
        alg: text("alg").notNull(),
        publicJwk: text("public_jwk").notNull(),
        privateJwkEncrypted: text("private_jwk_encrypted").notNull(),
        certPem: text("cert_pem"),
        active: boolean("active").notNull().default(true),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        rotatedAt: datetime("rotated_at", { mode: "date", fsp: 3 }),
        notAfter: datetime("not_after", { mode: "date", fsp: 3 }),
    },
    (t) => [
        uniqueIndex("signing_keys_tenant_kid_uidx").on(t.tenantId, t.kid),
        index("signing_keys_tenant_active_idx").on(t.tenantId, t.active),
        // ctrls H-ADMIN-5: tenant 당 active=true 인 signing key 는 최대 1개.
        // MySQL은 partial unique index를 지원하지 않으므로 "tenant당 active signing key 1개"
        // 불변식은 애플리케이션 레벨(트랜잭션)에서 보장한다.
        // (SQLite 원본의 partial unique index "signing_keys_tenant_one_active_uidx" 는 생략됨)
    ],
);

export const auditEvents = mysqlTable(
    "audit_events",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: varchar("user_id", { length: 64 }).references(() => users.id, { onDelete: "set null" }),
        actorId: text("actor_id"),
        spOrClientId: text("sp_or_client_id"),
        kind: varchar("kind", { length: 255 }).notNull(),
        outcome: varchar("outcome", { length: 64, enum: ["success", "failure"] }).notNull(),
        ip: text("ip"),
        userAgent: text("user_agent"),
        detailJson: text("detail_json"),
        // ctrls H-ADMIN-2: 행 단위 무결성 HMAC. IDP_SIGNING_KEY_SECRET 파생 키로 계산되어
        // DB write 권한만으로는 필드 변조/위조 불가(삭제 탐지는 Logpush 미러 권장).
        hash: text("hash"),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [index("audit_events_tenant_kind_idx").on(t.tenantId, t.kind), index("audit_events_tenant_created_idx").on(t.tenantId, t.createdAt), index("audit_events_user_idx").on(t.userId)],
);

// ---------- Organization ----------

/**
 * 직급 마스터. 테넌트별 독립 관리.
 * 예: 사원(10) → 대리(20) → 과장(30) → 차장(40) → 부장(50) → 이사(60)
 */
export const positions = mysqlTable(
    "positions",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        name: varchar("name", { length: 255 }).notNull(),
        code: varchar("code", { length: 255 }),
        level: int("level").notNull().default(0), // 높을수록 고위직
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        updatedAt: datetime("updated_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [index("positions_tenant_idx").on(t.tenantId), uniqueIndex("positions_tenant_code_uidx").on(t.tenantId, t.code)],
);

/**
 * 부서. parentId 로 계층 구조(트리) 표현.
 * 최상위 부서는 parentId=NULL.
 */
export const departments = mysqlTable(
    "departments",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        parentId: varchar("parent_id", { length: 64 }).references((): AnyMySqlColumn => departments.id, {
            onDelete: "set null",
        }),
        name: varchar("name", { length: 255 }).notNull(),
        code: varchar("code", { length: 255 }),
        description: text("description"),
        managerId: varchar("manager_id", { length: 64 }).references(() => users.id, { onDelete: "set null" }),
        displayOrder: int("display_order").notNull().default(0),
        status: varchar("status", { length: 64, enum: ["active", "inactive"] })
            .notNull()
            .default("active"),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        updatedAt: datetime("updated_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [index("departments_tenant_idx").on(t.tenantId), index("departments_parent_idx").on(t.parentId), uniqueIndex("departments_tenant_code_uidx").on(t.tenantId, t.code)],
);

/**
 * 팀. 부서 하위에 속하거나(departmentId 있음), 독립적으로 존재 가능.
 */
export const teams = mysqlTable(
    "teams",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        departmentId: varchar("department_id", { length: 64 }).references(() => departments.id, {
            onDelete: "set null",
        }),
        name: varchar("name", { length: 255 }).notNull(),
        code: varchar("code", { length: 255 }),
        description: text("description"),
        leaderId: varchar("leader_id", { length: 64 }).references(() => users.id, { onDelete: "set null" }),
        status: varchar("status", { length: 64, enum: ["active", "inactive"] })
            .notNull()
            .default("active"),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        updatedAt: datetime("updated_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [index("teams_tenant_idx").on(t.tenantId), index("teams_department_idx").on(t.departmentId), uniqueIndex("teams_tenant_code_uidx").on(t.tenantId, t.code)],
);

/**
 * 유저↔부서 소속 (N:M). 겸직·복수 소속 지원.
 * isPrimary=true 인 행이 주소속 부서.
 * endedAt=NULL 이면 현재 소속.
 */
export const userDepartments = mysqlTable(
    "user_departments",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        departmentId: varchar("department_id", { length: 64 })
            .notNull()
            .references(() => departments.id, { onDelete: "cascade" }),
        positionId: varchar("position_id", { length: 64 }).references(() => positions.id, { onDelete: "set null" }),
        jobTitle: text("job_title"), // 직책 (팀장, 파트장, 실장 …)
        isPrimary: boolean("is_primary").notNull().default(false),
        startedAt: datetime("started_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        endedAt: datetime("ended_at", { mode: "date", fsp: 3 }),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [index("user_departments_user_idx").on(t.userId), index("user_departments_dept_idx").on(t.departmentId), index("user_departments_tenant_idx").on(t.tenantId)],
);

/**
 * 파트. 팀 하위 단위. teamId(nullable)로 팀 소속 또는 독립 구성.
 */
export const parts = mysqlTable(
    "parts",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        teamId: varchar("team_id", { length: 64 }).references(() => teams.id, { onDelete: "set null" }),
        name: varchar("name", { length: 255 }).notNull(),
        code: varchar("code", { length: 255 }),
        description: text("description"),
        leaderId: varchar("leader_id", { length: 64 }).references(() => users.id, { onDelete: "set null" }),
        status: varchar("status", { length: 64, enum: ["active", "inactive"] })
            .notNull()
            .default("active"),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        updatedAt: datetime("updated_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [index("parts_tenant_idx").on(t.tenantId), index("parts_team_idx").on(t.teamId), uniqueIndex("parts_tenant_code_uidx").on(t.tenantId, t.code)],
);

/**
 * 유저↔파트 소속 (N:M).
 */
export const userParts = mysqlTable(
    "user_parts",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        partId: varchar("part_id", { length: 64 })
            .notNull()
            .references(() => parts.id, { onDelete: "cascade" }),
        jobTitle: text("job_title"),
        isPrimary: boolean("is_primary").notNull().default(false),
        startedAt: datetime("started_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        endedAt: datetime("ended_at", { mode: "date", fsp: 3 }),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [index("user_parts_user_idx").on(t.userId), index("user_parts_part_idx").on(t.partId), index("user_parts_tenant_idx").on(t.tenantId)],
);

/**
 * 유저↔팀 소속 (N:M). 복수 팀 동시 소속 지원.
 * isPrimary=true 인 행이 주소속 팀.
 * endedAt=NULL 이면 현재 소속.
 */
export const userTeams = mysqlTable(
    "user_teams",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        teamId: varchar("team_id", { length: 64 })
            .notNull()
            .references(() => teams.id, { onDelete: "cascade" }),
        jobTitle: text("job_title"), // 팀 내 역할 (팀장, 멤버 …)
        isPrimary: boolean("is_primary").notNull().default(false),
        startedAt: datetime("started_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        endedAt: datetime("ended_at", { mode: "date", fsp: 3 }),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [index("user_teams_user_idx").on(t.userId), index("user_teams_team_idx").on(t.teamId), index("user_teams_tenant_idx").on(t.tenantId)],
);

// ---------- SAML AuthnRequest ID replay cache ----------

/**
 * SAML AuthnRequest ID 1회용 캐시. parseAuthnRequest 통과 후 INSERT;
 * 동일 ID 가 이미 존재하면 replay 로 간주하고 거부한다. expiresAt 이 지난 행은
 * cleanup job 또는 DELETE WHERE expiresAt < now() 로 정리.
 */
export const samlAuthnRequestIds = mysqlTable(
    "saml_authn_request_ids",
    {
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        // 외부에서 들어온 SAML AuthnRequest ID 값 그대로 저장.
        requestId: varchar("request_id", { length: 255 }).notNull(),
        // SP entityId (디버깅/감사용)
        spEntityId: varchar("sp_entity_id", { length: 255 }).notNull(),
        seenAt: datetime("seen_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
    },
    (t) => [uniqueIndex("saml_authn_request_ids_tenant_req_uidx").on(t.tenantId, t.requestId), index("saml_authn_request_ids_expires_idx").on(t.expiresAt)],
);

// ---------- WebAuthn Challenges ----------

/**
 * WebAuthn 1회용 챌린지. options 응답 시 INSERT, verify 시 atomic UPDATE 로 usedAt 마킹.
 * 만료/재사용 챌린지는 거부된다.
 */
export const webauthnChallenges = mysqlTable(
    "webauthn_challenges",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        // 마이그레이션 호환을 위해 nullable. 신규 row 는 항상 not null 로 INSERT 되며,
        // 조회/소진 시 tenantId 일치를 강제해 (다른 테넌트 challenge 매칭 차단) NULL 인
        // 레거시 row 는 어떤 쿼리에도 잡히지 않는다 (5분 TTL 후 purge).
        tenantId: varchar("tenant_id", { length: 64 }).references(() => tenants.id, { onDelete: "cascade" }),
        userId: varchar("user_id", { length: 64 }).references(() => users.id, { onDelete: "cascade" }),
        challenge: varchar("challenge", { length: 255 }).notNull(),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
        usedAt: datetime("used_at", { mode: "date", fsp: 3 }),
    },
    (t) => [uniqueIndex("webauthn_challenges_tenant_challenge_uidx").on(t.tenantId, t.challenge), index("webauthn_challenges_tenant_expires_idx").on(t.tenantId, t.expiresAt)],
);

// ---------- Types ----------

export type Tenant = typeof tenants.$inferSelect;
// ---------- Rate Limits ----------

export const rateLimits = mysqlTable("rate_limits", {
    key: varchar("key", { length: 255 }).primaryKey(),
    count: int("count").notNull().default(1),
    expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
});

export const clientSkins = mysqlTable(
    "client_skins",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        clientType: varchar("client_type", { length: 64, enum: ["oidc", "saml"] }).notNull(),
        clientRefId: varchar("client_ref_id", { length: 64 }).notNull(),
        skinType: varchar("skin_type", { length: 64, enum: ["login", "signup", "find_id", "find_password", "mfa", "reset_password"] })
            .notNull()
            .default("login"),
        fetchUrl: text("fetch_url").notNull(),
        fetchSecret: text("fetch_secret"),
        cacheTtlSeconds: int("cache_ttl_seconds").notNull().default(3600),
        enabled: boolean("enabled").notNull().default(true),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .$defaultFn(() => new Date()),
    },
    (t) => [uniqueIndex("client_skins_unique").on(t.tenantId, t.clientType, t.clientRefId, t.skinType)],
);

// ---------- Password Reset ----------

export const passwordResetTokens = mysqlTable(
    "password_reset_tokens",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        tokenHash: varchar("token_hash", { length: 255 }).notNull(),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
        usedAt: datetime("used_at", { mode: "date", fsp: 3 }),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [index("password_reset_tokens_user_idx").on(t.userId), uniqueIndex("password_reset_tokens_hash_uidx").on(t.tokenHash)],
);

export type PasswordResetToken = typeof passwordResetTokens.$inferSelect;

// ---------- Email Verification ----------
// password_reset_tokens 와 동일 패턴(SHA-256 해시 저장, TTL, 1회용). TTL 24시간.

export const emailVerificationTokens = mysqlTable(
    "email_verification_tokens",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        tokenHash: varchar("token_hash", { length: 255 }).notNull(),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
        usedAt: datetime("used_at", { mode: "date", fsp: 3 }),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [index("email_verification_tokens_user_idx").on(t.userId), uniqueIndex("email_verification_tokens_hash_uidx").on(t.tokenHash)],
);

export type EmailVerificationToken = typeof emailVerificationTokens.$inferSelect;

// ---------- Invite ----------
// email_verification_tokens 와 동일 패턴(SHA-256 해시 저장, TTL, 1회용). TTL 72시간.
// 초대는 관리자가 비밀번호 없이 계정을 선생성하고, 이 토큰 링크로 최초 비밀번호를 설정한다.

export const inviteTokens = mysqlTable(
    "invite_tokens",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        tokenHash: varchar("token_hash", { length: 255 }).notNull(),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
        usedAt: datetime("used_at", { mode: "date", fsp: 3 }),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [index("invite_tokens_user_idx").on(t.userId), uniqueIndex("invite_tokens_hash_uidx").on(t.tokenHash)],
);

export type InviteToken = typeof inviteTokens.$inferSelect;

// ---------- Email change ----------
// F3: 프로필 이메일 변경 확인 토큰. email_verification_tokens 와 분리한다 — 변경 대상 주소
// (targetEmail)를 토큰에 바인딩해야 하고(확인 링크가 다른 주소로 재사용되지 않도록), 확인
// 라우트/시맨틱도 다르기 때문이다. SHA-256 해시 저장, TTL 24시간, 1회용(usedAt).
export const emailChangeTokens = mysqlTable(
    "email_change_tokens",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        userId: varchar("user_id", { length: 64 })
            .notNull()
            .references(() => users.id, { onDelete: "cascade" }),
        tokenHash: varchar("token_hash", { length: 255 }).notNull(),
        // 변경하려는 새 이메일 주소(토큰에 바인딩). 확인 시 이 값으로 users.email 을 교체한다.
        targetEmail: varchar("target_email", { length: 320 }).notNull(),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }).notNull(),
        usedAt: datetime("used_at", { mode: "date", fsp: 3 }),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
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
 * IdP 세션 ↔ OIDC 클라이언트 연결 기록. (설명은 schema.pg.ts 참조 — 3방언 동일 정의)
 */
export const oidcClientSessions = mysqlTable(
    "oidc_client_sessions",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        sessionId: varchar("session_id", { length: 64 })
            .notNull()
            .references(() => sessions.id, { onDelete: "cascade" }),
        clientId: varchar("client_id", { length: 255 }).notNull(),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
    },
    (t) => [uniqueIndex("oidc_client_sessions_session_client_uidx").on(t.sessionId, t.clientId), index("oidc_client_sessions_tenant_session_idx").on(t.tenantId, t.sessionId)],
);

/**
 * 서비스 API 토큰. (설명은 schema.pg.ts 참조 — 3방언 동일 정의)
 */
export const serviceApiTokens = mysqlTable(
    "service_api_tokens",
    {
        id: varchar("id", { length: 64 })
            .primaryKey()
            .$defaultFn(() => crypto.randomUUID()),
        tenantId: varchar("tenant_id", { length: 64 })
            .notNull()
            .references(() => tenants.id, { onDelete: "cascade" }),
        name: varchar("name", { length: 255 }).notNull(),
        tokenHash: varchar("token_hash", { length: 255 }).notNull(),
        tokenPrefix: varchar("token_prefix", { length: 64 }).notNull(),
        scopes: text("scopes").notNull(),
        createdBy: text("created_by"),
        createdAt: datetime("created_at", { mode: "date", fsp: 3 })
            .notNull()
            .default(sql`(CURRENT_TIMESTAMP(3))`),
        expiresAt: datetime("expires_at", { mode: "date", fsp: 3 }),
        lastUsedAt: datetime("last_used_at", { mode: "date", fsp: 3 }),
    },
    (t) => [uniqueIndex("service_api_tokens_token_hash_uidx").on(t.tokenHash), index("service_api_tokens_tenant_idx").on(t.tenantId)],
);

export type OidcClientSession = typeof oidcClientSessions.$inferSelect;
export type ServiceApiToken = typeof serviceApiTokens.$inferSelect;
export type ServiceRole = typeof serviceRoles.$inferSelect;
export type UserServiceAssignment = typeof userServiceAssignments.$inferSelect;
export type ServiceEntitlement = typeof serviceEntitlements.$inferSelect;
export type UserServiceEntitlement = typeof userServiceEntitlements.$inferSelect;
