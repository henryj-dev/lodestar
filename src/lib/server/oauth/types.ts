/**
 * upstream OAuth2 / OIDC 연합의 공용 타입.
 *
 * Lodestar 은 downstream 으로 OIDC/SAML 을 제공하는 IdP 이면서, upstream 으로는
 * 외부 소셜 프로바이더(네이버/카카오/깃허브/Microsoft 등)에 연합할 수 있다.
 * 이 파일은 그 upstream 방향의 계약만 정의한다.
 */

/**
 * 매칭되는 Lodestar 계정이 없을 때의 처리 방식. `identity_providers.configJson` 에 저장한다.
 *
 * - `signup_form`: 외부 프로필을 프리필한 가입 폼(`/signup?federated=1`)으로 보낸다. 소셜 기본값.
 * - `jit`:         무음으로 계정을 생성한다. LDAP 기본값(기존 동작 유지).
 * - `deny`:        가입을 막고 관리자에게 문의하도록 안내한다. 사전 프로비저닝된 조직에 유용.
 */
export type ProvisioningMode = "signup_form" | "jit" | "deny";

/** `identity_providers.config_json` 에 저장되는 소셜 프로바이더 설정. */
export interface OAuthProviderConfig {
    /** `registry.ts` 의 프리셋 키. 어댑터 선택에 쓰인다. */
    providerType: string;

    /** 프리셋 엔드포인트 오버라이드. 자체 호스팅 OIDC 등 예외 케이스용. */
    authorizationUrl?: string;
    tokenUrl?: string;
    userinfoUrl?: string;
    /** OIDC discovery 문서 URL. 지정하면 위 엔드포인트보다 우선한다. */
    discoveryUrl?: string;
    /** OIDC issuer 기대값. id_token 의 `iss` 검증에 쓰인다. */
    issuer?: string;
    /** Microsoft Entra 전용 — `common` / `organizations` / 디렉터리 GUID. */
    directoryTenant?: string;

    /** 프리셋 기본 스코프 대신 사용할 스코프. */
    scopes?: string[];

    /** §2.8 — 매칭 계정이 없을 때의 처리. 미지정 시 소셜은 `signup_form`. */
    provisioningMode?: ProvisioningMode;
    /**
     * 프로바이더가 이메일 검증을 단언한 경우, 같은 이메일의 기존 계정에 자동 연결할지 여부.
     * 기본 false — 켜면 프로바이더의 이메일 주장만으로 기존 계정에 접근이 열리므로,
     * 해당 프로바이더의 이메일 검증을 신뢰할 수 있을 때만 활성화한다.
     */
    autoLinkVerifiedEmail?: boolean;

    /** 로그인 버튼 표시용. */
    buttonLabel?: string;
    iconKey?: string;
    displayOrder?: number;
}

/** 프로바이더 응답을 Lodestar 계정 모델로 정규화한 결과. */
export interface NormalizedProfile {
    /** 프로바이더 내 불변 사용자 식별자. `identities.subject` 가 된다. */
    subject: string;
    email: string | null;
    /**
     * 프로바이더가 이메일 소유를 **검증했다고 단언**한 경우에만 true.
     * "값이 존재함" 과 혼동하면 안 된다 — 계정 연결 정책이 이 플래그에 의존한다.
     */
    emailVerified: boolean;
    displayName?: string;
    givenName?: string;
    familyName?: string;
    avatarUrl?: string;
    /** username 프리필 후보. 규칙(`^[a-z0-9_]{3,32}$`)을 만족하지 않을 수 있다. */
    suggestedUsername?: string;
    /** `identities.raw_profile_json` 에 보관할 원본. 시크릿은 포함하지 않는다. */
    raw: Record<string, unknown>;
}

/** 토큰 엔드포인트 응답 중 우리가 쓰는 부분. */
export interface TokenResponse {
    accessToken: string;
    idToken?: string;
    tokenType?: string;
    scope?: string;
}

/** 프로바이더별 어댑터. `registry.ts` 가 이 형태로 프리셋을 등록한다. */
export interface ProviderPreset {
    /** `OAuthProviderConfig.providerType` 와 일치하는 키. */
    id: string;
    /** 관리자 UI 및 기본 버튼 라벨. */
    label: string;
    /** `identity_providers.kind` 로 저장될 값. */
    kind: "oauth2" | "oidc";
    /**
     * PKCE 지원 여부. 네이버/깃허브는 미지원이라 code_verifier 를 보내면 오류가 난다.
     * state 쿠키가 CSRF 를 막으므로 미지원 프로바이더에서도 안전성은 유지된다.
     */
    supportsPkce: boolean;
    defaultScopes: string[];

    authorizationUrl?: string;
    tokenUrl?: string;
    userinfoUrl?: string;
    discoveryUrl?: string;

    /** authorize 요청에 항상 붙일 추가 파라미터. */
    extraAuthParams?: Record<string, string>;

    /**
     * 토큰 응답에서 정규화된 프로필을 만든다.
     * OIDC 프리셋은 id_token 클레임을, OAuth2 프리셋은 userinfo 호출 결과를 사용한다.
     */
    fetchProfile(tokens: TokenResponse, ctx: ProfileContext): Promise<NormalizedProfile>;
}

/** `fetchProfile` 에 전달되는 실행 컨텍스트. */
export interface ProfileContext {
    config: OAuthProviderConfig;
    clientId: string;
    /** OIDC nonce 검증용. authorize 요청에 실었던 값. */
    nonce?: string;
    /** discovery 로 해석된 엔드포인트(OIDC 프리셋에서만 채워진다). */
    resolved?: ResolvedEndpoints;
}

/** discovery 또는 프리셋으로 확정된 엔드포인트 집합. */
export interface ResolvedEndpoints {
    issuer?: string;
    authorizationUrl: string;
    tokenUrl: string;
    userinfoUrl?: string;
    jwksUri?: string;
}
