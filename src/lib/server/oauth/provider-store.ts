/**
 * `identity_providers` 행을 소셜 로그인이 쓰는 형태로 읽어오는 계층.
 *
 * 시크릿 복호화 정책은 LDAP(`login/+page.server.ts` 의 bindPassword 처리)과 같다 —
 * 무중단 키 회전을 위해 current/previous 두 시크릿으로 순차 시도한다.
 */

import { and, asc, eq, inArray } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { identityProviders } from "$lib/server/db/schema";
import { decryptSecret, tryWithSecrets } from "$lib/server/crypto/keys";
import { escapeHtml } from "$lib/server/skin/resolver";
import { getPreset } from "./registry";
import type { OAuthProviderConfig, ProviderPreset } from "./types";

/** client secret 암호문의 AAD 컨텍스트. LDAP bindPassword 와 다른 값을 써서 오용을 막는다. */
export const OAUTH_SECRET_CONTEXT = "idp-oauth-client-secret-v1";

/** 소셜 로그인에 해당하는 kind 들. LDAP/SAML 행은 제외된다. */
const SOCIAL_KINDS = ["oauth2", "oidc"] as const;

export interface LoadedProvider {
    id: string;
    slug: string;
    name: string;
    clientId: string;
    config: OAuthProviderConfig;
    preset: ProviderPreset;
}

/** 로그인 페이지 버튼 렌더에 필요한 최소 정보. */
export interface ProviderButton {
    slug: string;
    label: string;
    iconKey: string;
}

function parseConfig(configJson: string | null): OAuthProviderConfig | null {
    if (!configJson) return null;
    try {
        const parsed = JSON.parse(configJson) as OAuthProviderConfig;
        return typeof parsed?.providerType === "string" ? parsed : null;
    } catch {
        return null;
    }
}

/**
 * 활성화된 소셜 프로바이더의 버튼 목록. 설정이 깨졌거나 프리셋이 없는 행은 조용히 건너뛴다
 * (로그인 페이지 전체가 죽는 것보다 버튼 하나가 안 보이는 편이 낫다).
 */
export async function listEnabledProviderButtons(db: DB, tenantId: string): Promise<ProviderButton[]> {
    const rows = await db
        .select({ slug: identityProviders.slug, name: identityProviders.name, configJson: identityProviders.configJson })
        .from(identityProviders)
        .where(and(eq(identityProviders.tenantId, tenantId), inArray(identityProviders.kind, [...SOCIAL_KINDS]), eq(identityProviders.enabled, true)))
        .orderBy(asc(identityProviders.name));

    const buttons: ProviderButton[] = [];
    for (const row of rows) {
        if (!row.slug) continue;
        const config = parseConfig(row.configJson);
        if (!config) continue;
        const preset = getPreset(config.providerType);
        if (!preset) continue;

        buttons.push({
            slug: row.slug,
            label: config.buttonLabel?.trim() || preset.label,
            iconKey: config.iconKey?.trim() || preset.id,
        });
    }

    // displayOrder 는 config 안에 있어 SQL 로 정렬할 수 없다. 메모리에서 안정 정렬한다.
    return buttons.sort((a, b) => a.label.localeCompare(b.label));
}

/**
 * 커스텀 스킨의 `{{IDP_SOCIAL_BUTTONS}}` 자리에 넣을 HTML 을 만든다.
 *
 * 스킨은 관리자가 등록한 외부 HTML 이라 Svelte 컴포넌트를 쓸 수 없다. 링크 목록만
 * 내보내고 스타일은 스킨이 `.idp-social-btn` 클래스로 입히도록 한다.
 * 삽입값은 모두 escape 한다 — label 은 관리자 입력이라 무조건 신뢰할 대상이 아니다.
 */
export function renderSocialButtonsHtml(buttons: ProviderButton[], opts: { redirectTo: string | null; skinHint: string | null }): string {
    if (buttons.length === 0) return "";

    const items = buttons.map((b) => {
        const params = new URLSearchParams();
        if (opts.redirectTo) params.set("redirectTo", opts.redirectTo);
        if (opts.skinHint) params.set("skinHint", opts.skinHint);
        const qs = params.toString();
        const href = `/auth/oauth/${encodeURIComponent(b.slug)}/start${qs ? `?${qs}` : ""}`;
        return `<a class="idp-social-btn idp-social-${escapeHtml(b.iconKey)}" href="${escapeHtml(href)}">${escapeHtml(b.label)}</a>`;
    });

    return `<div class="idp-social-buttons">${items.join("")}</div>`;
}

/**
 * slug 로 활성 프로바이더를 로드한다. 없거나 비활성이거나 설정이 깨졌으면 null.
 * client secret 은 포함하지 않는다 — 필요할 때 `loadClientSecret` 을 따로 부른다.
 */
export async function loadProviderBySlug(db: DB, tenantId: string, slug: string): Promise<LoadedProvider | null> {
    const [row] = await db
        .select()
        .from(identityProviders)
        .where(and(eq(identityProviders.tenantId, tenantId), eq(identityProviders.slug, slug), eq(identityProviders.enabled, true)))
        .limit(1);

    if (!row || !row.slug) return null;
    if (!SOCIAL_KINDS.includes(row.kind as (typeof SOCIAL_KINDS)[number])) return null;

    const config = parseConfig(row.configJson);
    if (!config) return null;

    const preset = getPreset(config.providerType);
    if (!preset) return null;
    if (!row.clientId) return null;

    return { id: row.id, slug: row.slug, name: row.name, clientId: row.clientId, config, preset };
}

/**
 * 저장된 client secret 을 복호화한다. 시크릿이 없거나 복호화에 실패하면 null.
 * (LDAP 과 달리 평문 폴백을 두지 않는다 — 신규 기능이라 레거시 평문 행이 존재하지 않는다.)
 */
export async function loadClientSecret(db: DB, tenantId: string, providerId: string, signingKeySecrets: string[]): Promise<string | null> {
    if (signingKeySecrets.length === 0) return null;

    const [row] = await db
        .select({ enc: identityProviders.clientSecretEnc })
        .from(identityProviders)
        .where(and(eq(identityProviders.id, providerId), eq(identityProviders.tenantId, tenantId)))
        .limit(1);

    if (!row?.enc) return null;

    try {
        return await tryWithSecrets(signingKeySecrets, (s) => decryptSecret(row.enc!, s, OAUTH_SECRET_CONTEXT));
    } catch {
        return null;
    }
}
