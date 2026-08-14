/**
 * 프로바이더 프리셋 레지스트리.
 *
 * 관리자는 프리셋을 고르고 client_id/secret 만 넣으면 되고, 엔드포인트·스코프·
 * 프로필 정규화는 프리셋이 담당한다. 목록에 없는 프로바이더는 `oidc` 프리셋에
 * discoveryUrl 을 직접 입력해 붙인다.
 */

import { genericOidcPreset, googlePreset, microsoftPreset } from "./providers/generic-oidc";
import { githubPreset } from "./providers/github";
import { kakaoPreset } from "./providers/kakao";
import { naverPreset } from "./providers/naver";
import type { OAuthProviderConfig, ProviderPreset } from "./types";

const PRESETS: ProviderPreset[] = [naverPreset, kakaoPreset, githubPreset, microsoftPreset, googlePreset, genericOidcPreset];

const PRESET_BY_ID = new Map(PRESETS.map((p) => [p.id, p]));

/** 관리자 UI 의 프로바이더 선택 목록. */
export function listPresets(): ReadonlyArray<Pick<ProviderPreset, "id" | "label" | "kind" | "defaultScopes">> {
    return PRESETS.map((p) => ({ id: p.id, label: p.label, kind: p.kind, defaultScopes: p.defaultScopes }));
}

/** providerType 으로 프리셋을 찾는다. 없으면 null. */
export function getPreset(providerType: string): ProviderPreset | null {
    return PRESET_BY_ID.get(providerType) ?? null;
}

/**
 * 설정에 프리셋을 적용해 실제 사용할 discovery URL 을 만든다.
 * Microsoft 처럼 URL 에 디렉터리 테넌트를 끼워 넣어야 하는 경우를 처리한다.
 */
export function resolveDiscoveryUrl(preset: ProviderPreset, config: OAuthProviderConfig): string | undefined {
    // 관리자가 직접 지정한 값이 항상 우선한다.
    if (config.discoveryUrl) return config.discoveryUrl;
    if (!preset.discoveryUrl) return undefined;

    if (preset.discoveryUrl.includes("{directoryTenant}")) {
        const raw = config.directoryTenant?.trim() || "common";
        // 경로 주입 방지 — GUID 또는 알려진 별칭만 허용한다.
        const allowed = /^(common|organizations|consumers|[0-9a-f-]{36})$/i.test(raw) ? raw : "common";
        return preset.discoveryUrl.replace("{directoryTenant}", allowed);
    }

    return preset.discoveryUrl;
}

/** 설정에 지정된 스코프가 있으면 그것을, 없으면 프리셋 기본값을 쓴다. */
export function resolveScopes(preset: ProviderPreset, config: OAuthProviderConfig): string[] {
    const configured = config.scopes?.filter((s) => s.trim().length > 0);
    return configured && configured.length > 0 ? configured : preset.defaultScopes;
}
