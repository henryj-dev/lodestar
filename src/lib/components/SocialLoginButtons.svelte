<!--
    소셜 로그인 버튼 목록.

    아이콘은 **인라인 SVG** 다. CSP 의 `img-src` 가 `self`/`data:` 만 허용하므로
    (svelte.config.js) 프로바이더 CDN 로고 URL 은 브라우저가 차단한다.

    각 버튼은 `/auth/oauth/{slug}/start` 로 가는 단순 링크다. GET 인 이유와 CSRF 방어
    근거는 해당 라우트 주석 참고(state 쿠키가 막는다).
-->
<script lang="ts">
import { t } from "$lib/i18n.svelte";

interface Provider {
    slug: string;
    label: string;
    iconKey: string;
}

const { providers, redirectTo = null, skinHint = null } = $props<{ providers: Provider[]; redirectTo?: string | null; skinHint?: string | null }>();

function startUrl(slug: string): string {
    // 반응형 상태가 아니라 렌더 시점의 문자열 조립이므로 수동으로 인코딩한다
    // (URLSearchParams 인스턴스를 만들면 svelte/prefer-svelte-reactivity 에 걸린다).
    const parts: string[] = [];
    if (redirectTo) parts.push(`redirectTo=${encodeURIComponent(redirectTo)}`);
    if (skinHint) parts.push(`skinHint=${encodeURIComponent(skinHint)}`);
    const qs = parts.join("&");
    return `/auth/oauth/${encodeURIComponent(slug)}/start${qs ? `?${qs}` : ""}`;
}

/** 프로바이더별 브랜드 색. 목록에 없으면 중립 회색 테두리로 렌더된다. */
const BRAND: Record<string, { bg: string; fg: string; border: string }> = {
    naver: { bg: "#03C75A", fg: "#FFFFFF", border: "#03C75A" },
    kakao: { bg: "#FEE500", fg: "#191600", border: "#FEE500" },
    github: { bg: "#24292F", fg: "#FFFFFF", border: "#24292F" },
    microsoft: { bg: "#FFFFFF", fg: "#3B3A39", border: "#8C8C8C" },
    google: { bg: "#FFFFFF", fg: "#3C4043", border: "#DADCE0" },
};

function styleFor(iconKey: string): string {
    const brand = BRAND[iconKey];
    if (!brand) return "";
    return `background-color:${brand.bg};color:${brand.fg};border-color:${brand.border}`;
}
</script>

{#if providers.length > 0}
    <div class="mt-4 flex items-center gap-3">
        <div class="h-px flex-1 bg-gray-200"></div>
        <span class="text-xs text-gray-400">{t("social.divider")}</span>
        <div class="h-px flex-1 bg-gray-200"></div>
    </div>

    <!-- resolve() 는 컴파일 타임에 알려진 라우트 ID 를 요구하지만, 여기 slug 는 DB 에서
         읽은 런타임 값이라 정적으로 해석할 수 없다. data-sveltekit-reload 로 전체
         내비게이션을 강제해 서버 라우트(/auth/oauth/[slug]/start)로 직접 나간다. -->
    <!-- eslint-disable svelte/no-navigation-without-resolve -->
    <div class="mt-4 space-y-2">
        {#each providers as provider (provider.slug)}
            <a
                href={startUrl(provider.slug)}
                data-sveltekit-reload
                style={styleFor(provider.iconKey)}
                class="flex w-full items-center justify-center gap-2 rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow-sm transition hover:opacity-90">
                {#if provider.iconKey === "naver"}
                    <svg class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path d="M11.6 10.7 8.2 5.5H5.5v9h2.9V9.3l3.4 5.2h2.7v-9h-2.9v5.2Z" />
                    </svg>
                {:else if provider.iconKey === "kakao"}
                    <svg class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path d="M10 3C6.13 3 3 5.46 3 8.5c0 1.96 1.3 3.68 3.27 4.66l-.83 3.05c-.07.26.22.47.45.33l3.66-2.42c.15.01.3.02.45.02 3.87 0 7-2.46 7-5.5S13.87 3 10 3Z" />
                    </svg>
                {:else if provider.iconKey === "github"}
                    <svg class="h-4 w-4" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
                        <path
                            d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
                    </svg>
                {:else if provider.iconKey === "microsoft"}
                    <svg class="h-4 w-4" viewBox="0 0 20 20" aria-hidden="true">
                        <path fill="#F25022" d="M2 2h7.6v7.6H2z" />
                        <path fill="#7FBA00" d="M10.4 2H18v7.6h-7.6z" />
                        <path fill="#00A4EF" d="M2 10.4h7.6V18H2z" />
                        <path fill="#FFB900" d="M10.4 10.4H18V18h-7.6z" />
                    </svg>
                {:else if provider.iconKey === "google"}
                    <svg class="h-4 w-4" viewBox="0 0 20 20" aria-hidden="true">
                        <path fill="#4285F4" d="M19.6 10.23c0-.68-.06-1.36-.19-2.02H10v3.82h5.4a4.62 4.62 0 0 1-2 3.03v2.5h3.23c1.89-1.74 2.97-4.3 2.97-7.33Z" />
                        <path fill="#34A853" d="M10 20c2.7 0 4.96-.9 6.62-2.44l-3.23-2.5c-.9.6-2.05.96-3.39.96-2.6 0-4.8-1.76-5.6-4.12H1.07v2.58A10 10 0 0 0 10 20Z" />
                        <path fill="#FBBC05" d="M4.4 11.9a6 6 0 0 1 0-3.8V5.52H1.07a10 10 0 0 0 0 8.96L4.4 11.9Z" />
                        <path fill="#EA4335" d="M10 3.96c1.47 0 2.79.5 3.83 1.5l2.86-2.86C14.96.98 12.7 0 10 0A10 10 0 0 0 1.07 5.52L4.4 8.1C5.2 5.73 7.4 3.96 10 3.96Z" />
                    </svg>
                {/if}
                {t("social.continue_with", { provider: provider.label })}
            </a>
        {/each}
    </div>
{/if}
