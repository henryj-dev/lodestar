<script lang="ts">
import { enhance } from "$app/forms";
import { page } from "$app/state";
import { onMount } from "svelte";
import type { SubmitFunction } from "@sveltejs/kit";
import { t } from "$lib/i18n.svelte";
import FormError from "$lib/components/FormError.svelte";
import LocaleToggle from "$lib/components/LocaleToggle.svelte";
import type { ActionData, PageData } from "./$types";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();
const err = $derived((form as { error?: string } | null)?.error ?? null);

const skinHtmlEffective = $derived((form as { skinHtml?: string | null } | null)?.skinHtml ?? data.skinHtml);

onMount(() => {
    if (!skinHtmlEffective) return;
    const el = document.createElement("script");
    el.src = "/api/skin-scripts";
    document.head.appendChild(el);
    return () => {
        if (el.parentNode) el.parentNode.removeChild(el);
    };
});

/**
 * 폼 액션에 **현재 쿼리스트링을 유지**한다.
 *
 * `action="?/approve"` 로 두면 브라우저가 상대 URL 을 해석할 때 쿼리스트링을 통째로
 * 교체해서 대상 파라미터(client_type / client_ref / redirectTo)가 사라진다. 그러면 서버가
 * 대상을 못 읽고 `/` 로 돌려보내, 승인해도 서비스로 못 돌아간다.
 *
 * SvelteKit 은 **이름이 `/` 로 시작하는 파라미터**로 named action 을 찾으므로, 기존 쿼리
 * 뒤에 붙이면 둘 다 성립한다. 대상을 hidden input 으로 옮기지 않은 것은, 화면에 보여준
 * 대상과 기록되는 동의가 같은 출처(URL)에서 나와야 어긋날 수 없기 때문이다.
 */
const actionPrefix = $derived(page.url.search ? `${page.url.search}&` : "?");

let submitting = $state(false);
const enhanceSubmit: SubmitFunction = () => {
    submitting = true;
    return async ({ update }) => {
        await update({ reset: false });
        submitting = false;
    };
};

// 이미 승인된 항목은 접어 둔다 (C3-A) — 재동의에서 무엇이 새로운지 바로 보이게.
let showGranted = $state(false);

/**
 * 스코프/속성 이름을 사람 말로. 카탈로그에 없으면 원래 이름을 그대로 보여준다 —
 * 커스텀 스코프를 쓰는 배포에서 빈 줄이 뜨는 것보다 낫다.
 */
function label(scope: string): string {
    const key = `consent.scope_${scope.replace(/[^a-zA-Z0-9_]/g, "_")}`;
    const translated = t(key);
    return translated === key ? scope : translated;
}
</script>

{#if skinHtmlEffective}
    <!-- 커스텀 스킨 — 서버가 가져와 sanitize 한 HTML. 사용자 입력은 이 슬롯에 들어오지 않는다. -->
    <!-- eslint-disable-next-line svelte/no-at-html-tags -->
    {@html skinHtmlEffective}
{:else}
    <div class="fixed top-4 right-4 z-40"><LocaleToggle /></div>
    <div class="flex min-h-screen items-center justify-center bg-gray-50 p-4">
        <div class="w-full max-w-md space-y-6 rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
            <div>
                <h1 class="text-2xl font-bold text-gray-900">
                    {data.isReconsent ? t("consent.title_reconsent") : t("consent.title")}
                </h1>
                <p class="mt-1 text-sm leading-6 text-gray-500">
                    {t("consent.subtitle", { client: data.clientName })}
                </p>
            </div>

            <FormError message={err} />

            <form method="POST" action="{actionPrefix}/approve" use:enhance={enhanceSubmit} class="space-y-5">
                <!-- 쿼리스트링이 유실되어도 서버가 대상을 찾을 수 있게 본문에도 싣는다. -->
                <input type="hidden" name="clientType" value={data.clientType} />
                <input type="hidden" name="clientRefId" value={data.clientRefId} />
                <input type="hidden" name="redirectTo" value={data.redirectTo} />
                {#if data.requiredScopes.length > 0}
                    <div>
                        <h2 class="text-xs font-semibold tracking-wide text-gray-700 uppercase">{t("consent.required_label")}</h2>
                        <ul class="mt-2 space-y-1.5">
                            {#each data.requiredScopes as scope (scope)}
                                <li class="flex items-start gap-2 text-sm text-gray-800">
                                    <span aria-hidden="true" class="mt-0.5 text-gray-400">•</span>
                                    <span>
                                        {label(scope)}
                                        {#if data.newlyRequested.includes(scope) && data.isReconsent}
                                            <span class="ml-1 rounded bg-blue-50 px-1.5 py-0.5 text-xs font-medium text-blue-700">{t("consent.badge_new")}</span>
                                        {/if}
                                    </span>
                                </li>
                            {/each}
                        </ul>
                    </div>
                {/if}

                {#if data.optionalScopes.length > 0}
                    <div>
                        <h2 class="text-xs font-semibold tracking-wide text-gray-700 uppercase">{t("consent.optional_label")}</h2>
                        <p class="mt-0.5 text-xs text-gray-500">{t("consent.optional_hint")}</p>
                        <ul class="mt-2 space-y-2">
                            {#each data.optionalScopes as scope (scope)}
                                <li>
                                    <label class="flex items-start gap-2 text-sm text-gray-800">
                                        <!-- 기본 해제(opt-in) — 미리 체크된 상태는 동의를 받은 것으로 보기 어렵다. -->
                                        <input type="checkbox" name="optionalScope" value={scope} class="mt-0.5 rounded border-gray-300" />
                                        <span>{label(scope)}</span>
                                    </label>
                                </li>
                            {/each}
                        </ul>
                    </div>
                {/if}

                {#if data.alreadyGranted.length > 0}
                    <div class="rounded-lg border border-gray-100 bg-gray-50 px-3 py-2">
                        <button type="button" onclick={() => (showGranted = !showGranted)} class="flex w-full items-center justify-between text-xs font-medium text-gray-600">
                            <span>{t("consent.already_granted", { count: String(data.alreadyGranted.length) })}</span>
                            <span aria-hidden="true">{showGranted ? "▾" : "▸"}</span>
                        </button>
                        {#if showGranted}
                            <ul class="mt-2 space-y-1">
                                {#each data.alreadyGranted as scope (scope)}
                                    <li class="text-xs text-gray-500">• {label(scope)}</li>
                                {/each}
                            </ul>
                        {/if}
                    </div>
                {/if}

                <div class="flex gap-2 pt-1">
                    <button
                        type="submit"
                        formaction="{actionPrefix}/deny"
                        disabled={submitting}
                        class="flex-1 rounded-lg border border-gray-300 bg-white py-2.5 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-60">
                        {t("consent.deny")}
                    </button>
                    <button type="submit" disabled={submitting} class="flex-1 rounded-lg bg-blue-600 py-2.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-60">
                        {submitting ? t("common.processing") : t("consent.approve")}
                    </button>
                </div>
            </form>

            <p class="text-xs leading-relaxed text-gray-400">{t("consent.revoke_hint")}</p>
        </div>
    </div>
{/if}
