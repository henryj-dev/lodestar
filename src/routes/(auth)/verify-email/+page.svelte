<script lang="ts">
import { enhance } from "$app/forms";
import { resolve } from "$app/paths";
import { onMount } from "svelte";
import type { SubmitFunction } from "@sveltejs/kit";
import { t } from "$lib/i18n.svelte";
import FormError from "$lib/components/FormError.svelte";
import LocaleToggle from "$lib/components/LocaleToggle.svelte";
import type { ActionData, PageData } from "./$types";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();
const err = $derived((form as { error?: string } | null)?.error ?? null);
const verified = $derived((form as { verified?: boolean } | null)?.verified ?? false);
const isSuccess = $derived(verified || (data.valid && data.alreadyVerified));

const skinHtmlEffective = $derived((form as { skinHtml?: string | null } | null)?.skinHtml ?? data.skinHtml);

// 스킨은 자체 <script> 를 쓸 수 없으므로 공통 스크립트를 여기서 주입한다(형제 스킨 페이지와 동일).
onMount(() => {
    if (!skinHtmlEffective) return;
    const el = document.createElement("script");
    el.src = "/api/skin-scripts";
    document.head.appendChild(el);
    return () => {
        if (el.parentNode) el.parentNode.removeChild(el);
    };
});

let submitting = $state(false);
const enhanceSubmit: SubmitFunction = () => {
    submitting = true;
    return async ({ update }) => {
        await update({ reset: false });
        submitting = false;
    };
};
</script>

{#if skinHtmlEffective}
    <!-- 커스텀 스킨 — 관리자가 등록한 외부 URL 을 서버에서 가져와 sanitize 한 HTML 이다.
         사용자 입력은 이 슬롯에 들어오지 않으며, CSP·CSRF·admin 전용 등록 권한으로 영향을 제한한다. -->
    <!-- eslint-disable-next-line svelte/no-at-html-tags -->
    {@html skinHtmlEffective}
{:else}
    <div class="fixed top-4 right-4 z-40"><LocaleToggle /></div>
    <div class="flex min-h-screen items-center justify-center bg-gray-50 p-4">
        <div class="w-full max-w-md space-y-6 rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
            <div>
                <h1 class="text-2xl font-bold text-gray-900">{t("verify_email.title")}</h1>
                <p class="mt-1 text-sm text-gray-500">{t("verify_email.subtitle")}</p>
            </div>

            {#if isSuccess}
                <div class="rounded-lg border border-green-200 bg-green-50 p-4 text-sm text-green-700">
                    {t("verify_email.success")}
                </div>
                <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
                <a href={resolve("/login")} class="block text-center text-sm text-blue-600 hover:underline">
                    {t("verify_email.go_login")} →
                </a>
            {:else if data.valid}
                <FormError message={err} />
                <p class="text-sm text-gray-600">{t("verify_email.confirm_prompt")}</p>
                <form method="POST" use:enhance={enhanceSubmit} class="space-y-4">
                    <input type="hidden" name="token" value={data.token} />
                    <button
                        type="submit"
                        disabled={submitting}
                        class="flex w-full items-center justify-center gap-2 rounded-lg bg-blue-600 py-2.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-60">
                        {#if submitting}
                            <svg class="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                            </svg>
                            {t("common.processing")}
                        {:else}
                            {t("verify_email.submit")}
                        {/if}
                    </button>
                </form>
            {:else}
                <div class="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                    {t("verify_email.invalid_link")}
                </div>
                <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
                <a href={resolve("/login")} class="block text-center text-sm text-blue-600 hover:underline">
                    {t("verify_email.go_login")} →
                </a>
            {/if}
        </div>
    </div>
{/if}
