<script lang="ts">
import { enhance } from "$app/forms";
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

let submitting = $state(false);
const enhanceSubmit: SubmitFunction = () => {
    submitting = true;
    return async ({ update }) => {
        await update({ reset: false });
        submitting = false;
    };
};

// 어떤 항목을 펼쳐 두었는지. 본문이 길어 기본은 접어 둔다.
let expanded = $state<Record<string, boolean>>({});
// 필수 항목이 모두 체크됐는지 — 제출 버튼 활성화에 쓴다(서버도 다시 검증한다).
let checked = $state<Record<string, boolean>>({});
type TermItem = PageData["terms"][number];
const requiredKeys = $derived(data.terms.filter((item: TermItem) => item.required).map((item: TermItem) => item.key));
const canSubmit = $derived(requiredKeys.every((k: string) => checked[k]));

function toggleAll(value: boolean) {
    const next: Record<string, boolean> = {};
    for (const item of data.terms) next[item.key] = value;
    checked = next;
}
</script>

{#if skinHtmlEffective}
    <!-- 커스텀 스킨 — 서버가 가져와 sanitize 한 HTML. 사용자 입력은 이 슬롯에 들어오지 않는다. -->
    <!-- eslint-disable-next-line svelte/no-at-html-tags -->
    {@html skinHtmlEffective}
{:else}
    <div class="fixed top-4 right-4 z-40"><LocaleToggle /></div>
    <div class="flex min-h-screen items-center justify-center bg-gray-50 p-4">
        <div class="w-full max-w-2xl space-y-6 rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
            <div>
                <h1 class="text-2xl font-bold text-gray-900">{t("terms.title")}</h1>
                <p class="mt-1 text-sm leading-6 text-gray-500">{t("terms.subtitle")}</p>
            </div>

            <FormError message={err} />

            <form method="POST" use:enhance={enhanceSubmit} class="space-y-4">
                <div class="flex justify-end">
                    <button type="button" onclick={() => toggleAll(true)} class="text-xs font-medium text-blue-600 hover:underline">
                        {t("terms.agree_all")}
                    </button>
                </div>

                {#each data.terms as item (item.key)}
                    <div class="rounded-xl border border-gray-200">
                        <div class="flex items-start gap-3 px-4 py-3">
                            <input id={`terms-${item.key}`} type="checkbox" name="termsKey" value={item.key} bind:checked={checked[item.key]} class="mt-0.5 rounded border-gray-300" />
                            <div class="min-w-0 flex-1">
                                <label for={`terms-${item.key}`} class="text-sm font-medium text-gray-900">
                                    {item.title}
                                    {#if item.required}
                                        <span class="ml-1 text-xs font-normal text-red-600">{t("terms.required_mark")}</span>
                                    {:else}
                                        <span class="ml-1 text-xs font-normal text-gray-400">{t("terms.optional_mark")}</span>
                                    {/if}
                                </label>
                                <button type="button" onclick={() => (expanded[item.key] = !expanded[item.key])} class="mt-0.5 block text-xs text-gray-500 hover:underline">
                                    {expanded[item.key] ? t("terms.collapse") : t("terms.expand")}
                                </button>
                            </div>
                        </div>
                        {#if expanded[item.key]}
                            <!-- 본문은 서버에서 이스케이프 후 마크다운 부분집합만 서식화한 것이다
                                 (renderTermsBody) — 원본 HTML 이 살아남을 수 없어 안전하다. -->
                            <div class="terms-body max-h-72 overflow-y-auto border-t border-gray-100 px-4 py-3 text-sm leading-relaxed text-gray-700">
                                <!-- eslint-disable-next-line svelte/no-at-html-tags -->
                                {@html item.bodyHtml}
                            </div>
                        {/if}
                    </div>
                {/each}

                <button type="submit" disabled={submitting || !canSubmit} class="w-full rounded-lg bg-blue-600 py-2.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-60">
                    {submitting ? t("common.processing") : t("terms.submit")}
                </button>
                {#if !canSubmit}
                    <p class="text-center text-xs text-gray-500">{t("terms.required_hint")}</p>
                {/if}
            </form>
        </div>
    </div>
{/if}

<style>
/* 렌더된 약관 본문의 기본 서식. 본문은 h2~h4 / p / ul / strong / a 만 나온다. */
.terms-body :global(h2),
.terms-body :global(h3),
.terms-body :global(h4) {
    margin: 1em 0 0.4em;
    font-weight: 600;
}
.terms-body :global(h2) {
    font-size: 1rem;
}
.terms-body :global(h3),
.terms-body :global(h4) {
    font-size: 0.9375rem;
}
.terms-body :global(p) {
    margin: 0.5em 0;
}
.terms-body :global(ul) {
    margin: 0.5em 0;
    padding-left: 1.25em;
    list-style: disc;
}
.terms-body :global(a) {
    color: #2563eb;
    text-decoration: underline;
}
</style>
