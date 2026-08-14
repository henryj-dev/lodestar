<script lang="ts">
import { enhance } from "$app/forms";
import { t } from "$lib/i18n.svelte";
import FormError from "$lib/components/FormError.svelte";
import type { ActionData, PageData } from "./$types";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();

function linkUrl(slug: string): string {
    // 연결도 로그인과 같은 시작점을 쓴다. 콜백이 "이미 로그인된 사용자" 를 보고
    // 기존 계정에 연결한다.
    return `/auth/oauth/${encodeURIComponent(slug)}/start?redirectTo=${encodeURIComponent("/account/connections")}`;
}

function formatDate(value: Date | string | null): string {
    if (!value) return "-";
    return new Date(value).toISOString().slice(0, 10);
}
</script>

<div class="mx-auto max-w-3xl space-y-6 p-6">
    <div>
        <h1 class="text-2xl font-bold text-gray-900">{t("connections.title")}</h1>
        <p class="mt-1 text-sm text-gray-500">{t("connections.subtitle")}</p>
    </div>

    <FormError message={form?.error} class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" />

    {#if form?.unlinked}
        <div class="rounded-xl border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-800">{t("connections.unlinked")}</div>
    {/if}

    {#if data.justLinked}
        <div class="rounded-xl border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-800">{t("connections.linked_success")}</div>
    {/if}

    {#if data.linkError}
        <div class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{t("connections.err_already_linked_elsewhere")}</div>
    {/if}

    <section class="space-y-3">
        <h2 class="text-sm font-semibold text-gray-700">{t("connections.linked_heading")}</h2>

        {#if data.connections.length === 0}
            <div class="rounded-2xl border border-dashed border-gray-300 bg-white p-8 text-center text-sm text-gray-500">
                {t("connections.none_linked")}
            </div>
        {:else}
            {#each data.connections as conn (conn.id)}
                <div class="flex items-center justify-between gap-4 rounded-2xl border border-gray-200 bg-white p-4">
                    <div class="min-w-0">
                        <p class="font-medium text-gray-900">{conn.label}</p>
                        <p class="mt-0.5 truncate text-xs text-gray-500">
                            {conn.email ?? t("connections.no_email")}
                            · {t("connections.linked_at", { date: formatDate(conn.linkedAt) })}
                        </p>
                    </div>

                    {#if conn.unlinkable}
                        <form method="POST" action="?/unlink" use:enhance>
                            <input type="hidden" name="csrf" value={data.csrf} />
                            <input type="hidden" name="id" value={conn.id} />
                            <button type="submit" class="shrink-0 rounded-lg border border-red-300 px-3 py-1.5 text-sm text-red-700 hover:bg-red-50">
                                {t("connections.unlink")}
                            </button>
                        </form>
                    {:else}
                        <span class="shrink-0 text-xs text-gray-400">{t("connections.managed_by_admin")}</span>
                    {/if}
                </div>
            {/each}
        {/if}
    </section>

    {#if data.availableProviders.length > 0}
        <section class="space-y-3">
            <h2 class="text-sm font-semibold text-gray-700">{t("connections.available_heading")}</h2>
            {#each data.availableProviders as provider (provider.slug)}
                <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
                <a href={linkUrl(provider.slug)} data-sveltekit-reload class="flex items-center justify-between gap-4 rounded-2xl border border-gray-200 bg-white p-4 transition hover:border-blue-400">
                    <span class="font-medium text-gray-900">{provider.label}</span>
                    <span class="shrink-0 text-sm text-blue-600">{t("connections.link")}</span>
                </a>
            {/each}
        </section>
    {/if}
</div>
