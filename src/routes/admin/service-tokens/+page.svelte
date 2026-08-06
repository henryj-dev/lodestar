<script lang="ts">
import { enhance } from "$app/forms";
import type { ActionData, PageData } from "./$types";
import { t } from "$lib/i18n.svelte";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();

const err = $derived((form as { error?: string } | null)?.error ?? null);
// 평문 토큰은 생성 응답에만 담겨 온다 — 화면을 벗어나면 다시 볼 수 없다.
const issued = $derived((form as { created?: boolean; token?: string; name?: string } | null)?.created ? (form as { token: string; name: string }) : null);

const dateFormatter = new Intl.DateTimeFormat("ko-KR", { dateStyle: "medium", timeStyle: "short" });

function isExpired(d: Date | null): boolean {
    return d !== null && d.getTime() <= Date.now();
}
</script>

<div class="max-w-4xl space-y-6">
    <div>
        <h1 class="text-2xl font-bold text-gray-900">{t("service_tokens.title")}</h1>
        <p class="mt-1 text-sm text-gray-500">{t("service_tokens.subtitle")}</p>
    </div>

    {#if err}
        <div class="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{err}</div>
    {/if}

    {#if issued}
        <div class="rounded-xl border border-green-200 bg-green-50 p-4">
            <p class="mb-1 font-semibold text-green-900">{t("service_tokens.created_title")} — {issued.name}</p>
            <p class="mb-2 text-xs text-green-700">{t("service_tokens.created_hint")}</p>
            <code class="block rounded bg-white px-3 py-2 font-mono text-sm break-all text-gray-800">{issued.token}</code>
        </div>
    {/if}

    <section class="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
        <div class="mb-4 flex items-center justify-between">
            <h2 class="text-sm font-semibold text-gray-700">{t("service_tokens.list_title")}</h2>
            <span class="text-xs text-gray-400">{t("service_tokens.count", { count: data.tokens.length })}</span>
        </div>

        {#if data.tokens.length > 0}
            <div class="mb-4 divide-y divide-gray-100 rounded-lg border border-gray-200">
                {#each data.tokens as tk (tk.id)}
                    <div class="flex flex-wrap items-center justify-between gap-2 px-4 py-3 text-sm">
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="font-medium text-gray-900">{tk.name}</span>
                            <code class="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-xs text-gray-500">{tk.tokenPrefix}…</code>
                            {#each tk.scopes.split(" ").filter(Boolean) as sc (sc)}
                                <span class="rounded-full bg-blue-50 px-1.5 py-0.5 font-mono text-xs text-blue-700">{sc}</span>
                            {/each}
                            {#if isExpired(tk.expiresAt)}
                                <span class="rounded-full bg-amber-100 px-1.5 py-0.5 text-xs text-amber-700">{t("service_tokens.expired")}</span>
                            {:else if tk.expiresAt}
                                <span class="text-xs text-gray-400">~{dateFormatter.format(tk.expiresAt)}</span>
                            {/if}
                        </div>
                        <div class="flex items-center gap-3">
                            <span class="text-xs text-gray-400">
                                {#if tk.lastUsedAt}
                                    {t("service_tokens.last_used")}: {dateFormatter.format(tk.lastUsedAt)}
                                {:else}
                                    {t("service_tokens.never_used")}
                                {/if}
                            </span>
                            <form method="POST" action="?/revoke" use:enhance>
                                <input type="hidden" name="csrf" value={data.csrfToken} />
                                <input type="hidden" name="tokenId" value={tk.id} />
                                <button
                                    type="submit"
                                    class="text-xs text-red-400 hover:text-red-600"
                                    onclick={(e) => {
                                        if (!confirm(t("service_tokens.revoke_confirm", { name: tk.name }))) e.preventDefault();
                                    }}>{t("common.delete")}</button>
                            </form>
                        </div>
                    </div>
                {/each}
            </div>
        {:else}
            <p class="mb-4 text-sm text-gray-400">{t("service_tokens.empty")}</p>
        {/if}

        <form method="POST" action="?/create" use:enhance class="grid grid-cols-1 gap-3 border-t border-gray-100 pt-4 sm:grid-cols-2">
            <input type="hidden" name="csrf" value={data.csrfToken} />
            <div>
                <label for="tk-name" class="block text-xs font-medium text-gray-700">{t("service_tokens.name_label")}</label>
                <input
                    id="tk-name"
                    type="text"
                    name="name"
                    required
                    placeholder={t("service_tokens.name_placeholder")}
                    class="mt-1 w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
            </div>
            <div>
                <label for="tk-expires" class="block text-xs font-medium text-gray-700">{t("service_tokens.expires_label")}</label>
                <input id="tk-expires" type="datetime-local" name="expiresAt" class="mt-1 w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm" />
            </div>
            <fieldset class="sm:col-span-2">
                <legend class="block text-xs font-medium text-gray-700">{t("service_tokens.scopes_label")}</legend>
                <div class="mt-1 flex flex-wrap gap-3">
                    {#each data.availableScopes as sc (sc)}
                        <label class="flex items-center gap-1.5 text-xs text-gray-700">
                            <input type="checkbox" name="scopes" value={sc} class="rounded" />
                            <code class="font-mono">{sc}</code>
                        </label>
                    {/each}
                </div>
            </fieldset>
            <div class="flex justify-end sm:col-span-2">
                <button type="submit" class="rounded-md bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700">{t("service_tokens.add")}</button>
            </div>
        </form>
    </section>

    <p class="text-xs text-gray-500">{t("service_tokens.env_note")}</p>
</div>
