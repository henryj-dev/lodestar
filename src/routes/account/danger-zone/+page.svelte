<script lang="ts">
import { enhance } from "$app/forms";
import type { ActionData, PageData } from "./$types";
import { t } from "$lib/i18n.svelte";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();

const formError = $derived((form as { error?: string } | null)?.error ?? null);
let confirmed = $state(false);
</script>

<div class="min-h-screen bg-gray-50 p-4">
    <div class="mx-auto max-w-lg">
        <div class="mb-6">
            <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
            <a href="/" class="text-sm text-gray-500 hover:underline">← {t("mfa_manage.back_to_home")}</a>
        </div>

        <div class="rounded-2xl border border-red-200 bg-white p-8 shadow-sm">
            <h1 class="mb-1 text-2xl font-bold text-red-700">{t("account.danger_zone.title")}</h1>
            <p class="mb-6 text-sm text-gray-500">{t("account.danger_zone.subtitle")}</p>

            {#if formError}
                <div class="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                    {formError}
                </div>
            {/if}

            <div class="mb-6 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                <p class="font-medium">{t("account.danger_zone.warning_title")}</p>
                <p class="mt-1">{t("account.danger_zone.warning_immediate")}</p>
                <p class="mt-1">{t("account.danger_zone.warning_recovery")}</p>
            </div>

            <form method="POST" action="?/requestDeletion" class="space-y-4" use:enhance>
                {#if data.hasPassword}
                    <div>
                        <label for="dz-password" class="block text-sm font-medium text-gray-700">
                            {t("account.danger_zone.password_label")}
                        </label>
                        <input
                            type="password"
                            name="password"
                            id="dz-password"
                            autocomplete="current-password"
                            class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-red-500 focus:ring-red-500 focus:outline-none sm:text-sm" />
                    </div>
                {/if}

                {#if data.hasTotp}
                    <div>
                        <label for="dz-totp" class="block text-sm font-medium text-gray-700">
                            {t("account.danger_zone.totp_label")}
                        </label>
                        <input
                            type="text"
                            name="totp"
                            id="dz-totp"
                            inputmode="numeric"
                            autocomplete="one-time-code"
                            placeholder="000000"
                            class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-red-500 focus:ring-red-500 focus:outline-none sm:text-sm" />
                    </div>
                {/if}

                <label class="flex items-start gap-2 text-sm text-gray-700">
                    <input type="checkbox" bind:checked={confirmed} class="mt-0.5 rounded border-gray-300 text-red-600 focus:ring-red-500" />
                    <span>{t("account.danger_zone.confirm_label")}</span>
                </label>

                <button
                    type="submit"
                    disabled={!confirmed}
                    class="flex w-full justify-center rounded-md border border-transparent bg-red-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-red-700 focus:ring-2 focus:ring-red-500 focus:ring-offset-2 focus:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                    onclick={(e: MouseEvent) => {
                        if (!confirm(t("account.danger_zone.confirm_dialog"))) {
                            e.preventDefault();
                        }
                    }}>
                    {t("account.danger_zone.submit")}
                </button>
            </form>
        </div>
    </div>
</div>
