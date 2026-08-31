<script lang="ts">
import { page } from "$app/state";
import { resolve } from "$app/paths";
import { t } from "$lib/i18n.svelte";

const status = $derived(page.status);
const message = $derived(page.error?.message ?? "");

const titleKey = $derived(status === 404 ? "error_page.not_found" : status === 403 ? "error_page.forbidden" : status === 503 ? "error_page.unavailable" : "error_page.generic");
const title = $derived(t(titleKey));
</script>

<div class="flex min-h-screen items-center justify-center bg-gray-50 p-4">
    <div class="w-full max-w-md space-y-6 rounded-2xl border border-gray-200 bg-white p-8 text-center shadow-sm">
        <div>
            <p class="text-5xl font-bold text-gray-300">{status}</p>
            <h1 class="mt-4 text-2xl font-bold text-gray-900">{title}</h1>
            {#if message && message !== title}
                <p class="mt-2 text-sm text-gray-500">{message}</p>
            {/if}
        </div>
        <a href={resolve("/")} class="block rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-700">
            {t("error_page.home")}
        </a>
    </div>
</div>
