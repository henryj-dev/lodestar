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

let submitting = $state(false);
const enhanceSubmit: SubmitFunction = () => {
    submitting = true;
    return async ({ update }) => {
        await update({ reset: false });
        submitting = false;
    };
};

const skinHtmlEffective = $derived((form as { skinHtml?: string | null } | null)?.skinHtml ?? data.skinHtml);

onMount(() => {
    if (!skinHtmlEffective) return;
    const s = document.createElement("script");
    s.src = "/api/skin-scripts";
    document.head.appendChild(s);
    return () => {
        if (s.parentNode) s.parentNode.removeChild(s);
    };
});

function buildAuthSuffix(redirectTo: string | null, skinHint: string | null): string {
    const parts: string[] = [];
    if (redirectTo) parts.push(`redirectTo=${encodeURIComponent(redirectTo)}`);
    if (skinHint) parts.push(`skinHint=${encodeURIComponent(skinHint)}`);
    return parts.length ? `?${parts.join("&")}` : "";
}

const authLinkSuffix = $derived(buildAuthSuffix(data.redirectTo ?? null, data.skinHint ?? null));

// 연합 회원가입 모드(§2.8) — 외부 IdP 인증을 마쳤지만 매칭 계정이 없는 상태.
// 서버가 서명 쿠키에서 읽은 프로필만 내려주며, 폼은 사용자가 정할 수 있는 값만 다룬다.
const fed = $derived(data.federated ?? null);
</script>

{#if skinHtmlEffective}
    <!-- eslint-disable-next-line svelte/no-at-html-tags -->
    {@html skinHtmlEffective}
{:else}
    <div class="fixed top-4 right-4 z-40"><LocaleToggle /></div>
    <div class="flex min-h-screen items-center justify-center bg-gray-50 p-4">
        <div class="w-full max-w-md space-y-6 rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
            <div>
                <h1 class="text-2xl font-bold text-gray-900">{t("signup.title")}</h1>
                <p class="mt-1 text-sm text-gray-500">
                    {#if fed}
                        {t("signup.federated_subtitle", { provider: fed.providerLabel })}
                    {:else}
                        {t("signup.subtitle")}
                    {/if}
                </p>
            </div>

            {#if fed}
                <div class="rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-900">
                    {t("signup.federated_notice", { provider: fed.providerLabel })}
                </div>
            {/if}

            <FormError message={form?.error} />

            <form method="POST" use:enhance={enhanceSubmit} class="space-y-4">
                {#if fed}
                    <!-- 이 표식만으로 서버가 연합 분기를 탄다. 실제 신원(provider/subject)은
                         폼이 아니라 서명 쿠키에서 읽으므로 여기에 담지 않는다. -->
                    <input type="hidden" name="federated" value="1" />
                {/if}

                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700">{t("signup.username_label")}</label>
                    <input
                        id="username"
                        name="username"
                        type="text"
                        required
                        readonly={fed ? !fed.allowUsernameEdit : false}
                        value={form?.username ?? fed?.suggestedUsername ?? ""}
                        autocomplete="username"
                        placeholder={t("signup.username_placeholder")}
                        class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm read-only:bg-gray-100 read-only:text-gray-500 focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="email" class="block text-sm font-medium text-gray-700">{t("signup.email_label")}</label>
                    <input
                        id="email"
                        name="email"
                        type="email"
                        required
                        readonly={fed?.emailLocked ?? false}
                        value={fed?.email ?? ""}
                        autocomplete="email"
                        class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm read-only:bg-gray-100 read-only:text-gray-500 focus:border-blue-500 focus:outline-none" />
                    {#if fed?.emailLocked}
                        <!-- 잠긴 이유를 밝힌다. 서버는 이 필드의 제출값을 어차피 무시한다. -->
                        <p class="mt-1 text-xs text-gray-500">{t("signup.federated_email_locked", { provider: fed.providerLabel })}</p>
                    {:else if fed}
                        <p class="mt-1 text-xs text-gray-500">{t("signup.federated_email_verify_notice")}</p>
                    {/if}
                </div>

                {#if !fed || fed.allowPassword}
                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-700">
                            {t("signup.password_label")}
                            {#if fed}<span class="ml-1 font-normal text-gray-400">{t("signup.federated_password_optional")}</span>{/if}
                        </label>
                        <input
                            id="password"
                            name="password"
                            type="password"
                            required={!fed}
                            autocomplete="new-password"
                            placeholder={t("signup.password_placeholder")}
                            class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                        {#if fed}
                            <p class="mt-1 text-xs text-gray-500">{t("signup.federated_password_hint", { provider: fed.providerLabel })}</p>
                        {/if}
                    </div>
                    <div>
                        <label for="confirmPassword" class="block text-sm font-medium text-gray-700">{t("signup.confirm_password_label")}</label>
                        <input
                            id="confirmPassword"
                            name="confirmPassword"
                            type="password"
                            required={!fed}
                            autocomplete="new-password"
                            class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                    </div>
                {/if}

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
                    {:else if fed}
                        {t("signup.federated_submit")}
                    {:else}
                        {t("signup.submit")}
                    {/if}
                </button>
            </form>

            <p class="text-center text-sm text-gray-500">
                {t("signup.have_account")}
                <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
                <a href={resolve("/login") + authLinkSuffix} class="text-blue-600 hover:underline">{t("login.submit")}</a>
            </p>
        </div>
    </div>
{/if}
