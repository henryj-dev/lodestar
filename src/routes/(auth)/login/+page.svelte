<script lang="ts">
import { enhance } from "$app/forms";
import { goto } from "$app/navigation";
import { resolve } from "$app/paths";
import { onMount } from "svelte";
import type { SubmitFunction } from "@sveltejs/kit";
import { t } from "$lib/i18n.svelte";
import FormError from "$lib/components/FormError.svelte";
import LocaleToggle from "$lib/components/LocaleToggle.svelte";
import SocialLoginButtons from "$lib/components/SocialLoginButtons.svelte";
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
    const scripts: HTMLScriptElement[] = [];
    for (const src of ["/api/skin-scripts", "/api/webauthn/passkey-client"]) {
        const s = document.createElement("script");
        s.src = src;
        document.head.appendChild(s);
        scripts.push(s);
    }
    return () => {
        scripts.forEach((s) => {
            if (s.parentNode) s.parentNode.removeChild(s);
        });
    };
});

let passkeyLoading = $state(false);
let passkeyError = $state("");

function buildAuthSuffix(redirectTo: string | null, skinHint: string | null): string {
    const parts: string[] = [];
    if (redirectTo) parts.push(`redirectTo=${encodeURIComponent(redirectTo)}`);
    if (skinHint) parts.push(`skinHint=${encodeURIComponent(skinHint)}`);
    return parts.length ? `?${parts.join("&")}` : "";
}

const authLinkSuffix = $derived(buildAuthSuffix(data.redirectTo, data.skinHint));

/**
 * 소셜 콜백 실패 사유. 알 수 없는 값이 쿼리로 들어와도 임의 문자열이 화면에 뜨지
 * 않도록, 아는 키만 번역하고 나머지는 일반 메시지로 떨어뜨린다.
 */
const SOCIAL_ERROR_KEYS = new Set([
    "state_expired",
    "state_mismatch",
    "provider_denied",
    "missing_code",
    "provider_unavailable",
    "exchange_failed",
    "link_required",
    "link_expired",
    "signup_disabled",
    "account_disabled",
    "account_deleting",
    "no_email",
]);

const socialErrorMessage = $derived(data.socialError ? t(`social.err_${SOCIAL_ERROR_KEYS.has(data.socialError) ? data.socialError : "generic"}`) : "");

async function loginWithPasskey() {
    passkeyError = "";
    passkeyLoading = true;
    try {
        // 1. 인증 옵션 요청
        const optRes = await fetch("/api/webauthn/authenticate/options", { method: "POST" });
        if (!optRes.ok) throw new Error((await optRes.text()) || t("login.passkey_options_failed"));
        const options = await optRes.json();

        // 2. 브라우저 패스키 인증 (클라이언트 전용)
        const { startAuthentication } = await import("@simplewebauthn/browser");
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const authResponse = await startAuthentication({ optionsJSON: options as any });

        // 3. 검증 요청 — SAML/OIDC 플로우의 redirectTo 를 함께 전달
        const pendingRedirect = form?.redirectTo ?? data.redirectTo ?? "";
        const verRes = await fetch("/api/webauthn/authenticate/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ...authResponse, _redirectTo: pendingRedirect }),
        });

        if (!verRes.ok) throw new Error((await verRes.text()) || t("login.passkey_verify_failed"));

        const { redirectTo } = (await verRes.json()) as { redirectTo?: string };
        // eslint-disable-next-line svelte/no-navigation-without-resolve
        await goto(redirectTo ?? "/");
    } catch (err: unknown) {
        const e = err as { name?: string; message?: string };
        if (e?.name === "NotAllowedError") {
            passkeyError = t("login.passkey_cancelled");
        } else {
            passkeyError = e?.message ?? t("login.passkey_failed");
        }
    } finally {
        passkeyLoading = false;
    }
}
</script>

{#if skinHtmlEffective && !form?.recovery}
    <!-- 커스텀 스킨 — 에러/성공 메시지는 스킨 내부 #flash 로 표시됨.
         단, soft-delete 복구(form.recovery) 케이스는 스킨에 복구 UI 가 없으므로
         기본 스킨의 복구 패널로 강제 폴백한다. -->
    {#if !data.dbReady && data.runtimeError}
        <div class="fixed top-4 left-1/2 z-50 -translate-x-1/2 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900 shadow-lg">
            {data.runtimeError}
        </div>
    {/if}
    <!--
        스킨 HTML 출처: 관리자(admin)가 등록한 외부 URL을 서버측에서 fetch 하여 주입한다.
        XSS 가능성은 인지하고 있으며, CSP(script-src 화이트리스트), CSRF 토큰, form-action,
        그리고 admin-only 등록 권한으로 영향을 제한한다. 사용자 입력은 절대 이 슬롯에 들어오지 않는다.
    -->
    <!-- eslint-disable-next-line svelte/no-at-html-tags -->
    {@html skinHtmlEffective}
{:else}
    <!-- 기본 스킨 -->
    <div class="fixed top-4 right-4 z-40"><LocaleToggle /></div>
    <div class="flex min-h-screen items-center justify-center bg-gray-50 p-4">
        <div class="w-full max-w-105 rounded-2xl border border-gray-200 bg-white p-8 shadow-sm">
            <div class="mb-6 space-y-2 text-center">
                <h1 class="text-2xl font-bold text-gray-900">{t("app.title")}</h1>
                <p class="text-sm leading-6 text-gray-500">{t("login.subtitle")}</p>
            </div>

            {#if !data.dbReady && data.runtimeError}
                <div class="mb-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                    {data.runtimeError}
                </div>
            {/if}

            {#if data.registered}
                <div class="mb-4 rounded-xl border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-800">
                    {t("login.registered_success")}
                </div>
            {/if}

            {#if data.passwordReset}
                <div class="mb-4 rounded-xl border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-800">
                    {t("login.password_reset_success")}
                </div>
            {/if}

            {#if data.deletionRequested}
                <div class="mb-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                    {t("login.deletion_requested_notice")}
                </div>
            {/if}

            <FormError message={form?.error} class="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" />

            <FormError message={passkeyError} class="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" />

            <FormError message={socialErrorMessage} class="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" />

            {#if form?.recovery}
                <!-- 탈퇴 예정 계정 복구 확인. 본인 확인을 위해 비밀번호를 다시 입력한다. -->
                <div class="mb-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                    {t("login.recovery_desc")}
                </div>

                <form method="POST" use:enhance={enhanceSubmit} class="space-y-4">
                    <input type="hidden" name="redirectTo" value={form?.redirectTo ?? data.redirectTo ?? ""} />
                    <input type="hidden" name="username" value={form?.username ?? ""} />
                    <input type="hidden" name="recover" value="1" />

                    <div>
                        <label for="recover-password" class="block text-sm font-medium text-gray-700">
                            {t("login.recovery_password_label")}
                        </label>
                        <input
                            type="password"
                            name="password"
                            id="recover-password"
                            required
                            autocomplete="current-password"
                            class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-blue-500 focus:ring-blue-500 focus:outline-none sm:text-sm" />
                    </div>

                    <button
                        type="submit"
                        disabled={submitting}
                        class="flex w-full items-center justify-center gap-2 rounded-md border border-transparent bg-blue-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:outline-none disabled:opacity-60">
                        {#if submitting}
                            <svg class="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                            </svg>
                            {t("common.processing")}
                        {:else}
                            {t("login.recovery_confirm")}
                        {/if}
                    </button>
                </form>

                <div class="mt-5 flex justify-center gap-4 text-sm text-gray-500">
                    <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
                    <a href={resolve("/login") + authLinkSuffix} class="hover:text-blue-600">{t("login.recovery_cancel")}</a>
                </div>
            {:else}
                <form method="POST" use:enhance={enhanceSubmit} class="space-y-4">
                    <input type="hidden" name="redirectTo" value={form?.redirectTo ?? data.redirectTo ?? ""} />

                    <div>
                        <label for="username" class="block text-sm font-medium text-gray-700">
                            {t("login.username")}
                        </label>
                        <input
                            type="text"
                            name="username"
                            id="username"
                            required
                            autocomplete="username"
                            value={form?.username ?? data.loginHint ?? ""}
                            class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-blue-500 focus:ring-blue-500 focus:outline-none sm:text-sm" />
                    </div>

                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-700">
                            {t("login.password")}
                        </label>
                        <input
                            type="password"
                            name="password"
                            id="password"
                            required
                            autocomplete="current-password"
                            class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-blue-500 focus:ring-blue-500 focus:outline-none sm:text-sm" />
                    </div>

                    <button
                        type="submit"
                        disabled={submitting}
                        class="flex w-full items-center justify-center gap-2 rounded-md border border-transparent bg-blue-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:outline-none disabled:opacity-60">
                        {#if submitting}
                            <svg class="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                            </svg>
                            {t("common.processing")}
                        {:else}
                            {t("login.submit")}
                        {/if}
                    </button>
                </form>

                <div class="mt-4 flex items-center gap-3">
                    <div class="h-px flex-1 bg-gray-200"></div>
                    <span class="text-xs text-gray-400">{t("login.or")}</span>
                    <div class="h-px flex-1 bg-gray-200"></div>
                </div>

                <button
                    type="button"
                    onclick={loginWithPasskey}
                    disabled={passkeyLoading}
                    class="mt-4 flex w-full items-center justify-center gap-2 rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow-sm transition hover:bg-gray-50 disabled:opacity-60">
                    {#if passkeyLoading}
                        <svg class="h-4 w-4 animate-spin text-gray-500" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                        </svg>
                        {t("login.passkey_authenticating")}
                    {:else}
                        <svg class="h-4 w-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path
                                stroke-linecap="round"
                                stroke-linejoin="round"
                                stroke-width="2"
                                d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                        {t("login.passkey_login")}
                    {/if}
                </button>

                <SocialLoginButtons providers={data.socialProviders ?? []} redirectTo={data.redirectTo} skinHint={data.skinHint} />

                <div class="mt-5 flex justify-center gap-4 text-sm text-gray-500">
                    <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
                    <a href={resolve("/signup") + authLinkSuffix} class="hover:text-blue-600">{t("signup.title")}</a>
                    <span>·</span>
                    <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
                    <a href={resolve("/find-id") + authLinkSuffix} class="hover:text-blue-600">{t("find_id.title")}</a>
                    <span>·</span>
                    <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -->
                    <a href={resolve("/find-password") + authLinkSuffix} class="hover:text-blue-600">{t("find_password.title")}</a>
                </div>
            {/if}
        </div>
    </div>
{/if}
