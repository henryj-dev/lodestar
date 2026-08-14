<script lang="ts">
import { enhance } from "$app/forms";
import { t } from "$lib/i18n.svelte";
import FormError from "$lib/components/FormError.svelte";
import type { ActionData, PageData } from "./$types";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();

let creating = $state(false);
let editingId = $state<string | null>(null);

/** 프리셋을 고르면 스코프 안내와 프로바이더별 추가 필드가 달라진다. */
let newProviderType = $state("naver");

type Preset = PageData["presets"][number];

const presetById = $derived(new Map<string, Preset>(data.presets.map((p: Preset) => [p.id, p])));
const newPreset = $derived(presetById.get(newProviderType));

function callbackUrl(slug: string): string {
    return `${data.callbackOrigin}/auth/oauth/${slug || "<slug>"}/callback`;
}

/** Microsoft/일반 OIDC 만 디렉터리·discovery 입력이 의미가 있다. */
function needsDirectoryTenant(type: string): boolean {
    return type === "microsoft";
}
function needsDiscoveryUrl(type: string): boolean {
    return type === "oidc";
}
</script>

<div class="space-y-6">
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">{t("social_admin.title")}</h1>
            <p class="mt-1 text-sm text-gray-500">{t("social_admin.subtitle")}</p>
        </div>
        <button type="button" onclick={() => (creating = !creating)} class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">
            {creating ? t("common.cancel") : t("social_admin.add")}
        </button>
    </div>

    {#if !data.signingKeyReady}
        <div class="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
            {t("social_admin.signing_key_warning")}
        </div>
    {/if}

    <FormError message={form?.error} class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" />

    {#if creating}
        <form method="POST" action="?/create" use:enhance class="space-y-4 rounded-2xl border border-gray-200 bg-white p-6">
            <input type="hidden" name="csrf" value={data.csrf} />
            <h2 class="text-lg font-semibold text-gray-900">{t("social_admin.add")}</h2>

            <div class="grid gap-4 sm:grid-cols-2">
                <label class="block text-sm">
                    <span class="font-medium text-gray-700">{t("social_admin.provider_type")}</span>
                    <select name="providerType" bind:value={newProviderType} class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none">
                        {#each data.presets as preset (preset.id)}
                            <option value={preset.id}>{preset.label}</option>
                        {/each}
                    </select>
                </label>

                <label class="block text-sm">
                    <span class="font-medium text-gray-700">{t("social_admin.name")}</span>
                    <input name="name" required class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                </label>

                <label class="block text-sm sm:col-span-2">
                    <span class="font-medium text-gray-700">{t("social_admin.slug")}</span>
                    <input
                        name="slug"
                        required
                        value={newProviderType}
                        pattern="[a-z0-9][a-z0-9-]&#123;1,30&#125;[a-z0-9]"
                        class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                    <span class="mt-1 block text-xs text-gray-500">{t("social_admin.slug_hint")}</span>
                </label>

                <label class="block text-sm">
                    <span class="font-medium text-gray-700">Client ID</span>
                    <input name="clientId" required class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                </label>

                <label class="block text-sm">
                    <span class="font-medium text-gray-700">Client Secret</span>
                    <input
                        name="clientSecret"
                        type="password"
                        required
                        autocomplete="new-password"
                        class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                </label>

                {#if needsDiscoveryUrl(newProviderType)}
                    <label class="block text-sm sm:col-span-2">
                        <span class="font-medium text-gray-700">Discovery URL</span>
                        <input
                            name="discoveryUrl"
                            type="url"
                            placeholder="https://idp.example.com/.well-known/openid-configuration"
                            class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                    </label>
                {/if}

                {#if needsDirectoryTenant(newProviderType)}
                    <label class="block text-sm sm:col-span-2">
                        <span class="font-medium text-gray-700">{t("social_admin.directory_tenant")}</span>
                        <input
                            name="directoryTenant"
                            placeholder="common"
                            class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                        <span class="mt-1 block text-xs text-gray-500">{t("social_admin.directory_tenant_hint")}</span>
                    </label>
                {/if}

                <label class="block text-sm sm:col-span-2">
                    <span class="font-medium text-gray-700">{t("social_admin.scopes")}</span>
                    <input
                        name="scopes"
                        placeholder={newPreset?.defaultScopes.join(" ") || t("social_admin.scopes_none")}
                        class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                    <span class="mt-1 block text-xs text-gray-500">{t("social_admin.scopes_hint")}</span>
                    {#if newProviderType === "kakao"}
                        <span class="mt-1 block text-xs text-amber-700">{t("social_admin.kakao_email_hint")}</span>
                    {/if}
                </label>

                <label class="block text-sm">
                    <span class="font-medium text-gray-700">{t("social_admin.provisioning_mode")}</span>
                    <select name="provisioningMode" class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none">
                        <option value="signup_form">{t("social_admin.mode_signup_form")}</option>
                        <option value="jit">{t("social_admin.mode_jit")}</option>
                        <option value="deny">{t("social_admin.mode_deny")}</option>
                    </select>
                    <span class="mt-1 block text-xs text-gray-500">{t("social_admin.provisioning_mode_hint")}</span>
                </label>

                <label class="flex items-start gap-2 pt-6 text-sm">
                    <input type="checkbox" name="autoLinkVerifiedEmail" value="true" class="mt-0.5 rounded border-gray-300" />
                    <span>
                        <span class="font-medium text-gray-700">{t("social_admin.auto_link")}</span>
                        <span class="mt-0.5 block text-xs text-amber-700">{t("social_admin.auto_link_warning")}</span>
                    </span>
                </label>
            </div>

            <div class="rounded-lg bg-gray-50 px-4 py-3 text-xs text-gray-600">
                {t("social_admin.redirect_uri_notice")}
                <code class="mt-1 block font-mono break-all text-gray-900">{callbackUrl(newProviderType)}</code>
            </div>

            <button type="submit" class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">{t("common.save")}</button>
        </form>
    {/if}

    {#if data.providers.length === 0}
        <div class="rounded-2xl border border-dashed border-gray-300 bg-white p-10 text-center text-sm text-gray-500">
            {t("social_admin.empty")}
        </div>
    {:else}
        <div class="space-y-3">
            {#each data.providers as provider (provider.id)}
                <div class="rounded-2xl border border-gray-200 bg-white p-5">
                    <div class="flex items-start justify-between gap-4">
                        <div class="min-w-0">
                            <div class="flex items-center gap-2">
                                <h3 class="truncate font-semibold text-gray-900">{provider.name}</h3>
                                {#if provider.enabled}
                                    <span class="rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800">{t("social_admin.enabled")}</span>
                                {:else}
                                    <span class="rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-600">{t("social_admin.disabled")}</span>
                                {/if}
                            </div>
                            <p class="mt-1 font-mono text-xs break-all text-gray-500">{callbackUrl(provider.slug ?? "")}</p>
                        </div>
                        <div class="flex shrink-0 gap-2">
                            <button
                                type="button"
                                onclick={() => (editingId = editingId === provider.id ? null : provider.id)}
                                class="rounded-lg border border-gray-300 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50">
                                {editingId === provider.id ? t("common.cancel") : t("common.edit")}
                            </button>
                            <form method="POST" action="?/delete" use:enhance>
                                <input type="hidden" name="csrf" value={data.csrf} />
                                <input type="hidden" name="id" value={provider.id} />
                                <button type="submit" class="rounded-lg border border-red-300 px-3 py-1.5 text-sm text-red-700 hover:bg-red-50">{t("common.delete")}</button>
                            </form>
                        </div>
                    </div>

                    {#if editingId === provider.id}
                        <form method="POST" action="?/update" use:enhance class="mt-4 space-y-4 border-t border-gray-100 pt-4">
                            <input type="hidden" name="csrf" value={data.csrf} />
                            <input type="hidden" name="id" value={provider.id} />
                            <input type="hidden" name="providerType" value={provider.providerType} />

                            <div class="grid gap-4 sm:grid-cols-2">
                                <label class="block text-sm">
                                    <span class="font-medium text-gray-700">{t("social_admin.name")}</span>
                                    <input
                                        name="name"
                                        required
                                        value={provider.name}
                                        class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                                </label>

                                <label class="block text-sm">
                                    <span class="font-medium text-gray-700">{t("social_admin.slug")}</span>
                                    <input
                                        name="slug"
                                        required
                                        value={provider.slug ?? ""}
                                        class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                                </label>

                                <label class="block text-sm">
                                    <span class="font-medium text-gray-700">Client ID</span>
                                    <input
                                        name="clientId"
                                        required
                                        value={provider.clientId ?? ""}
                                        class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                                </label>

                                <label class="block text-sm">
                                    <span class="font-medium text-gray-700">Client Secret</span>
                                    <input
                                        name="clientSecret"
                                        type="password"
                                        autocomplete="new-password"
                                        placeholder={provider.hasClientSecret ? t("social_admin.secret_keep") : t("social_admin.secret_unset")}
                                        class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                                </label>

                                {#if needsDiscoveryUrl(provider.providerType)}
                                    <label class="block text-sm sm:col-span-2">
                                        <span class="font-medium text-gray-700">Discovery URL</span>
                                        <input
                                            name="discoveryUrl"
                                            type="url"
                                            value={provider.discoveryUrl}
                                            class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                                    </label>
                                {/if}

                                {#if needsDirectoryTenant(provider.providerType)}
                                    <label class="block text-sm sm:col-span-2">
                                        <span class="font-medium text-gray-700">{t("social_admin.directory_tenant")}</span>
                                        <input
                                            name="directoryTenant"
                                            value={provider.directoryTenant}
                                            class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                                    </label>
                                {/if}

                                <label class="block text-sm sm:col-span-2">
                                    <span class="font-medium text-gray-700">{t("social_admin.scopes")}</span>
                                    <input
                                        name="scopes"
                                        value={provider.scopes}
                                        class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                                </label>

                                <label class="block text-sm">
                                    <span class="font-medium text-gray-700">{t("social_admin.provisioning_mode")}</span>
                                    <select name="provisioningMode" class="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none">
                                        <option value="signup_form" selected={provider.provisioningMode === "signup_form"}>{t("social_admin.mode_signup_form")}</option>
                                        <option value="jit" selected={provider.provisioningMode === "jit"}>{t("social_admin.mode_jit")}</option>
                                        <option value="deny" selected={provider.provisioningMode === "deny"}>{t("social_admin.mode_deny")}</option>
                                    </select>
                                </label>

                                <div class="space-y-2 pt-6 text-sm">
                                    <label class="flex items-start gap-2">
                                        <input type="checkbox" name="autoLinkVerifiedEmail" value="true" checked={provider.autoLinkVerifiedEmail} class="mt-0.5 rounded border-gray-300" />
                                        <span class="font-medium text-gray-700">{t("social_admin.auto_link")}</span>
                                    </label>
                                    <label class="flex items-start gap-2">
                                        <input type="checkbox" name="enabled" value="true" checked={provider.enabled} class="mt-0.5 rounded border-gray-300" />
                                        <span class="font-medium text-gray-700">{t("social_admin.enable")}</span>
                                    </label>
                                </div>
                            </div>

                            <button type="submit" class="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">{t("common.save")}</button>
                        </form>
                    {/if}
                </div>
            {/each}
        </div>
    {/if}
</div>
