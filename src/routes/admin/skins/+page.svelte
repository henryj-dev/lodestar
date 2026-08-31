<script lang="ts">
import { enhance } from "$app/forms";
import { resolve } from "$app/paths";
import { untrack } from "svelte";
import type { ActionData, PageData } from "./$types";
import { t } from "$lib/i18n.svelte";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();

const dateFormatter = new Intl.DateTimeFormat("ko-KR", { dateStyle: "medium" });

let showCreate = $state(false);
const firstClientId = untrack(() => data.oidcList[0]?.id ?? data.samlList[0]?.id ?? "");
let selectedClientRefId = $state(firstClientId);
// "*" 는 테넌트 기본 스킨 슬롯(TENANT_DEFAULT_CLIENT_REF). 클라이언트가 특정되지 않는
// 흐름(초대 수락·이메일 변경 확인 등)과, 전용 스킨이 없는 클라이언트의 폴백으로 쓰인다.
const TENANT_DEFAULT_REF = "*";
const derivedClientType = $derived(selectedClientRefId === TENANT_DEFAULT_REF ? "tenant" : data.oidcList.some((c: { id: string }) => c.id === selectedClientRefId) ? "oidc" : "saml");

let editingId = $state<string | null>(null);

const createErr = $derived((form as { create?: boolean; error?: string } | null)?.create ? ((form as { error?: string } | null)?.error ?? null) : null);
const updateErr = $derived((form as { update?: boolean; updateId?: string; error?: string } | null)?.update ? ((form as { error?: string } | null)?.error ?? null) : null);
const globalErr = $derived(createErr || updateErr ? null : ((form as { error?: string } | null)?.error ?? null));

const CLIENT_TYPE_LABEL: Record<string, string> = { oidc: "OIDC", saml: "SAML", tenant: "—" };

function clientLabel(clientType: string, clientRefId: string): string {
    if (clientType === "tenant") return t("skins.tenant_default");
    if (clientType === "oidc") {
        const c = data.oidcList.find((o: { id: string }) => o.id === clientRefId);
        return c ? `${c.name} (${c.clientId})` : clientRefId;
    }
    const s = data.samlList.find((sp: { id: string }) => sp.id === clientRefId);
    return s ? `${s.name} (${s.entityId})` : clientRefId;
}
</script>

<div class="space-y-6">
    <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-gray-900">{t("skins.title")}</h1>
        <div class="flex items-center gap-2">
            <a href={resolve("/admin/skins/guide")} class="rounded-md border border-gray-300 px-4 py-2 text-sm text-gray-600 hover:bg-gray-50">{t("skins.guide_link")}</a>
            <button type="button" onclick={() => (showCreate = !showCreate)} class="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-700">
                {showCreate ? t("common.cancel") : t("skins.add_btn")}
            </button>
        </div>
    </div>

    {#if globalErr}
        <div class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{globalErr}</div>
    {/if}

    {#if (form as { created?: boolean } | null)?.created}
        <div class="rounded-xl border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-800">{t("skins.created_success")}</div>
    {/if}

    {#if (form as { invalidated?: boolean } | null)?.invalidated}
        <div class="rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-800">{t("skins.cache_invalidated")}</div>
    {/if}

    {#if (form as { updated?: boolean } | null)?.updated}
        <div class="rounded-xl border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-800">{t("skins.updated_success")}</div>
    {/if}

    {#if showCreate}
        <div class="rounded-xl border border-blue-100 bg-blue-50 p-5">
            <h2 class="mb-4 font-semibold text-blue-900">{t("skins.create_title")}</h2>
            {#if createErr}
                <div class="mb-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{createErr}</div>
            {/if}
            <form
                method="POST"
                action="?/create"
                use:enhance={() =>
                    ({ result, update }) => {
                        update();
                        if (result.type === "success") showCreate = false;
                    }}
                class="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <input type="hidden" name="clientType" value={derivedClientType} />
                <div>
                    <label for="c-skinType" class="block text-xs font-medium text-gray-700">{t("skins.skin_type_label")}</label>
                    <select id="c-skinType" name="skinType" class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none">
                        <option value="login">{t("skins.skin_type_login")}</option>
                        <option value="signup">{t("skins.skin_type_signup")}</option>
                        <option value="find_id">{t("skins.skin_type_find_id")}</option>
                        <option value="find_password">{t("skins.skin_type_find_password")}</option>
                        <option value="mfa">{t("skins.skin_type_mfa")}</option>
                        <option value="reset_password">{t("skins.skin_type_reset_password")}</option>
                        <option value="verify_email">{t("skins.skin_type_verify_email")}</option>
                        <option value="accept_invite">{t("skins.skin_type_accept_invite")}</option>
                        <option value="confirm_email_change">{t("skins.skin_type_confirm_email_change")}</option>
                        <option value="logout">{t("skins.skin_type_logout")}</option>
                    </select>
                </div>
                <div>
                    <label for="c-clientRefId" class="block text-xs font-medium text-gray-700">{t("skins.client_label")}</label>
                    <select
                        id="c-clientRefId"
                        name="clientRefId"
                        bind:value={selectedClientRefId}
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none">
                        <option value={TENANT_DEFAULT_REF}>{t("skins.tenant_default")}</option>
                        {#if data.oidcList.length > 0}
                            <optgroup label="OIDC">
                                {#each data.oidcList as c (c.id)}
                                    <option value={c.id}>{c.name} ({c.clientId})</option>
                                {/each}
                            </optgroup>
                        {/if}
                        {#if data.samlList.length > 0}
                            <optgroup label="SAML">
                                {#each data.samlList as sp (sp.id)}
                                    <option value={sp.id}>{sp.name} ({sp.entityId})</option>
                                {/each}
                            </optgroup>
                        {/if}
                    </select>
                </div>
                <div class="sm:col-span-2">
                    <label for="c-fetchUrl" class="block text-xs font-medium text-gray-700">{t("skins.fetch_url_label")}</label>
                    <input
                        id="c-fetchUrl"
                        type="url"
                        name="fetchUrl"
                        required
                        placeholder="https://example.com/login-skin.html"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="c-fetchSecret" class="block text-xs font-medium text-gray-700">{t("skins.fetch_secret_label")}</label>
                    <input
                        id="c-fetchSecret"
                        type="password"
                        name="fetchSecret"
                        placeholder={t("skins.fetch_secret_placeholder")}
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="c-cacheTtl" class="block text-xs font-medium text-gray-700">{t("skins.cache_ttl_label")}</label>
                    <input
                        id="c-cacheTtl"
                        type="number"
                        name="cacheTtlSeconds"
                        value="3600"
                        min="60"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div class="flex justify-end sm:col-span-2">
                    <button type="submit" class="rounded-md bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700">{t("common.add")}</button>
                </div>
            </form>
        </div>
    {/if}

    <div class="overflow-x-auto rounded-xl border border-gray-200 bg-white shadow-sm">
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("skins.col_client")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("skins.col_skin_type")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("skins.col_fetch_url")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("skins.col_ttl")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("common.status")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("skins.col_created")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("common.actions")}</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-200">
                {#if data.skins.length === 0}
                    <tr>
                        <td colspan="7" class="px-6 py-8 text-center text-sm text-gray-500">{t("skins.empty")}</td>
                    </tr>
                {:else}
                    {#each data.skins as skin (skin.id)}
                        <tr class="hover:bg-gray-50 {skin.enabled ? '' : 'opacity-60'}">
                            <td class="px-4 py-3">
                                <span class="mr-1 rounded bg-gray-100 px-1.5 py-0.5 text-xs font-medium text-gray-600">{CLIENT_TYPE_LABEL[skin.clientType]}</span>
                                <span class="text-sm text-gray-800">{clientLabel(skin.clientType, skin.clientRefId)}</span>
                            </td>
                            <td class="px-4 py-3 text-xs text-gray-600">{t(`skins.skin_type_${skin.skinType}`)}</td>
                            <td class="max-w-xs truncate px-4 py-3 font-mono text-xs text-gray-500" title={skin.fetchUrl}>{skin.fetchUrl}</td>
                            <td class="px-4 py-3 text-xs text-gray-500">{skin.cacheTtlSeconds}s</td>
                            <td class="px-4 py-3">
                                <span class="rounded-full px-2 py-0.5 text-xs font-medium {skin.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}">
                                    {skin.enabled ? t("common.status_active") : t("common.status_inactive")}
                                </span>
                            </td>
                            <td class="px-4 py-3 text-xs text-gray-400">{dateFormatter.format(skin.createdAt)}</td>
                            <td class="px-4 py-3">
                                <div class="flex items-center gap-2">
                                    <button type="button" class="text-xs text-indigo-500 hover:text-indigo-700" onclick={() => (editingId = editingId === skin.id ? null : skin.id)}>
                                        {editingId === skin.id ? t("common.cancel") : t("common.edit")}
                                    </button>
                                    <form method="POST" action="?/toggleEnabled" use:enhance>
                                        <input type="hidden" name="id" value={skin.id} />
                                        <button type="submit" class="text-xs text-gray-500 hover:text-gray-800">
                                            {skin.enabled ? t("common.status_inactive") : t("common.status_active")}
                                        </button>
                                    </form>
                                    <form method="POST" action="?/invalidateCache" use:enhance>
                                        <input type="hidden" name="id" value={skin.id} />
                                        <button type="submit" class="text-xs text-blue-500 hover:text-blue-700">{t("skins.invalidate_cache")}</button>
                                    </form>
                                    <form method="POST" action="?/delete" use:enhance>
                                        <input type="hidden" name="id" value={skin.id} />
                                        <button
                                            type="submit"
                                            class="text-xs text-red-400 hover:text-red-600"
                                            onclick={(e) => {
                                                if (!confirm(t("skins.delete_confirm"))) e.preventDefault();
                                            }}>
                                            {t("common.delete")}
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                        {#if editingId === skin.id}
                            <tr class="bg-indigo-50">
                                <td colspan="7" class="px-4 py-4">
                                    {#if updateErr && (form as { updateId?: string } | null)?.updateId === skin.id}
                                        <div class="mb-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{updateErr}</div>
                                    {/if}
                                    <form
                                        method="POST"
                                        action="?/update"
                                        use:enhance={() =>
                                            ({ result, update }) => {
                                                update();
                                                if (result.type === "success") editingId = null;
                                            }}
                                        class="grid grid-cols-1 gap-3 sm:grid-cols-3">
                                        <input type="hidden" name="id" value={skin.id} />
                                        <div class="sm:col-span-3">
                                            <label for="e-fetchUrl-{skin.id}" class="block text-xs font-medium text-gray-700">{t("skins.fetch_url_label")}</label>
                                            <input
                                                id="e-fetchUrl-{skin.id}"
                                                type="url"
                                                name="fetchUrl"
                                                value={skin.fetchUrl}
                                                required
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-indigo-500 focus:outline-none" />
                                        </div>
                                        <div class="sm:col-span-2">
                                            <label for="e-fetchSecret-{skin.id}" class="block text-xs font-medium text-gray-700">{t("skins.fetch_secret_label")}</label>
                                            <input
                                                id="e-fetchSecret-{skin.id}"
                                                type="password"
                                                name="fetchSecret"
                                                placeholder={t("skins.fetch_secret_placeholder")}
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-indigo-500 focus:outline-none" />
                                        </div>
                                        <div>
                                            <label for="e-cacheTtl-{skin.id}" class="block text-xs font-medium text-gray-700">{t("skins.cache_ttl_label")}</label>
                                            <input
                                                id="e-cacheTtl-{skin.id}"
                                                type="number"
                                                name="cacheTtlSeconds"
                                                value={skin.cacheTtlSeconds}
                                                min="60"
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-indigo-500 focus:outline-none" />
                                        </div>
                                        <div class="flex items-end justify-end sm:col-span-3">
                                            <button type="submit" class="rounded-md bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-700">
                                                {t("common.save")}
                                            </button>
                                        </div>
                                    </form>
                                </td>
                            </tr>
                        {/if}
                    {/each}
                {/if}
            </tbody>
        </table>
    </div>

    <div class="space-y-1 rounded-xl border border-gray-100 bg-gray-50 p-4 text-xs text-gray-500">
        <p class="font-medium text-gray-700">{t("skins.placeholder_guide_title")}</p>
        <p><code class="rounded bg-white px-1 py-0.5">&#123;&#123;IDP_FORM_ACTION&#125;&#125;</code> — {t("skins.placeholder_form_action")}</p>
        <p><code class="rounded bg-white px-1 py-0.5">&#123;&#123;IDP_REDIRECT_TO&#125;&#125;</code> — {t("skins.placeholder_redirect_to")}</p>
        <p><code class="rounded bg-white px-1 py-0.5">&#123;&#123;IDP_SKIN_HINT&#125;&#125;</code> — {t("skins.placeholder_skin_hint")}</p>
        <p><code class="rounded bg-white px-1 py-0.5">&#123;&#123;IDP_REGISTERED&#125;&#125;</code> — {t("skins.placeholder_registered")}</p>
        <p><code class="rounded bg-white px-1 py-0.5">&#123;&#123;IDP_PASSWORD_RESET&#125;&#125;</code> — {t("skins.placeholder_password_reset")}</p>
        <p><code class="rounded bg-white px-1 py-0.5">&#123;&#123;IDP_FLASH_MSG&#125;&#125;</code> — {t("skins.placeholder_flash_msg")}</p>
    </div>
</div>
