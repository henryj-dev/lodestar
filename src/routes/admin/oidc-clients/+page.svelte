<script lang="ts">
import { enhance } from "$app/forms";
import { resolve } from "$app/paths";
import type { ActionData, PageData } from "./$types";
import { t } from "$lib/i18n.svelte";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();

const dateFormatter = new Intl.DateTimeFormat("ko-KR", { dateStyle: "medium" });

let showCreate = $state(false);
let editingId = $state<string | null>(null);

const newSecret = $derived((form as { clientSecret?: string } | null)?.clientSecret ?? null);
const newClientId = $derived((form as { clientId?: string } | null)?.clientId ?? null);
const createErr = $derived((form as { create?: boolean; error?: string } | null)?.create ? ((form as { error?: string } | null)?.error ?? null) : null);
const globalErr = $derived(createErr ? null : ((form as { error?: string } | null)?.error ?? null));

function urisToText(json: string | null): string {
    if (!json) return "";
    try {
        return (JSON.parse(json) as string[]).join("\n");
    } catch {
        return json;
    }
}
</script>

<div class="space-y-6">
    <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-gray-900">{t("oidc.title")}</h1>
        <button
            type="button"
            onclick={() => {
                showCreate = !showCreate;
                editingId = null;
            }}
            class="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-700">
            {showCreate ? t("common.cancel") : t("oidc.add_btn")}
        </button>
    </div>

    {#if newSecret && newClientId}
        <div class="rounded-xl border border-green-200 bg-green-50 p-4">
            <p class="mb-1 font-semibold text-green-900">{t("oidc.created_title")}</p>
            <p class="mb-2 text-xs text-green-700">{t("oidc.created_secret_hint")}</p>
            <div class="space-y-1">
                <div class="flex items-center gap-2">
                    <span class="w-28 text-xs text-gray-500">Client ID</span>
                    <code class="rounded bg-white px-2 py-1 font-mono text-sm text-gray-800">{newClientId}</code>
                </div>
                <div class="flex items-center gap-2">
                    <span class="w-28 text-xs text-gray-500">Client Secret</span>
                    <code class="rounded bg-white px-2 py-1 font-mono text-sm break-all text-gray-800">{newSecret}</code>
                </div>
            </div>
        </div>
    {:else if (form as { regenerateSecret?: boolean } | null)?.regenerateSecret && newSecret}
        <div class="rounded-xl border border-amber-200 bg-amber-50 p-4">
            <p class="mb-1 font-semibold text-amber-900">{t("oidc.secret_regenerated_title")}</p>
            <p class="mb-2 text-xs text-amber-700">{t("oidc.secret_regenerated_hint")}</p>
            <code class="rounded bg-white px-2 py-1 font-mono text-sm break-all text-gray-800">{newSecret}</code>
        </div>
    {/if}

    {#if globalErr}
        <div class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {globalErr}
        </div>
    {/if}

    {#if showCreate}
        <div class="rounded-xl border border-blue-100 bg-blue-50 p-5">
            <h2 class="mb-4 font-semibold text-blue-900">{t("oidc.create_title")}</h2>
            {#if createErr}
                <div class="mb-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                    {createErr}
                </div>
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
                <input type="hidden" name="csrf" value={data.csrfToken} />
                <div>
                    <label for="c-name" class="block text-xs font-medium text-gray-700">{t("oidc.name_label")}</label>
                    <input id="c-name" type="text" name="name" required class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="c-scopes" class="block text-xs font-medium text-gray-700">Scopes</label>
                    <input
                        id="c-scopes"
                        type="text"
                        name="scopes"
                        value="openid profile email"
                        aria-describedby="c-scopes-hint"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                    <p id="c-scopes-hint" class="mt-1 text-xs text-gray-500">{t("oidc.scopes_hint")}</p>
                </div>
                <div class="sm:col-span-2">
                    <label for="c-redirectUris" class="block text-xs font-medium text-gray-700">{t("oidc.redirect_uris_label")}</label>
                    <textarea
                        id="c-redirectUris"
                        name="redirectUris"
                        required
                        rows="3"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none"></textarea>
                </div>
                <div class="sm:col-span-2">
                    <label for="c-postLogout" class="block text-xs font-medium text-gray-700">{t("oidc.post_logout_label")}</label>
                    <textarea
                        id="c-postLogout"
                        name="postLogoutRedirectUris"
                        rows="2"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none"></textarea>
                </div>
                <div>
                    <label for="c-fcLogout" class="block text-xs font-medium text-gray-700">Front-channel Logout URI</label>
                    <input
                        id="c-fcLogout"
                        type="url"
                        name="frontchannelLogoutUri"
                        placeholder="https://sp.example.com/logout"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                    <div class="mt-1 flex items-center gap-2">
                        <input id="c-fcSession" type="checkbox" name="frontchannelLogoutSessionRequired" value="true" class="h-4 w-4 rounded border-gray-300" />
                        <label for="c-fcSession" class="text-xs text-gray-600">session required (append sid)</label>
                    </div>
                </div>
                <div>
                    <label for="c-bcLogout" class="block text-xs font-medium text-gray-700">Back-channel Logout URI</label>
                    <input
                        id="c-bcLogout"
                        type="url"
                        name="backchannelLogoutUri"
                        placeholder="https://sp.example.com/backchannel-logout"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                    <div class="mt-1 flex items-center gap-2">
                        <input id="c-bcSession" type="checkbox" name="backchannelLogoutSessionRequired" value="true" class="h-4 w-4 rounded border-gray-300" />
                        <label for="c-bcSession" class="text-xs text-gray-600">session required (include sid)</label>
                    </div>
                </div>
                <div>
                    <label for="c-roleChange" class="block text-xs font-medium text-gray-700">Role Change URI</label>
                    <input
                        id="c-roleChange"
                        type="url"
                        name="roleChangeUri"
                        placeholder="https://sp.example.com/auth/oidc/role-change"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                    <p class="mt-1 text-xs text-gray-500">role 변경 시 서명된 Security Event Token 을 이 URI 로 push (세션 유지)</p>
                </div>
                <div>
                    <label for="c-authMethod" class="block text-xs font-medium text-gray-700">{t("oidc.auth_method_label")}</label>
                    <select id="c-authMethod" name="tokenEndpointAuthMethod" class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none">
                        <option value="client_secret_basic">client_secret_basic</option>
                        <option value="client_secret_post">client_secret_post</option>
                        <option value="none">{t("oidc.auth_method_none")}</option>
                    </select>
                </div>
                <div class="flex items-center gap-2 pt-5">
                    <input id="c-pkce" type="checkbox" name="requirePkce" value="true" checked class="h-4 w-4 rounded border-gray-300 text-blue-600" />
                    <label for="c-pkce" class="text-xs text-gray-700">{t("oidc.pkce_required")}</label>
                </div>
                <div class="flex items-center gap-2 pt-1 sm:col-span-2">
                    <input id="c-verifiedEmail" type="checkbox" name="requireVerifiedEmail" value="true" class="h-4 w-4 rounded border-gray-300 text-blue-600" />
                    <label for="c-verifiedEmail" class="text-xs text-gray-700">{t("oidc.require_verified_email")}</label>
                </div>
                <div class="flex items-start gap-2 pt-1 sm:col-span-2">
                    <input id="c-requireMfa" type="checkbox" name="requireMfa" value="true" class="mt-0.5 h-4 w-4 rounded border-gray-300 text-blue-600" />
                    <label for="c-requireMfa" class="text-xs text-gray-700">
                        <span class="font-medium">{t("oidc.require_mfa")}</span>
                        <span class="block text-gray-500">{t("oidc.require_mfa_hint")}</span>
                    </label>
                </div>
                <div class="sm:col-span-2">
                    <label for="c-reauthPolicy" class="block text-xs font-medium text-gray-600">{t("oidc.reauth_policy")}</label>
                    <select id="c-reauthPolicy" name="reauthPolicy" class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none">
                        <option value="full">{t("oidc.reauth_policy_full")}</option>
                        <option value="mfa_only">{t("oidc.reauth_policy_mfa_only")}</option>
                    </select>
                    <p class="mt-1 text-xs text-gray-500">{t("oidc.reauth_policy_hint")}</p>
                </div>
                <div class="flex items-start gap-2 pt-1 sm:col-span-2">
                    <input id="c-wildcard" type="checkbox" name="allowWildcardRedirectUri" value="true" class="mt-0.5 h-4 w-4 rounded border-gray-300 text-amber-600" />
                    <label for="c-wildcard" class="text-xs text-gray-700">
                        <span class="font-medium text-amber-700">{t("oidc.allow_wildcard_redirect_uri")}</span>
                        <span class="block text-gray-500">{t("oidc.allow_wildcard_redirect_uri_hint")}</span>
                    </label>
                </div>
                <div class="flex items-start gap-2 pt-1 sm:col-span-2">
                    <input id="c-allowAll" type="checkbox" name="allowAllUsers" value="true" class="mt-0.5 h-4 w-4 rounded border-gray-300 text-blue-600" />
                    <label for="c-allowAll" class="text-xs text-gray-700">
                        <span class="font-medium">{t("oidc.allow_all_users")}</span>
                        <span class="block text-gray-500">{t("oidc.allow_all_users_hint")}</span>
                    </label>
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
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("oidc.col_name_id")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">Scopes</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("oidc.col_auth")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("common.status")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("oidc.col_created")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("common.actions")}</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-200">
                {#if data.clients.length === 0}
                    <tr>
                        <td colspan="6" class="px-6 py-8 text-center text-sm text-gray-500">{t("oidc.empty")}</td>
                    </tr>
                {:else}
                    {#each data.clients as client (client.id)}
                        <tr class="hover:bg-gray-50">
                            <td class="px-4 py-3">
                                <p class="text-sm font-medium text-gray-900">{client.name}</p>
                                <p class="font-mono text-xs text-gray-400">{client.clientId}</p>
                            </td>
                            <td class="px-4 py-3 text-xs text-gray-600">{client.scopes}</td>
                            <td class="px-4 py-3 text-xs text-gray-500">{client.tokenEndpointAuthMethod}</td>
                            <td class="px-4 py-3">
                                <span class="rounded-full px-2 py-0.5 text-xs font-medium {client.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}">
                                    {client.enabled ? t("common.status_active") : t("common.status_inactive")}
                                </span>
                            </td>
                            <td class="px-4 py-3 text-xs text-gray-400">{dateFormatter.format(client.createdAt)}</td>
                            <td class="px-4 py-3">
                                <div class="flex items-center gap-2">
                                    <a href={resolve(`/admin/oidc-clients/${client.id}`)} class="text-xs text-indigo-500 hover:text-indigo-700">role</a>
                                    <button type="button" onclick={() => (editingId = editingId === client.id ? null : client.id)} class="text-xs text-blue-500 hover:text-blue-700">
                                        {editingId === client.id ? t("common.collapse") : t("common.expand")}
                                    </button>
                                    <form method="POST" action="?/regenerateSecret" use:enhance>
                                        <input type="hidden" name="csrf" value={data.csrfToken} />
                                        <input type="hidden" name="id" value={client.id} />
                                        <button
                                            type="submit"
                                            class="text-xs text-amber-500 hover:text-amber-700"
                                            onclick={(e) => {
                                                if (!confirm(t("oidc.regenerate_confirm"))) e.preventDefault();
                                            }}>
                                            {t("oidc.regenerate_secret")}
                                        </button>
                                    </form>
                                    <form method="POST" action="?/delete" use:enhance>
                                        <input type="hidden" name="csrf" value={data.csrfToken} />
                                        <input type="hidden" name="id" value={client.id} />
                                        <button
                                            type="submit"
                                            class="text-xs text-red-400 hover:text-red-600"
                                            onclick={(e) => {
                                                if (!confirm(t("oidc.delete_confirm"))) e.preventDefault();
                                            }}>
                                            {t("common.delete")}
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>

                        {#if editingId === client.id}
                            <tr class="bg-gray-50">
                                <td colspan="6" class="px-4 py-4">
                                    <form
                                        method="POST"
                                        action="?/update"
                                        use:enhance={() =>
                                            ({ result, update }) => {
                                                update();
                                                if (result.type === "success") editingId = null;
                                            }}
                                        class="grid grid-cols-1 gap-3 sm:grid-cols-2">
                                        <input type="hidden" name="csrf" value={data.csrfToken} />
                                        <input type="hidden" name="id" value={client.id} />
                                        <div>
                                            <label for="e-name-{client.id}" class="block text-xs font-medium text-gray-700">{t("oidc.name_label")}</label>
                                            <input
                                                id="e-name-{client.id}"
                                                type="text"
                                                name="name"
                                                value={client.name}
                                                required
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                                        </div>
                                        <div>
                                            <label for="e-scopes-{client.id}" class="block text-xs font-medium text-gray-700">Scopes</label>
                                            <input
                                                id="e-scopes-{client.id}"
                                                type="text"
                                                name="scopes"
                                                value={client.scopes}
                                                aria-describedby="e-scopes-hint-{client.id}"
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                                            <p id="e-scopes-hint-{client.id}" class="mt-1 text-xs text-gray-500">{t("oidc.scopes_hint")}</p>
                                        </div>
                                        <div class="sm:col-span-2">
                                            <label for="e-redirectUris-{client.id}" class="block text-xs font-medium text-gray-700">{t("oidc.redirect_uris_label")}</label>
                                            <textarea
                                                id="e-redirectUris-{client.id}"
                                                name="redirectUris"
                                                required
                                                rows="3"
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none"
                                                >{urisToText(client.redirectUris)}</textarea>
                                        </div>
                                        <div class="sm:col-span-2">
                                            <label for="e-postLogout-{client.id}" class="block text-xs font-medium text-gray-700">Post-Logout Redirect URIs</label>
                                            <textarea
                                                id="e-postLogout-{client.id}"
                                                name="postLogoutRedirectUris"
                                                rows="2"
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none"
                                                >{urisToText(client.postLogoutRedirectUris)}</textarea>
                                        </div>
                                        <div>
                                            <label for="e-fcLogout-{client.id}" class="block text-xs font-medium text-gray-700">Front-channel Logout URI</label>
                                            <input
                                                id="e-fcLogout-{client.id}"
                                                type="url"
                                                name="frontchannelLogoutUri"
                                                value={client.frontchannelLogoutUri ?? ""}
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                                            <div class="mt-1 flex items-center gap-2">
                                                <input
                                                    id="e-fcSession-{client.id}"
                                                    type="checkbox"
                                                    name="frontchannelLogoutSessionRequired"
                                                    value="true"
                                                    checked={client.frontchannelLogoutSessionRequired}
                                                    class="h-4 w-4 rounded border-gray-300" />
                                                <label for="e-fcSession-{client.id}" class="text-xs text-gray-600">session required (append sid)</label>
                                            </div>
                                        </div>
                                        <div>
                                            <label for="e-bcLogout-{client.id}" class="block text-xs font-medium text-gray-700">Back-channel Logout URI</label>
                                            <input
                                                id="e-bcLogout-{client.id}"
                                                type="url"
                                                name="backchannelLogoutUri"
                                                value={client.backchannelLogoutUri ?? ""}
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                                            <div class="mt-1 flex items-center gap-2">
                                                <input
                                                    id="e-bcSession-{client.id}"
                                                    type="checkbox"
                                                    name="backchannelLogoutSessionRequired"
                                                    value="true"
                                                    checked={client.backchannelLogoutSessionRequired}
                                                    class="h-4 w-4 rounded border-gray-300" />
                                                <label for="e-bcSession-{client.id}" class="text-xs text-gray-600">session required (include sid)</label>
                                            </div>
                                        </div>
                                        <div>
                                            <label for="e-roleChange-{client.id}" class="block text-xs font-medium text-gray-700">Role Change URI</label>
                                            <input
                                                id="e-roleChange-{client.id}"
                                                type="url"
                                                name="roleChangeUri"
                                                value={client.roleChangeUri ?? ""}
                                                placeholder="https://sp.example.com/auth/oidc/role-change"
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                                            <p class="mt-1 text-xs text-gray-500">role 변경 시 서명된 Security Event Token 을 이 URI 로 push (세션 유지)</p>
                                        </div>
                                        <div class="flex items-center gap-4">
                                            <div class="flex items-center gap-2">
                                                <input id="e-pkce-{client.id}" type="checkbox" name="requirePkce" value="true" checked={client.requirePkce} class="h-4 w-4 rounded border-gray-300" />
                                                <label for="e-pkce-{client.id}" class="text-xs text-gray-700">{t("oidc.pkce_required")}</label>
                                            </div>
                                            <div class="flex items-center gap-2">
                                                <input
                                                    id="e-verifiedEmail-{client.id}"
                                                    type="checkbox"
                                                    name="requireVerifiedEmail"
                                                    value="true"
                                                    checked={client.requireVerifiedEmail}
                                                    class="h-4 w-4 rounded border-gray-300" />
                                                <label for="e-verifiedEmail-{client.id}" class="text-xs text-gray-700">{t("oidc.require_verified_email")}</label>
                                            </div>
                                            <div class="flex items-center gap-2">
                                                <input
                                                    id="e-requireMfa-{client.id}"
                                                    type="checkbox"
                                                    name="requireMfa"
                                                    value="true"
                                                    checked={client.requireMfa}
                                                    class="h-4 w-4 rounded border-gray-300" />
                                                <label for="e-requireMfa-{client.id}" class="text-xs text-gray-700">{t("oidc.require_mfa")}</label>
                                            </div>
                                            <div class="flex items-center gap-2">
                                                <input id="e-enabled-{client.id}" type="checkbox" name="enabled" value="true" checked={client.enabled} class="h-4 w-4 rounded border-gray-300" />
                                                <label for="e-enabled-{client.id}" class="text-xs text-gray-700">{t("oidc.enabled")}</label>
                                            </div>
                                        </div>
                                        <div>
                                            <label for="e-reauthPolicy-{client.id}" class="block text-xs font-medium text-gray-600">{t("oidc.reauth_policy")}</label>
                                            <select
                                                id="e-reauthPolicy-{client.id}"
                                                name="reauthPolicy"
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none">
                                                <option value="full" selected={client.reauthPolicy !== "mfa_only"}>{t("oidc.reauth_policy_full")}</option>
                                                <option value="mfa_only" selected={client.reauthPolicy === "mfa_only"}>{t("oidc.reauth_policy_mfa_only")}</option>
                                            </select>
                                            <p class="mt-1 text-xs text-gray-500">{t("oidc.reauth_policy_hint")}</p>
                                        </div>
                                        <div class="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2">
                                            <input
                                                id="e-wildcard-{client.id}"
                                                type="checkbox"
                                                name="allowWildcardRedirectUri"
                                                value="true"
                                                checked={client.allowWildcardRedirectUri}
                                                class="mt-0.5 h-4 w-4 rounded border-gray-300 text-amber-600" />
                                            <label for="e-wildcard-{client.id}" class="text-xs text-gray-700">
                                                <span class="font-medium text-amber-800">{t("oidc.allow_wildcard_redirect_uri")}</span>
                                                <span class="block text-gray-500">{t("oidc.allow_wildcard_redirect_uri_hint")}</span>
                                            </label>
                                        </div>
                                        <div class="flex items-start gap-2">
                                            <input
                                                id="e-allowAll-{client.id}"
                                                type="checkbox"
                                                name="allowAllUsers"
                                                value="true"
                                                checked={client.allowAllUsers}
                                                class="mt-0.5 h-4 w-4 rounded border-gray-300 text-blue-600" />
                                            <label for="e-allowAll-{client.id}" class="text-xs text-gray-700">
                                                <span class="font-medium">{t("oidc.allow_all_users")}</span>
                                                <span class="block text-gray-500">{t("oidc.allow_all_users_hint")}</span>
                                            </label>
                                        </div>
                                        <div class="flex justify-end gap-2">
                                            <button type="button" onclick={() => (editingId = null)} class="rounded-md border border-gray-300 px-3 py-1.5 text-xs text-gray-600 hover:bg-gray-50"
                                                >{t("common.cancel")}</button>
                                            <button type="submit" class="rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700">{t("common.save")}</button>
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
</div>
