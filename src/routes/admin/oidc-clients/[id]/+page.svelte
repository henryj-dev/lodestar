<script lang="ts">
import { enhance } from "$app/forms";
import { resolve } from "$app/paths";
import type { ActionData, PageData } from "./$types";
import { t } from "$lib/i18n.svelte";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();

const err = $derived((form as { error?: string } | null)?.error ?? null);

let editingId = $state<string | null>(null);
let editingEntitlementId = $state<string | null>(null);

// organization 클레임 노출 토글 — config null/미설정이면 전량 노출(하위호환)이므로 전부 체크.
const ORG_CLAIM_FIELDS = ["department", "team", "position", "jobTitle"] as const;
type OrgClaimField = (typeof ORG_CLAIM_FIELDS)[number];

function parseOrgClaimConfig(raw: string | null): Record<OrgClaimField, boolean> {
    const result: Record<OrgClaimField, boolean> = { department: true, team: true, position: true, jobTitle: true };
    if (!raw) return result; // null=미설정=전량 노출
    try {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        for (const f of ORG_CLAIM_FIELDS) {
            if (typeof parsed[f] === "boolean") result[f] = parsed[f] as boolean;
        }
    } catch {
        /* 파싱 실패 시 전량 노출 폴백 */
    }
    return result;
}

// 서버 저장값에서 파생한 체크박스 상태(writable $derived). 체크박스 bind 로 로컬 편집이
// 가능하고, 저장 후 load 재실행으로 data.client 가 바뀌면 자동으로 재계산된다.
let orgClaims = $derived(parseOrgClaimConfig((data.client as { organizationClaimConfig: string | null }).organizationClaimConfig));
</script>

<div class="max-w-3xl space-y-8">
    <div class="flex items-center gap-3">
        <a href={resolve("/admin/oidc-clients")} class="text-sm text-gray-400 hover:text-gray-600">← {t("oidc.title")}</a>
        <h1 class="text-2xl font-bold text-gray-900">{data.client.name}</h1>
        <span class="font-mono text-xs text-gray-400">{data.client.clientId}</span>
    </div>

    {#if err}
        <div class="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{err}</div>
    {/if}

    <section class="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
        <div class="mb-4 flex items-center justify-between">
            <h2 class="text-sm font-semibold text-gray-700">{t("roles.list_title")}</h2>
            <span class="text-xs text-gray-400">{t("roles.count", { count: data.roles.length })}</span>
        </div>

        {#if data.roles.length > 0}
            <div class="mb-4 divide-y divide-gray-100 rounded-lg border border-gray-200">
                {#each data.roles as r (r.id)}
                    <div class="px-4 py-3 text-sm">
                        {#if editingId === r.id}
                            <form
                                method="POST"
                                action="?/updateRole"
                                use:enhance={() =>
                                    ({ result, update }) => {
                                        update();
                                        if (result.type === "success") editingId = null;
                                    }}
                                class="grid grid-cols-2 gap-2 sm:grid-cols-5">
                                <input type="hidden" name="csrf" value={data.csrfToken} />
                                <input type="hidden" name="roleId" value={r.id} />
                                <label class="block text-xs text-gray-500 sm:col-span-1">
                                    key
                                    <input type="text" value={r.key} disabled class="mt-1 w-full rounded-md border border-gray-200 bg-gray-50 px-2 py-1 font-mono text-xs text-gray-500" />
                                </label>
                                <label class="block text-xs text-gray-500 sm:col-span-1">
                                    label
                                    <input type="text" name="label" value={r.label} required class="mt-1 w-full rounded-md border border-gray-300 px-2 py-1 text-xs" />
                                </label>
                                <label class="block text-xs text-gray-500 sm:col-span-2">
                                    description
                                    <input type="text" name="description" value={r.description ?? ""} class="mt-1 w-full rounded-md border border-gray-300 px-2 py-1 text-xs" />
                                </label>
                                <label class="block text-xs text-gray-500 sm:col-span-1">
                                    order
                                    <input type="number" name="displayOrder" value={r.displayOrder} class="mt-1 w-full rounded-md border border-gray-300 px-2 py-1 text-xs" />
                                </label>
                                <div class="flex items-center gap-2 sm:col-span-5">
                                    <label class="flex items-center gap-1 text-xs text-gray-600">
                                        <input type="checkbox" name="isDefault" value="true" checked={r.isDefault} class="rounded" /> default
                                    </label>
                                    <div class="ml-auto flex gap-2">
                                        <button type="button" onclick={() => (editingId = null)} class="rounded-md border border-gray-300 px-3 py-1 text-xs text-gray-600">{t("common.cancel")}</button>
                                        <button type="submit" class="rounded-md bg-blue-600 px-3 py-1 text-xs font-medium text-white">{t("common.save")}</button>
                                    </div>
                                </div>
                            </form>
                        {:else}
                            <div class="flex items-center justify-between">
                                <div class="flex flex-wrap items-center gap-2">
                                    <code class="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-xs">{r.key}</code>
                                    <span class="font-medium text-gray-900">{r.label}</span>
                                    {#if r.isDefault}<span class="rounded-full bg-blue-100 px-1.5 py-0.5 text-xs text-blue-700">default</span>{/if}
                                    {#if r.description}<span class="text-xs text-gray-500">{r.description}</span>{/if}
                                    <span class="text-xs text-gray-300">order: {r.displayOrder}</span>
                                </div>
                                <div class="flex items-center gap-2">
                                    <button type="button" onclick={() => (editingId = r.id)} class="text-xs text-blue-500">{t("roles.edit")}</button>
                                    <form method="POST" action="?/deleteRole" use:enhance>
                                        <input type="hidden" name="csrf" value={data.csrfToken} />
                                        <input type="hidden" name="roleId" value={r.id} />
                                        <button
                                            type="submit"
                                            class="text-xs text-red-400"
                                            onclick={(e) => {
                                                if (!confirm(t("roles.delete_confirm", { key: r.key }))) e.preventDefault();
                                            }}>{t("common.delete")}</button>
                                    </form>
                                </div>
                            </div>
                        {/if}
                    </div>
                {/each}
            </div>
        {:else}
            <p class="mb-4 text-sm text-gray-400">{t("roles.empty")}</p>
        {/if}

        <form method="POST" action="?/addRole" use:enhance class="grid grid-cols-2 gap-2 border-t border-gray-100 pt-4 sm:grid-cols-5">
            <input type="hidden" name="csrf" value={data.csrfToken} />
            <input type="text" name="key" placeholder={t("roles.key_placeholder")} required class="rounded-md border border-gray-300 px-2 py-1.5 font-mono text-sm" />
            <input type="text" name="label" placeholder="label" required class="rounded-md border border-gray-300 px-2 py-1.5 text-sm" />
            <input type="text" name="description" placeholder="description (optional)" class="rounded-md border border-gray-300 px-2 py-1.5 text-sm sm:col-span-2" />
            <input type="number" name="displayOrder" value="0" class="rounded-md border border-gray-300 px-2 py-1.5 text-sm" />
            <div class="flex items-center gap-2 sm:col-span-5">
                <label class="flex items-center gap-1 text-xs text-gray-600">
                    <input type="checkbox" name="isDefault" value="true" class="rounded" /> default
                </label>
                <button type="submit" class="ml-auto rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white">{t("roles.add")}</button>
            </div>
        </form>
    </section>

    <!-- entitlement(권한) 정의 — role 과 직교하는 축. isDefault 가 없다. -->
    <section class="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
        <div class="mb-1 flex items-center justify-between">
            <h2 class="text-sm font-semibold text-gray-700">{t("entitlements.list_title")}</h2>
            <span class="text-xs text-gray-400">{t("entitlements.count", { count: data.entitlements.length })}</span>
        </div>
        <p class="mb-4 text-xs text-gray-500">{t("entitlements.hint")}</p>

        {#if data.entitlements.length > 0}
            <div class="mb-4 divide-y divide-gray-100 rounded-lg border border-gray-200">
                {#each data.entitlements as e (e.id)}
                    <div class="px-4 py-3 text-sm">
                        {#if editingEntitlementId === e.id}
                            <form
                                method="POST"
                                action="?/updateEntitlement"
                                use:enhance={() =>
                                    ({ result, update }) => {
                                        update();
                                        if (result.type === "success") editingEntitlementId = null;
                                    }}
                                class="grid grid-cols-2 gap-2 sm:grid-cols-5">
                                <input type="hidden" name="csrf" value={data.csrfToken} />
                                <input type="hidden" name="entitlementId" value={e.id} />
                                <label class="block text-xs text-gray-500 sm:col-span-1">
                                    key
                                    <input type="text" value={e.key} disabled class="mt-1 w-full rounded-md border border-gray-200 bg-gray-50 px-2 py-1 font-mono text-xs text-gray-500" />
                                </label>
                                <label class="block text-xs text-gray-500 sm:col-span-1">
                                    label
                                    <input type="text" name="label" value={e.label} required class="mt-1 w-full rounded-md border border-gray-300 px-2 py-1 text-xs" />
                                </label>
                                <label class="block text-xs text-gray-500 sm:col-span-2">
                                    description
                                    <input type="text" name="description" value={e.description ?? ""} class="mt-1 w-full rounded-md border border-gray-300 px-2 py-1 text-xs" />
                                </label>
                                <label class="block text-xs text-gray-500 sm:col-span-1">
                                    order
                                    <input type="number" name="displayOrder" value={e.displayOrder} class="mt-1 w-full rounded-md border border-gray-300 px-2 py-1 text-xs" />
                                </label>
                                <div class="flex gap-2 sm:col-span-5">
                                    <div class="ml-auto flex gap-2">
                                        <button type="button" onclick={() => (editingEntitlementId = null)} class="rounded-md border border-gray-300 px-3 py-1 text-xs text-gray-600"
                                            >{t("common.cancel")}</button>
                                        <button type="submit" class="rounded-md bg-blue-600 px-3 py-1 text-xs font-medium text-white">{t("common.save")}</button>
                                    </div>
                                </div>
                            </form>
                        {:else}
                            <div class="flex items-center justify-between">
                                <div class="flex flex-wrap items-center gap-2">
                                    <code class="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-xs">{e.key}</code>
                                    <span class="font-medium text-gray-900">{e.label}</span>
                                    {#if e.description}<span class="text-xs text-gray-500">{e.description}</span>{/if}
                                    <span class="text-xs text-gray-300">order: {e.displayOrder}</span>
                                </div>
                                <div class="flex items-center gap-2">
                                    <button type="button" onclick={() => (editingEntitlementId = e.id)} class="text-xs text-blue-500">{t("entitlements.edit")}</button>
                                    <form method="POST" action="?/deleteEntitlement" use:enhance>
                                        <input type="hidden" name="csrf" value={data.csrfToken} />
                                        <input type="hidden" name="entitlementId" value={e.id} />
                                        <button
                                            type="submit"
                                            class="text-xs text-red-400"
                                            onclick={(ev) => {
                                                if (!confirm(t("entitlements.delete_confirm", { key: e.key }))) ev.preventDefault();
                                            }}>{t("common.delete")}</button>
                                    </form>
                                </div>
                            </div>
                        {/if}
                    </div>
                {/each}
            </div>
        {:else}
            <p class="mb-4 text-sm text-gray-400">{t("entitlements.empty")}</p>
        {/if}

        <form method="POST" action="?/addEntitlement" use:enhance class="grid grid-cols-2 gap-2 border-t border-gray-100 pt-4 sm:grid-cols-5">
            <input type="hidden" name="csrf" value={data.csrfToken} />
            <input type="text" name="key" placeholder={t("entitlements.key_placeholder")} required class="rounded-md border border-gray-300 px-2 py-1.5 font-mono text-sm" />
            <input type="text" name="label" placeholder="label" required class="rounded-md border border-gray-300 px-2 py-1.5 text-sm" />
            <input type="text" name="description" placeholder="description (optional)" class="rounded-md border border-gray-300 px-2 py-1.5 text-sm sm:col-span-2" />
            <input type="number" name="displayOrder" value="0" class="rounded-md border border-gray-300 px-2 py-1.5 text-sm" />
            <div class="flex sm:col-span-5">
                <button type="submit" class="ml-auto rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white">{t("entitlements.add")}</button>
            </div>
        </form>
    </section>

    <!-- organization scope 클레임 노출 토글 -->
    <section class="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
        <div class="mb-1 flex items-center justify-between">
            <h2 class="text-sm font-semibold text-gray-700">{t("oidc.org_claims.title")}</h2>
        </div>
        <p class="mb-4 text-xs text-gray-500">{t("oidc.org_claims.desc")}</p>

        {#if (form as { organizationClaimsUpdated?: boolean } | null)?.organizationClaimsUpdated}
            <div class="mb-4 rounded-lg border border-green-200 bg-green-50 px-4 py-2 text-xs text-green-700">{t("oidc.org_claims.saved")}</div>
        {/if}

        <form method="POST" action="?/updateOrganizationClaims" use:enhance class="space-y-3">
            <input type="hidden" name="csrf" value={data.csrfToken} />
            {#each ORG_CLAIM_FIELDS as field (field)}
                <label class="flex items-start gap-3">
                    <input type="checkbox" name={field} value="true" bind:checked={orgClaims[field]} class="mt-0.5 rounded" />
                    <span>
                        <span class="block text-sm font-medium text-gray-800">{t(`oidc.org_claims.field_${field}`)}</span>
                        <span class="block text-xs text-gray-500">{t(`oidc.org_claims.field_${field}_desc`)}</span>
                    </span>
                </label>
            {/each}
            <div class="flex items-center gap-3 border-t border-gray-100 pt-3">
                <p class="text-xs text-gray-400">{t("oidc.org_claims.all_note")}</p>
                <button type="submit" class="ml-auto rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white">{t("common.save")}</button>
            </div>
        </form>
    </section>
</div>
