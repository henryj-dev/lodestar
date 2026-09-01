<script lang="ts">
import { enhance } from "$app/forms";
import { t } from "$lib/i18n.svelte";
import type { ActionData, PageData } from "./$types";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();

const dateFormatter = new Intl.DateTimeFormat("ko-KR", { dateStyle: "medium" });

let showCreate = $state(false);
let editingId = $state<string | null>(null);
let mappingKey = $state<string | null>(null);

const createErr = $derived((form as { create?: boolean; error?: string } | null)?.create ? ((form as { error?: string } | null)?.error ?? null) : null);
const mapErr = $derived((form as { map?: boolean; error?: string } | null)?.map ? ((form as { error?: string } | null)?.error ?? null) : null);
const globalErr = $derived(createErr || mapErr ? null : ((form as { error?: string } | null)?.error ?? null));

type Doc = PageData["docs"][number];
type Mapping = PageData["mappings"][number];

/** 이 key 에 걸린 매핑. 하나도 없으면 전역 약관이다. */
function mappingsFor(key: string): Mapping[] {
    return data.mappings.filter((m: Mapping) => m.termsKey === key);
}

function appLabel(m: Mapping): string {
    if (m.clientType === "oidc") {
        const c = data.oidcList.find((o: { id: string }) => o.id === m.clientRefId);
        return c ? `OIDC · ${c.name}` : `OIDC · ${m.clientRefId}`;
    }
    const s = data.samlList.find((sp: { id: string }) => sp.id === m.clientRefId);
    return s ? `SAML · ${s.name}` : `SAML · ${m.clientRefId}`;
}

/** key 별로 최신 버전이 무엇인지 — 목록에서 구버전을 흐리게 표시하는 데 쓴다. */
const latestByKey = $derived(
    data.docs.reduce((acc: Record<string, number>, d: Doc) => {
        const cur = acc[`${d.key}:${d.locale}`] ?? 0;
        if (d.version > cur) acc[`${d.key}:${d.locale}`] = d.version;
        return acc;
    }, {}),
);
const uniqueKeys = $derived([...new Set(data.docs.map((d: Doc) => d.key))] as string[]);
</script>

<div class="space-y-6">
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">{t("terms_admin.title")}</h1>
            <p class="mt-1 text-sm text-gray-500">{t("terms_admin.subtitle")}</p>
        </div>
        <button type="button" onclick={() => (showCreate = !showCreate)} class="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-700">
            {t("terms_admin.add_btn")}
        </button>
    </div>

    {#if globalErr}
        <div class="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{globalErr}</div>
    {/if}

    {#if showCreate}
        <div class="rounded-xl border border-blue-100 bg-blue-50 p-5">
            <h2 class="mb-4 font-semibold text-blue-900">{t("terms_admin.create_title")}</h2>
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
                class="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <div>
                    <label for="c-key" class="block text-xs font-medium text-gray-700">{t("terms_admin.key_label")}</label>
                    <input
                        id="c-key"
                        name="key"
                        required
                        placeholder="service"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="c-version" class="block text-xs font-medium text-gray-700">{t("terms_admin.version_label")}</label>
                    <input
                        id="c-version"
                        name="version"
                        type="number"
                        min="1"
                        value="1"
                        required
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="c-locale" class="block text-xs font-medium text-gray-700">{t("terms_admin.locale_label")}</label>
                    <select id="c-locale" name="locale" class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none">
                        <option value="ko">한국어 (ko)</option>
                        <option value="en">English (en)</option>
                    </select>
                </div>
                <div class="sm:col-span-2">
                    <label for="c-title" class="block text-xs font-medium text-gray-700">{t("terms_admin.title_label")}</label>
                    <input id="c-title" name="title" required class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="c-order" class="block text-xs font-medium text-gray-700">{t("terms_admin.display_order_label")}</label>
                    <input
                        id="c-order"
                        name="displayOrder"
                        type="number"
                        value="0"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div class="sm:col-span-3">
                    <label for="c-body" class="block text-xs font-medium text-gray-700">{t("terms_admin.body_label")}</label>
                    <textarea
                        id="c-body"
                        name="body"
                        rows="8"
                        required
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 font-mono text-sm focus:border-blue-500 focus:outline-none"></textarea>
                    <p class="mt-1 text-xs text-gray-500">{t("terms_admin.body_hint")}</p>
                </div>
                <div class="sm:col-span-3">
                    <label class="flex items-center gap-2 text-sm text-gray-700">
                        <input type="checkbox" name="required" value="true" checked class="rounded border-gray-300" />
                        {t("terms_admin.required_label")}
                    </label>
                </div>
                <div class="sm:col-span-3">
                    <button type="submit" class="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">{t("common.save")}</button>
                </div>
            </form>
        </div>
    {/if}

    <!-- 문서 목록 -->
    <div class="overflow-hidden rounded-xl border border-gray-200 bg-white">
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    {#each ["col_key", "col_version", "col_locale", "col_title", "col_required", "col_status", "col_scope"] as col (col)}
                        <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t(`terms_admin.${col}`)}</th>
                    {/each}
                    <th class="px-4 py-3"></th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100">
                {#each data.docs as doc (doc.id)}
                    {@const isLatest = latestByKey[`${doc.key}:${doc.locale}`] === doc.version}
                    {@const maps = mappingsFor(doc.key)}
                    <tr class={isLatest ? "" : "bg-gray-50/60 text-gray-400"}>
                        <td class="px-4 py-3 font-mono text-xs">{doc.key}</td>
                        <td class="px-4 py-3 text-xs">v{doc.version}</td>
                        <td class="px-4 py-3 text-xs">{doc.locale}</td>
                        <td class="px-4 py-3 text-sm">{doc.title}</td>
                        <td class="px-4 py-3 text-xs">
                            {doc.required ? t("terms_admin.required_yes") : t("terms_admin.required_no")}
                        </td>
                        <td class="px-4 py-3 text-xs">
                            {#if doc.publishedAt}
                                <span class="rounded bg-green-50 px-2 py-0.5 text-green-700">{t("terms_admin.status_published")}</span>
                            {:else}
                                <span class="rounded bg-gray-100 px-2 py-0.5 text-gray-600">{t("terms_admin.status_draft")}</span>
                            {/if}
                        </td>
                        <td class="px-4 py-3 text-xs">
                            {maps.length === 0 ? t("terms_admin.scope_global") : t("terms_admin.scope_apps", { count: String(maps.length) })}
                        </td>
                        <td class="space-x-2 px-4 py-3 text-right text-xs whitespace-nowrap">
                            <form method="POST" action={doc.publishedAt ? "?/unpublish" : "?/publish"} use:enhance class="inline">
                                <input type="hidden" name="id" value={doc.id} />
                                <button
                                    type="submit"
                                    onclick={(e) => {
                                        if (!doc.publishedAt && !confirm(t("terms_admin.publish_confirm"))) e.preventDefault();
                                    }}
                                    class="text-blue-600 hover:underline">
                                    {doc.publishedAt ? t("terms_admin.unpublish") : t("terms_admin.publish")}
                                </button>
                            </form>
                            <button type="button" onclick={() => (editingId = editingId === doc.id ? null : doc.id)} class="text-gray-600 hover:underline">{t("common.edit")}</button>
                            <form method="POST" action="?/delete" use:enhance class="inline">
                                <input type="hidden" name="id" value={doc.id} />
                                <button
                                    type="submit"
                                    onclick={(e) => {
                                        if (!confirm(t("terms_admin.delete_confirm"))) e.preventDefault();
                                    }}
                                    class="text-red-600 hover:underline">
                                    {t("common.delete")}
                                </button>
                            </form>
                        </td>
                    </tr>
                    {#if editingId === doc.id}
                        <tr class="bg-blue-50/40">
                            <td colspan="8" class="px-4 py-4">
                                <form
                                    method="POST"
                                    action="?/update"
                                    use:enhance={() =>
                                        async ({ update }) => {
                                            await update();
                                            editingId = null;
                                        }}
                                    class="space-y-3">
                                    <input type="hidden" name="id" value={doc.id} />
                                    <p class="text-xs text-gray-500">
                                        <span class="font-mono">{doc.key}</span> v{doc.version} · {doc.locale}
                                    </p>
                                    <input name="title" value={doc.title} required class="block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm" />
                                    <textarea name="body" rows="10" required class="block w-full rounded-md border border-gray-300 px-3 py-1.5 font-mono text-sm">{doc.body}</textarea>
                                    <div class="flex items-center gap-4">
                                        <label class="flex items-center gap-2 text-sm text-gray-700">
                                            <input type="checkbox" name="required" value="true" checked={doc.required} class="rounded border-gray-300" />
                                            {t("terms_admin.required_label")}
                                        </label>
                                        <input name="displayOrder" type="number" value={doc.displayOrder} class="w-24 rounded-md border border-gray-300 px-2 py-1 text-sm" />
                                        <button type="submit" class="rounded-md bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700">{t("common.save")}</button>
                                    </div>
                                </form>
                            </td>
                        </tr>
                    {/if}
                {/each}
                {#if data.docs.length === 0}
                    <tr><td colspan="8" class="px-4 py-8 text-center text-sm text-gray-500">{t("terms_admin.empty")}</td></tr>
                {/if}
            </tbody>
        </table>
    </div>

    <!-- 앱별 매핑 -->
    {#if uniqueKeys.length > 0}
        <div class="space-y-3 rounded-xl border border-gray-200 bg-white p-6">
            <div>
                <h2 class="text-base font-semibold text-gray-900">{t("terms_admin.mapping_title")}</h2>
                <p class="mt-1 text-sm leading-relaxed text-gray-600">{t("terms_admin.mapping_hint")}</p>
            </div>
            {#if mapErr}
                <div class="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{mapErr}</div>
            {/if}
            <div class="divide-y divide-gray-100">
                {#each uniqueKeys as key (key)}
                    <div class="py-3">
                        <div class="flex items-center justify-between">
                            <span class="font-mono text-xs text-gray-700">{key}</span>
                            <button type="button" onclick={() => (mappingKey = mappingKey === key ? null : key)} class="text-xs text-blue-600 hover:underline">
                                {t("terms_admin.mapping_add")}
                            </button>
                        </div>
                        {#if mappingsFor(key).length === 0}
                            <p class="mt-1 text-xs text-gray-400">{t("terms_admin.mapping_empty")}</p>
                        {:else}
                            <ul class="mt-1 space-y-1">
                                {#each mappingsFor(key) as m (m.id)}
                                    <li class="flex items-center justify-between text-xs text-gray-600">
                                        <span>{appLabel(m)}</span>
                                        <form method="POST" action="?/unmapClient" use:enhance class="inline">
                                            <input type="hidden" name="id" value={m.id} />
                                            <button type="submit" class="text-red-600 hover:underline">{t("terms_admin.mapping_remove")}</button>
                                        </form>
                                    </li>
                                {/each}
                            </ul>
                        {/if}
                        {#if mappingKey === key}
                            <form
                                method="POST"
                                action="?/mapClient"
                                use:enhance={() =>
                                    async ({ update }) => {
                                        await update();
                                        mappingKey = null;
                                    }}
                                class="mt-2 flex gap-2">
                                <input type="hidden" name="termsKey" value={key} />
                                <select name="clientType" class="rounded-md border border-gray-300 px-2 py-1 text-xs">
                                    <option value="oidc">OIDC</option>
                                    <option value="saml">SAML</option>
                                </select>
                                <select name="clientRefId" class="flex-1 rounded-md border border-gray-300 px-2 py-1 text-xs">
                                    {#each data.oidcList as c (c.id)}
                                        <option value={c.id}>OIDC · {c.name} ({c.clientId})</option>
                                    {/each}
                                    {#each data.samlList as sp (sp.id)}
                                        <option value={sp.id}>SAML · {sp.name}</option>
                                    {/each}
                                </select>
                                <button type="submit" class="rounded-md bg-blue-600 px-3 py-1 text-xs font-medium text-white hover:bg-blue-700">{t("terms_admin.mapping_add")}</button>
                            </form>
                        {/if}
                    </div>
                {/each}
            </div>
        </div>
    {/if}

    <p class="text-xs text-gray-400">
        {data.docs.filter((d: Doc) => d.publishedAt).length} / {data.docs.length} · {dateFormatter.format(new Date())}
    </p>
</div>
