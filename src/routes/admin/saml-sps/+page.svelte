<script lang="ts">
import { enhance } from "$app/forms";
import { resolve } from "$app/paths";
import type { ActionData, PageData } from "./$types";
import { t } from "$lib/i18n.svelte";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();

const dateFormatter = new Intl.DateTimeFormat("ko-KR", { dateStyle: "medium" });

let showCreate = $state(false);
let editingId = $state<string | null>(null);

let createName = $state("");
let createEntityId = $state("");
let createAcsUrl = $state("");
let createSloUrl = $state("");
let createNameIdFormat = $state("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
let createCert = $state("");
let createSignAssertion = $state(true);
let createSignResponse = $state(false);
// ctrls R8: 신규 SP 는 서명된 AuthnRequest 요구를 기본값으로(secure-by-default).
let createWantSigned = $state(true);
let createEncryptAssertion = $state(false);
let createAllowedAttributes = $state("");

let metadataXml = $state("");
let metaParseError = $state<string | null>(null);

function parseSpMetadata() {
    metaParseError = null;
    const xml = metadataXml.trim();
    if (!xml) return;

    try {
        const parser = new DOMParser();
        const doc = parser.parseFromString(xml, "text/xml");

        const parseErr = doc.querySelector("parsererror");
        if (parseErr) throw new Error(t("saml.parse_error_xml"));

        const entityId = doc.documentElement.getAttribute("entityID") ?? "";
        if (entityId) createEntityId = entityId;

        const acsList = doc.querySelectorAll("AssertionConsumerService");
        let acsUrl = "";
        for (const acs of acsList) {
            if ((acs.getAttribute("Binding") ?? "").includes("HTTP-POST")) {
                acsUrl = acs.getAttribute("Location") ?? "";
                break;
            }
        }
        if (!acsUrl && acsList.length > 0) acsUrl = acsList[0].getAttribute("Location") ?? "";
        if (acsUrl) createAcsUrl = acsUrl;

        const slo = doc.querySelector("SingleLogoutService");
        if (slo) createSloUrl = slo.getAttribute("Location") ?? "";

        const nameIdEl = doc.querySelector("NameIDFormat");
        if (nameIdEl?.textContent) createNameIdFormat = nameIdEl.textContent.trim();

        const certEl = doc.querySelector("KeyDescriptor[use='signing'] X509Certificate") ?? doc.querySelector("X509Certificate");
        if (certEl?.textContent) {
            const raw = certEl.textContent.trim().replace(/\s/g, "");
            const lines = raw.match(/.{1,64}/g)?.join("\n") ?? raw;
            createCert = `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
        }

        if (!createName && entityId) {
            try {
                createName = new URL(entityId).hostname;
            } catch {
                createName = entityId;
            }
        }
    } catch (e) {
        metaParseError = e instanceof Error ? e.message : t("saml.parse_error_generic");
    }
}

function resetCreateForm() {
    createName = "";
    createEntityId = "";
    createAcsUrl = "";
    createSloUrl = "";
    createNameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    createCert = "";
    createSignAssertion = true;
    createSignResponse = false;
    createWantSigned = true;
    createAllowedAttributes = "";
    metadataXml = "";
    metaParseError = null;
}

const createErr = $derived((form as { create?: boolean; error?: string } | null)?.create ? ((form as { error?: string } | null)?.error ?? null) : null);
const globalErr = $derived(createErr ? null : ((form as { error?: string } | null)?.error ?? null));

function formatAllowedAttributes(raw: string | null): string {
    if (!raw) return "";
    try {
        const parsed = JSON.parse(raw) as unknown;
        return Array.isArray(parsed) ? parsed.filter((v) => typeof v === "string").join(",") : "";
    } catch {
        return "";
    }
}

const NAME_ID_OPTIONS = [
    { value: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", label: "emailAddress" },
    { value: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", label: "persistent" },
    { value: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", label: "transient" },
    { value: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", label: "unspecified" },
];
</script>

<div class="space-y-6">
    <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-gray-900">{t("saml.title")}</h1>
        <button
            type="button"
            onclick={() => {
                showCreate = !showCreate;
                editingId = null;
                if (!showCreate) resetCreateForm();
            }}
            class="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-700">
            {showCreate ? t("common.cancel") : t("saml.add_btn")}
        </button>
    </div>

    {#if globalErr}
        <div class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {globalErr}
        </div>
    {/if}

    {#if showCreate}
        <div class="space-y-4 rounded-xl border border-blue-100 bg-blue-50 p-5">
            <h2 class="font-semibold text-blue-900">{t("saml.create_title")}</h2>

            <div class="space-y-2 rounded-lg border border-blue-200 bg-white p-4">
                <p class="text-xs font-medium text-gray-700">
                    {t("saml.metadata_hint")} <span class="font-normal text-gray-400">{t("saml.metadata_optional")}</span>
                </p>
                {#if metaParseError}
                    <div class="rounded border border-red-200 bg-red-50 px-3 py-1.5 text-xs text-red-600">
                        {metaParseError}
                    </div>
                {/if}
                <textarea
                    bind:value={metadataXml}
                    rows="4"
                    placeholder={t("saml.metadata_placeholder")}
                    class="block w-full rounded-md border border-gray-300 px-3 py-1.5 font-mono text-xs focus:border-blue-500 focus:outline-none"></textarea>
                <button type="button" onclick={parseSpMetadata} class="rounded-md bg-gray-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-gray-800">{t("saml.parse_btn")}</button>
            </div>

            {#if createErr}
                <div class="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                    {createErr}
                </div>
            {/if}

            <form
                method="POST"
                action="?/create"
                use:enhance={() =>
                    ({ result, update }) => {
                        update();
                        if (result.type === "success") {
                            showCreate = false;
                            resetCreateForm();
                        }
                    }}
                class="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                    <label for="s-name" class="block text-xs font-medium text-gray-700">{t("saml.name_label")}</label>
                    <input
                        id="s-name"
                        type="text"
                        name="name"
                        required
                        bind:value={createName}
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="s-entityId" class="block text-xs font-medium text-gray-700">{t("saml.entity_id_label")}</label>
                    <input
                        id="s-entityId"
                        type="text"
                        name="entityId"
                        required
                        bind:value={createEntityId}
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 font-mono text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div class="sm:col-span-2">
                    <label for="s-acsUrl" class="block text-xs font-medium text-gray-700">{t("saml.acs_url_label")}</label>
                    <input
                        id="s-acsUrl"
                        type="url"
                        name="acsUrl"
                        required
                        bind:value={createAcsUrl}
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div class="sm:col-span-2">
                    <label for="s-sloUrl" class="block text-xs font-medium text-gray-700">{t("saml.slo_url_label")}</label>
                    <input
                        id="s-sloUrl"
                        type="url"
                        name="sloUrl"
                        bind:value={createSloUrl}
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="s-nameIdFormat" class="block text-xs font-medium text-gray-700">{t("saml.name_id_label")}</label>
                    <select
                        id="s-nameIdFormat"
                        name="nameIdFormat"
                        bind:value={createNameIdFormat}
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none">
                        {#each NAME_ID_OPTIONS as opt (opt.value)}
                            <option value={opt.value}>{opt.label}</option>
                        {/each}
                    </select>
                </div>
                <div class="flex flex-col gap-2 pt-4">
                    <div class="flex items-center gap-2">
                        <input id="s-signAssertion" type="checkbox" name="signAssertion" value="true" bind:checked={createSignAssertion} class="h-4 w-4 rounded border-gray-300" />
                        <label for="s-signAssertion" class="text-xs text-gray-700">{t("saml.sign_assertion")}</label>
                    </div>
                    <div class="flex items-center gap-2">
                        <input id="s-signResponse" type="checkbox" name="signResponse" value="true" bind:checked={createSignResponse} class="h-4 w-4 rounded border-gray-300" />
                        <label for="s-signResponse" class="text-xs text-gray-700">{t("saml.sign_response")}</label>
                    </div>
                    <div class="flex items-center gap-2">
                        <input id="s-wantSigned" type="checkbox" name="wantAuthnRequestsSigned" value="true" bind:checked={createWantSigned} class="h-4 w-4 rounded border-gray-300" />
                        <label for="s-wantSigned" class="text-xs text-gray-700">{t("saml.want_signed")}</label>
                    </div>
                    <div class="flex items-center gap-2">
                        <input id="s-verifiedEmail" type="checkbox" name="requireVerifiedEmail" value="true" class="h-4 w-4 rounded border-gray-300" />
                        <label for="s-verifiedEmail" class="text-xs text-gray-700">{t("saml.require_verified_email")}</label>
                    </div>
                    <div class="flex items-center gap-2">
                        <input id="s-encryptAssertion" type="checkbox" name="encryptAssertion" value="true" bind:checked={createEncryptAssertion} class="h-4 w-4 rounded border-gray-300" />
                        <label for="s-encryptAssertion" class="text-xs text-gray-700">{t("saml.encrypt_assertion")}</label>
                    </div>
                    <div class="flex items-start gap-2">
                        <input id="s-allowAll" type="checkbox" name="allowAllUsers" value="true" class="mt-0.5 h-4 w-4 rounded border-gray-300 text-blue-600" />
                        <label for="s-allowAll" class="text-xs text-gray-700">
                            <span class="font-medium">{t("saml.allow_all_users")}</span>
                            <span class="block text-gray-500">{t("saml.allow_all_users_hint")}</span>
                        </label>
                    </div>
                </div>
                <div class="sm:col-span-2">
                    <label for="s-cert" class="block text-xs font-medium text-gray-700">{t("saml.cert_label")}</label>
                    <textarea
                        id="s-cert"
                        name="cert"
                        rows="4"
                        bind:value={createCert}
                        placeholder="-----BEGIN CERTIFICATE-----"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 font-mono text-xs focus:border-blue-500 focus:outline-none"></textarea>
                </div>
                <div class="sm:col-span-2">
                    <label for="s-allowedAttributes" class="block text-xs font-medium text-gray-700">{t("saml.allowed_attrs_label")}</label>
                    <input
                        id="s-allowedAttributes"
                        type="text"
                        name="allowedAttributes"
                        bind:value={createAllowedAttributes}
                        placeholder="email,username,displayName,department,team,jobTitle,position,givenName,familyName,surName,phoneNumber,Role,RoleLabel,Entitlements"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 font-mono text-xs focus:border-blue-500 focus:outline-none" />
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
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("saml.col_name_entity")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("saml.col_acs")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("saml.col_sign")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("common.status")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("saml.col_created")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("common.actions")}</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-200">
                {#if data.sps.length === 0}
                    <tr>
                        <td colspan="6" class="px-6 py-8 text-center text-sm text-gray-500">{t("saml.empty")}</td>
                    </tr>
                {:else}
                    {#each data.sps as sp (sp.id)}
                        <tr class="hover:bg-gray-50">
                            <td class="px-4 py-3">
                                <p class="text-sm font-medium text-gray-900">{sp.name}</p>
                                <p class="font-mono text-xs break-all text-gray-400">{sp.entityId}</p>
                            </td>
                            <td class="max-w-50 px-4 py-3 text-xs break-all text-gray-500">{sp.acsUrl}</td>
                            <td class="px-4 py-3 text-xs text-gray-500">
                                {#if sp.signAssertion}<span class="mr-1 rounded bg-blue-50 px-1 py-0.5 text-blue-600">Assertion</span>{/if}
                                {#if sp.signResponse}<span class="rounded bg-purple-50 px-1 py-0.5 text-purple-600">Response</span>{/if}
                            </td>
                            <td class="px-4 py-3">
                                <span class="rounded-full px-2 py-0.5 text-xs font-medium {sp.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}">
                                    {sp.enabled ? t("common.status_active") : t("common.status_inactive")}
                                </span>
                            </td>
                            <td class="px-4 py-3 text-xs text-gray-400">{dateFormatter.format(sp.createdAt)}</td>
                            <td class="px-4 py-3">
                                <div class="flex items-center gap-2">
                                    <a href={resolve(`/admin/saml-sps/${sp.id}`)} class="text-xs text-indigo-500 hover:text-indigo-700">role</a>
                                    <button type="button" onclick={() => (editingId = editingId === sp.id ? null : sp.id)} class="text-xs text-blue-500 hover:text-blue-700">
                                        {editingId === sp.id ? t("common.collapse") : t("common.expand")}
                                    </button>
                                    <form method="POST" action="?/delete" use:enhance>
                                        <input type="hidden" name="id" value={sp.id} />
                                        <button
                                            type="submit"
                                            class="text-xs text-red-400 hover:text-red-600"
                                            onclick={(e) => {
                                                if (!confirm(t("saml.delete_confirm"))) e.preventDefault();
                                            }}>
                                            {t("common.delete")}
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>

                        {#if editingId === sp.id}
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
                                        <input type="hidden" name="id" value={sp.id} />
                                        <div>
                                            <label for="e-name-{sp.id}" class="block text-xs font-medium text-gray-700">{t("saml.name_label")}</label>
                                            <input
                                                id="e-name-{sp.id}"
                                                type="text"
                                                name="name"
                                                value={sp.name}
                                                required
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                                        </div>
                                        <div>
                                            <label for="e-nameIdFormat-{sp.id}" class="block text-xs font-medium text-gray-700">{t("saml.name_id_label")}</label>
                                            <select
                                                id="e-nameIdFormat-{sp.id}"
                                                name="nameIdFormat"
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none">
                                                {#each NAME_ID_OPTIONS as opt (opt.value)}
                                                    <option value={opt.value} selected={sp.nameIdFormat === opt.value}>{opt.label}</option>
                                                {/each}
                                            </select>
                                        </div>
                                        <div class="sm:col-span-2">
                                            <label for="e-acsUrl-{sp.id}" class="block text-xs font-medium text-gray-700">{t("saml.acs_url_label")}</label>
                                            <input
                                                id="e-acsUrl-{sp.id}"
                                                type="url"
                                                name="acsUrl"
                                                value={sp.acsUrl}
                                                required
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                                        </div>
                                        <div class="sm:col-span-2">
                                            <label for="e-sloUrl-{sp.id}" class="block text-xs font-medium text-gray-700">{t("saml.slo_url_label")}</label>
                                            <input
                                                id="e-sloUrl-{sp.id}"
                                                type="url"
                                                name="sloUrl"
                                                value={sp.sloUrl ?? ""}
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                                        </div>
                                        <div class="flex flex-col gap-2">
                                            <div class="flex items-center gap-2">
                                                <input
                                                    id="e-signAssertion-{sp.id}"
                                                    type="checkbox"
                                                    name="signAssertion"
                                                    value="true"
                                                    checked={sp.signAssertion}
                                                    class="h-4 w-4 rounded border-gray-300" />
                                                <label for="e-signAssertion-{sp.id}" class="text-xs text-gray-700">{t("saml.sign_assertion")}</label>
                                            </div>
                                            <div class="flex items-center gap-2">
                                                <input id="e-signResponse-{sp.id}" type="checkbox" name="signResponse" value="true" checked={sp.signResponse} class="h-4 w-4 rounded border-gray-300" />
                                                <label for="e-signResponse-{sp.id}" class="text-xs text-gray-700">{t("saml.sign_response")}</label>
                                            </div>
                                            <div class="flex items-center gap-2">
                                                <input
                                                    id="e-wantSigned-{sp.id}"
                                                    type="checkbox"
                                                    name="wantAuthnRequestsSigned"
                                                    value="true"
                                                    checked={sp.wantAuthnRequestsSigned}
                                                    class="h-4 w-4 rounded border-gray-300" />
                                                <label for="e-wantSigned-{sp.id}" class="text-xs text-gray-700">{t("saml.want_signed")}</label>
                                            </div>
                                            <div class="flex items-center gap-2">
                                                <input
                                                    id="e-verifiedEmail-{sp.id}"
                                                    type="checkbox"
                                                    name="requireVerifiedEmail"
                                                    value="true"
                                                    checked={sp.requireVerifiedEmail}
                                                    class="h-4 w-4 rounded border-gray-300" />
                                                <label for="e-verifiedEmail-{sp.id}" class="text-xs text-gray-700">{t("saml.require_verified_email")}</label>
                                            </div>
                                            <div class="flex items-center gap-2">
                                                <input
                                                    id="e-encryptAssertion-{sp.id}"
                                                    type="checkbox"
                                                    name="encryptAssertion"
                                                    value="true"
                                                    checked={sp.encryptAssertion}
                                                    class="h-4 w-4 rounded border-gray-300" />
                                                <label for="e-encryptAssertion-{sp.id}" class="text-xs text-gray-700">{t("saml.encrypt_assertion")}</label>
                                            </div>
                                            <div class="flex items-start gap-2">
                                                <input
                                                    id="e-allowAll-{sp.id}"
                                                    type="checkbox"
                                                    name="allowAllUsers"
                                                    value="true"
                                                    checked={sp.allowAllUsers}
                                                    class="mt-0.5 h-4 w-4 rounded border-gray-300 text-blue-600" />
                                                <label for="e-allowAll-{sp.id}" class="text-xs text-gray-700">
                                                    <span class="font-medium">{t("saml.allow_all_users")}</span>
                                                    <span class="block text-gray-500">{t("saml.allow_all_users_hint")}</span>
                                                </label>
                                            </div>
                                            <div class="flex items-center gap-2">
                                                <input id="e-enabled-{sp.id}" type="checkbox" name="enabled" value="true" checked={sp.enabled} class="h-4 w-4 rounded border-gray-300" />
                                                <label for="e-enabled-{sp.id}" class="text-xs text-gray-700">{t("saml.enabled")}</label>
                                            </div>
                                        </div>
                                        <div class="sm:col-span-2">
                                            <label for="e-cert-{sp.id}" class="block text-xs font-medium text-gray-700">{t("saml.cert_label")}</label>
                                            <textarea
                                                id="e-cert-{sp.id}"
                                                name="cert"
                                                rows="4"
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 font-mono text-xs focus:border-blue-500 focus:outline-none"
                                                >{sp.cert ?? ""}</textarea>
                                        </div>
                                        <div class="sm:col-span-2">
                                            <label for="e-allowedAttributes-{sp.id}" class="block text-xs font-medium text-gray-700">{t("saml.allowed_attrs_label")}</label>
                                            <input
                                                id="e-allowedAttributes-{sp.id}"
                                                type="text"
                                                name="allowedAttributes"
                                                value={formatAllowedAttributes(sp.allowedAttributes)}
                                                placeholder="email,username,displayName"
                                                class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 font-mono text-xs focus:border-blue-500 focus:outline-none" />
                                        </div>
                                        <div class="flex justify-end gap-2 sm:col-span-2">
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
