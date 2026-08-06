<script lang="ts">
import { enhance } from "$app/forms";
import { resolve } from "$app/paths";
import type { ActionData, PageData } from "./$types";
import { t } from "$lib/i18n.svelte";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();

const err = $derived((form as { error?: string } | null)?.error ?? null);
const updated = $derived((form as { updated?: boolean } | null)?.updated ?? false);
const forcedLogout = $derived((form as { forcedLogout?: boolean } | null)?.forcedLogout ?? false);

const dateFormatter = new Intl.DateTimeFormat("ko-KR", { dateStyle: "medium" });

function teamLabel(tm: { name: string; departmentName: string | null }) {
    return tm.departmentName ? `${tm.departmentName} / ${tm.name}` : tm.name;
}

function partLabel(p: { name: string; teamName: string | null }) {
    return p.teamName ? `${p.teamName} / ${p.name}` : p.name;
}

let selectedService = $state("");
const filteredRoles = $derived(selectedService ? data.allServiceRoles.filter((r: { serviceType: string; serviceRefId: string }) => `${r.serviceType}:${r.serviceRefId}` === selectedService) : []);

// 배정이 가리키는 서비스에 정의된 권한만 그 배정의 체크박스로 보여 준다.
// (권한은 서비스별로 정의되므로 다른 서비스의 키가 섞이면 부여 자체가 서버에서 거부된다.)
type EntitlementRow = { id: string; serviceType: string; serviceRefId: string; key: string; label: string; description: string | null };
function entitlementsForAssignment(a: { serviceType: string; serviceRefId: string }): EntitlementRow[] {
    return (data.allServiceEntitlements as EntitlementRow[]).filter((e) => e.serviceType === a.serviceType && e.serviceRefId === a.serviceRefId);
}

function assignmentStatus(a: { revokedAt: Date | null; expiresAt: Date | null }): { label: string; className: string } {
    if (a.revokedAt) return { label: t("user_detail.svc_revoked"), className: "bg-gray-100 text-gray-500" };
    if (a.expiresAt && a.expiresAt.getTime() <= Date.now()) return { label: t("user_detail.svc_expired"), className: "bg-amber-100 text-amber-700" };
    return { label: t("user_detail.svc_active"), className: "bg-green-100 text-green-700" };
}

function toLocalDateTimeInputValue(d: Date | null): string {
    if (!d) return "";
    // input[type=datetime-local] 형식 (YYYY-MM-DDTHH:mm)
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const LOCALE_OPTIONS = [
    { value: "ko-KR", label: "한국어" },
    { value: "en-US", label: "English (US)" },
    { value: "ja-JP", label: "日本語" },
];
const TIMEZONE_OPTIONS = [
    { value: "Asia/Seoul", label: "Asia/Seoul (KST)" },
    { value: "Asia/Tokyo", label: "Asia/Tokyo (JST)" },
    { value: "UTC", label: "UTC" },
    { value: "America/New_York", label: "America/New_York (EST)" },
];
</script>

<div class="max-w-3xl space-y-8">
    <div class="flex items-center gap-3">
        <a href={resolve("/admin/users")} class="text-sm text-gray-400 hover:text-gray-600">{t("user_detail.back")}</a>
        <h1 class="text-2xl font-bold text-gray-900">{data.user.displayName ?? data.user.email}</h1>
        <span class="text-sm text-gray-400">{data.user.email}</span>
    </div>

    {#if err}
        <div class="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {err}
        </div>
    {/if}
    {#if updated}
        <div class="rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-700">{t("user_detail.saved")}</div>
    {/if}

    <section class="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
        <h2 class="mb-5 text-sm font-semibold text-gray-700">{t("user_detail.profile_section")}</h2>
        <form method="POST" action="?/updateProfile" use:enhance class="space-y-4">
            <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                    <label for="givenName" class="block text-xs font-medium text-gray-700">{t("user_detail.given_name")}</label>
                    <input
                        id="givenName"
                        type="text"
                        name="givenName"
                        value={data.user.givenName ?? ""}
                        class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="familyName" class="block text-xs font-medium text-gray-700">{t("user_detail.family_name")}</label>
                    <input
                        id="familyName"
                        type="text"
                        name="familyName"
                        value={data.user.familyName ?? ""}
                        class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div class="sm:col-span-2">
                    <label for="displayName" class="block text-xs font-medium text-gray-700">{t("user_detail.display_name")}</label>
                    <input
                        id="displayName"
                        type="text"
                        name="displayName"
                        value={data.user.displayName ?? ""}
                        class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="phoneNumber" class="block text-xs font-medium text-gray-700">{t("user_detail.phone")}</label>
                    <input
                        id="phoneNumber"
                        type="tel"
                        name="phoneNumber"
                        value={data.user.phoneNumber ?? ""}
                        placeholder="+82-10-0000-0000"
                        class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="birthdate" class="block text-xs font-medium text-gray-700">{t("user_detail.birthdate")}</label>
                    <input
                        id="birthdate"
                        type="date"
                        name="birthdate"
                        value={data.user.birthdate ?? ""}
                        class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div class="sm:col-span-2">
                    <label for="bio" class="block text-xs font-medium text-gray-700">{t("user_detail.bio")}</label>
                    <textarea id="bio" name="bio" rows="2" class="mt-1 w-full resize-none rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
                        >{data.user.bio ?? ""}</textarea>
                </div>
                <div>
                    <label for="locale" class="block text-xs font-medium text-gray-700">{t("user_detail.locale")}</label>
                    <select id="locale" name="locale" class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none">
                        {#each LOCALE_OPTIONS as opt (opt.value)}
                            <option value={opt.value} selected={data.user.locale === opt.value}>{opt.label}</option>
                        {/each}
                    </select>
                </div>
                <div>
                    <label for="zoneinfo" class="block text-xs font-medium text-gray-700">{t("user_detail.timezone")}</label>
                    <select id="zoneinfo" name="zoneinfo" class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none">
                        {#each TIMEZONE_OPTIONS as opt (opt.value)}
                            <option value={opt.value} selected={data.user.zoneinfo === opt.value}>{opt.label}</option>
                        {/each}
                    </select>
                </div>
                <div class="sm:col-span-2">
                    <label for="addressStreet" class="block text-xs font-medium text-gray-700">{t("user_detail.address_street")}</label>
                    <input
                        id="addressStreet"
                        type="text"
                        name="addressStreet"
                        value={data.user.addressStreet ?? ""}
                        class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="addressLocality" class="block text-xs font-medium text-gray-700">{t("user_detail.address_locality")}</label>
                    <input
                        id="addressLocality"
                        type="text"
                        name="addressLocality"
                        value={data.user.addressLocality ?? ""}
                        class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="addressRegion" class="block text-xs font-medium text-gray-700">{t("user_detail.address_region")}</label>
                    <input
                        id="addressRegion"
                        type="text"
                        name="addressRegion"
                        value={data.user.addressRegion ?? ""}
                        class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="addressPostalCode" class="block text-xs font-medium text-gray-700">{t("user_detail.address_postal_code")}</label>
                    <input
                        id="addressPostalCode"
                        type="text"
                        name="addressPostalCode"
                        value={data.user.addressPostalCode ?? ""}
                        class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="addressCountry" class="block text-xs font-medium text-gray-700">{t("user_detail.address_country")}</label>
                    <input
                        id="addressCountry"
                        type="text"
                        name="addressCountry"
                        value={data.user.addressCountry ?? ""}
                        class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="role" class="block text-xs font-medium text-gray-700">{t("user_detail.role")}</label>
                    <select id="role" name="role" class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none">
                        <option value="user" selected={data.user.role === "user"}>{t("user_detail.role_user")}</option>
                        <option value="admin" selected={data.user.role === "admin"}>{t("user_detail.role_admin")}</option>
                    </select>
                </div>
                <div>
                    <label for="status" class="block text-xs font-medium text-gray-700">{t("user_detail.status")}</label>
                    <select id="status" name="status" class="mt-1 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none">
                        <option value="active" selected={data.user.status === "active"}>{t("user_detail.status_active")}</option>
                        <option value="disabled" selected={data.user.status === "disabled"}>{t("user_detail.status_disabled")}</option>
                        <option value="locked" selected={data.user.status === "locked"}>{t("user_detail.status_locked")}</option>
                    </select>
                </div>
            </div>
            <div class="flex justify-end pt-2">
                <button type="submit" class="rounded-md bg-blue-600 px-5 py-2 text-sm font-medium text-white hover:bg-blue-700">{t("common.save")}</button>
            </div>
        </form>
    </section>

    <section class="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
        <h2 class="mb-4 text-sm font-semibold text-gray-700">{t("user_detail.dept_section")}</h2>

        {#if data.deptMemberships.length > 0}
            <div class="mb-4 divide-y divide-gray-100 rounded-lg border border-gray-200">
                {#each data.deptMemberships as m (m.id)}
                    <div class="flex items-center justify-between px-4 py-2.5 text-sm">
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="font-medium text-gray-900">{m.departmentName}</span>
                            {#if m.isPrimary}<span class="rounded-full bg-blue-100 px-1.5 py-0.5 text-xs text-blue-700">{t("user_detail.primary")}</span>{/if}
                            {#if m.positionName}<span class="text-gray-500">{m.positionName}</span>{/if}
                            {#if m.jobTitle}<span class="text-gray-400">/ {m.jobTitle}</span>{/if}
                            <span class="text-xs text-gray-300">{dateFormatter.format(m.startedAt)} ~</span>
                        </div>
                        <form method="POST" action="?/removeDept" use:enhance>
                            <input type="hidden" name="membershipId" value={m.id} />
                            <button type="submit" class="text-xs text-red-400 hover:text-red-600">{t("common.remove")}</button>
                        </form>
                    </div>
                {/each}
            </div>
        {:else}
            <p class="mb-4 text-sm text-gray-400">{t("user_detail.dept_empty")}</p>
        {/if}

        <form method="POST" action="?/addDept" use:enhance class="grid grid-cols-2 gap-2 border-t border-gray-100 pt-4 sm:grid-cols-4">
            <select name="departmentId" required class="rounded-md border border-gray-300 px-2 py-1.5 text-sm focus:border-blue-500 focus:outline-none">
                <option value="">{t("user_detail.dept_select")}</option>
                {#each data.allDepts as d (d.id)}
                    <option value={d.id}>{d.name}</option>
                {/each}
            </select>
            <select name="positionId" class="rounded-md border border-gray-300 px-2 py-1.5 text-sm focus:border-blue-500 focus:outline-none">
                <option value="">{t("user_detail.position_none")}</option>
                {#each data.allPositions as p (p.id)}
                    <option value={p.id}>{p.name}</option>
                {/each}
            </select>
            <input
                type="text"
                name="jobTitle"
                placeholder={t("user_detail.job_title_placeholder")}
                class="rounded-md border border-gray-300 px-2 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
            <div class="flex items-center gap-2">
                <label class="flex items-center gap-1 text-xs text-gray-600">
                    <input type="checkbox" name="isPrimary" value="true" class="rounded" />
                    {t("user_detail.primary")}
                </label>
                <button type="submit" class="ml-auto rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700">{t("common.add")}</button>
            </div>
        </form>
    </section>

    <section class="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
        <h2 class="mb-4 text-sm font-semibold text-gray-700">{t("user_detail.team_section")}</h2>

        {#if data.teamMemberships.length > 0}
            <div class="mb-4 divide-y divide-gray-100 rounded-lg border border-gray-200">
                {#each data.teamMemberships as m (m.id)}
                    <div class="flex items-center justify-between px-4 py-2.5 text-sm">
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="font-medium text-gray-900">{m.teamName}</span>
                            {#if m.departmentName}<span class="text-xs text-gray-400">({m.departmentName})</span>{/if}
                            {#if m.isPrimary}<span class="rounded-full bg-indigo-100 px-1.5 py-0.5 text-xs text-indigo-700">{t("user_detail.primary")}</span>{/if}
                            {#if m.jobTitle}<span class="text-gray-400">/ {m.jobTitle}</span>{/if}
                            <span class="text-xs text-gray-300">{dateFormatter.format(m.startedAt)} ~</span>
                        </div>
                        <form method="POST" action="?/removeTeam" use:enhance>
                            <input type="hidden" name="membershipId" value={m.id} />
                            <button type="submit" class="text-xs text-red-400 hover:text-red-600">{t("common.remove")}</button>
                        </form>
                    </div>
                {/each}
            </div>
        {:else}
            <p class="mb-4 text-sm text-gray-400">{t("user_detail.team_empty")}</p>
        {/if}

        <form method="POST" action="?/addTeam" use:enhance class="grid grid-cols-2 gap-2 border-t border-gray-100 pt-4 sm:grid-cols-4">
            <select name="teamId" required class="col-span-2 rounded-md border border-gray-300 px-2 py-1.5 text-sm focus:border-blue-500 focus:outline-none sm:col-span-1">
                <option value="">{t("user_detail.team_select")}</option>
                {#each data.allTeams as tm (tm.id)}
                    <option value={tm.id}>{teamLabel(tm)}</option>
                {/each}
            </select>
            <input
                type="text"
                name="jobTitle"
                placeholder={t("user_detail.job_title_placeholder")}
                class="rounded-md border border-gray-300 px-2 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
            <div class="flex items-center gap-2">
                <label class="flex items-center gap-1 text-xs text-gray-600">
                    <input type="checkbox" name="isPrimary" value="true" class="rounded" />
                    {t("user_detail.primary")}
                </label>
                <button type="submit" class="ml-auto rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700">{t("common.add")}</button>
            </div>
        </form>
    </section>

    <section class="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
        <h2 class="mb-4 text-sm font-semibold text-gray-700">{t("user_detail.part_section")}</h2>

        {#if data.partMemberships.length > 0}
            <div class="mb-4 divide-y divide-gray-100 rounded-lg border border-gray-200">
                {#each data.partMemberships as m (m.id)}
                    <div class="flex items-center justify-between px-4 py-2.5 text-sm">
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="font-medium text-gray-900">{m.partName}</span>
                            {#if m.teamName}<span class="text-xs text-gray-400">({m.teamName})</span>{/if}
                            {#if m.isPrimary}<span class="rounded-full bg-violet-100 px-1.5 py-0.5 text-xs text-violet-700">{t("user_detail.primary")}</span>{/if}
                            {#if m.jobTitle}<span class="text-gray-400">/ {m.jobTitle}</span>{/if}
                            <span class="text-xs text-gray-300">{dateFormatter.format(m.startedAt)} ~</span>
                        </div>
                        <form method="POST" action="?/removePart" use:enhance>
                            <input type="hidden" name="membershipId" value={m.id} />
                            <button type="submit" class="text-xs text-red-400 hover:text-red-600">{t("common.remove")}</button>
                        </form>
                    </div>
                {/each}
            </div>
        {:else}
            <p class="mb-4 text-sm text-gray-400">{t("user_detail.part_empty")}</p>
        {/if}

        <form method="POST" action="?/addPart" use:enhance class="grid grid-cols-2 gap-2 border-t border-gray-100 pt-4 sm:grid-cols-4">
            <select name="partId" required class="col-span-2 rounded-md border border-gray-300 px-2 py-1.5 text-sm focus:border-blue-500 focus:outline-none sm:col-span-1">
                <option value="">{t("user_detail.part_select")}</option>
                {#each data.allParts as p (p.id)}
                    <option value={p.id}>{partLabel(p)}</option>
                {/each}
            </select>
            <input
                type="text"
                name="jobTitle"
                placeholder={t("user_detail.part_job_title_placeholder")}
                class="rounded-md border border-gray-300 px-2 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
            <div class="flex items-center gap-2">
                <label class="flex items-center gap-1 text-xs text-gray-600">
                    <input type="checkbox" name="isPrimary" value="true" class="rounded" />
                    {t("user_detail.primary")}
                </label>
                <button type="submit" class="ml-auto rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700">{t("common.add")}</button>
            </div>
        </form>
    </section>

    <section class="rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
        <h2 class="mb-4 text-sm font-semibold text-gray-700">{t("user_detail.svc_section")}</h2>
        <p class="mb-3 text-xs text-gray-500">{t("user_detail.svc_desc")}</p>

        {#if data.assignments.length > 0}
            <div class="mb-4 divide-y divide-gray-100 rounded-lg border border-gray-200">
                {#each data.assignments as a (a.id)}
                    {@const status = assignmentStatus(a)}
                    {@const ents = entitlementsForAssignment(a)}
                    {@const granted = data.grantedEntitlementsByAssignment[a.id] ?? []}
                    <div class="px-4 py-3 text-sm">
                        <div class="flex flex-wrap items-center justify-between gap-2">
                            <div class="flex flex-wrap items-center gap-2">
                                <span class="font-medium text-gray-900">{data.serviceLabelMap[`${a.serviceType}:${a.serviceRefId}`] ?? `${a.serviceType}:${a.serviceRefId}`}</span>
                                {#if a.roleKey}
                                    <code class="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-xs">{a.roleKey}</code>
                                    <span class="text-xs text-gray-500">{a.roleLabel}</span>
                                {:else}
                                    <span class="text-xs text-gray-400">{t("user_detail.svc_role_none")}</span>
                                {/if}
                                <span class="rounded-full px-1.5 py-0.5 text-xs {status.className}">{status.label}</span>
                                {#if a.expiresAt}<span class="text-xs text-gray-400">~{dateFormatter.format(a.expiresAt)}</span>{/if}
                            </div>
                            <form method="POST" action="?/revokeAssignment" use:enhance>
                                <input type="hidden" name="assignmentId" value={a.id} />
                                <button
                                    type="submit"
                                    class="text-xs text-red-400 hover:text-red-600"
                                    onclick={(e) => {
                                        if (!confirm(t("user_detail.svc_delete_confirm"))) e.preventDefault();
                                    }}>{t("common.delete")}</button>
                            </form>
                        </div>
                        <form method="POST" action="?/updateAssignmentExpiry" use:enhance class="mt-2 flex items-center gap-2">
                            <input type="hidden" name="assignmentId" value={a.id} />
                            <label class="text-xs text-gray-500">
                                {t("user_detail.svc_expires")}
                                <input type="datetime-local" name="expiresAt" value={toLocalDateTimeInputValue(a.expiresAt)} class="rounded-md border border-gray-300 px-2 py-1 text-xs" />
                            </label>
                            <button type="submit" class="rounded-md border border-gray-300 px-2 py-1 text-xs text-gray-600">{t("user_detail.svc_renew")}</button>
                            {#if a.attributesJson}
                                <span class="ml-auto truncate font-mono text-xs text-gray-400" title={a.attributesJson}>{a.attributesJson}</span>
                            {/if}
                        </form>

                        <!-- 권한(entitlement) — role 과 직교. 이 배정이 가리키는 서비스에 정의된 것만 보인다. -->
                        {#if ents.length > 0}
                            <form method="POST" action="?/setAssignmentEntitlements" use:enhance class="mt-2 rounded-md bg-gray-50 px-3 py-2">
                                <input type="hidden" name="assignmentId" value={a.id} />
                                <div class="mb-1 flex items-center justify-between">
                                    <span class="text-xs font-medium text-gray-600">{t("user_detail.ent_title")}</span>
                                    <button type="submit" class="rounded-md border border-gray-300 bg-white px-2 py-1 text-xs text-gray-600">{t("common.save")}</button>
                                </div>
                                <div class="flex flex-col gap-1">
                                    {#each ents as e (e.id)}
                                        <label class="flex items-center gap-2 text-xs text-gray-700">
                                            <input type="checkbox" name="entitlementId" value={e.id} checked={granted.includes(e.id)} class="rounded" />
                                            <code class="rounded bg-white px-1 py-0.5 font-mono text-xs">{e.key}</code>
                                            <span>{e.label}</span>
                                            {#if e.description}<span class="text-gray-400">{e.description}</span>{/if}
                                        </label>
                                    {/each}
                                </div>
                                <p class="mt-1 text-xs text-gray-400">{t("user_detail.ent_order_hint")}</p>
                            </form>
                        {/if}
                    </div>
                {/each}
            </div>
        {:else}
            <p class="mb-4 text-sm text-gray-400">{t("user_detail.svc_empty")}</p>
        {/if}

        <form method="POST" action="?/addAssignment" use:enhance class="grid grid-cols-1 gap-2 border-t border-gray-100 pt-4 sm:grid-cols-2">
            <div>
                <label for="svc" class="block text-xs font-medium text-gray-700">{t("user_detail.svc_service")}</label>
                <select id="svc" name="service" required bind:value={selectedService} class="mt-1 w-full rounded-md border border-gray-300 px-2 py-1.5 text-sm">
                    <option value="">{t("user_detail.svc_select")}</option>
                    {#if data.allOidcClients.length > 0}
                        <optgroup label="OIDC">
                            {#each data.allOidcClients as c (c.id)}
                                <option value="oidc:{c.id}">{c.name} ({c.clientId})</option>
                            {/each}
                        </optgroup>
                    {/if}
                    {#if data.allSamlSps.length > 0}
                        <optgroup label="SAML">
                            {#each data.allSamlSps as s (s.id)}
                                <option value="saml:{s.id}">{s.name}</option>
                            {/each}
                        </optgroup>
                    {/if}
                </select>
            </div>
            <div>
                <label for="svc-role" class="block text-xs font-medium text-gray-700">Role</label>
                <select id="svc-role" name="serviceRoleId" class="mt-1 w-full rounded-md border border-gray-300 px-2 py-1.5 text-sm" disabled={!selectedService}>
                    <option value="">{t("user_detail.svc_role_none")}</option>
                    {#each filteredRoles as r (r.id)}
                        <option value={r.id}>{r.label} [{r.key}]{r.isDefault ? " · default" : ""}</option>
                    {/each}
                </select>
            </div>
            <div>
                <label for="svc-expires" class="block text-xs font-medium text-gray-700">{t("user_detail.svc_expires_optional")}</label>
                <input id="svc-expires" type="datetime-local" name="expiresAt" class="mt-1 w-full rounded-md border border-gray-300 px-2 py-1.5 text-sm" />
            </div>
            <div>
                <label for="svc-attrs" class="block text-xs font-medium text-gray-700">attributesJson (optional)</label>
                <textarea id="svc-attrs" name="attributesJson" rows="2" placeholder={'{"region":"kr"}'} class="mt-1 w-full rounded-md border border-gray-300 px-2 py-1.5 font-mono text-xs"></textarea>
            </div>
            <div class="flex justify-end sm:col-span-2">
                <button type="submit" class="rounded-md bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700">{t("user_detail.svc_add")}</button>
            </div>
        </form>
    </section>

    <!-- 위험 작업 -->
    <section class="rounded-xl border border-red-200 bg-white p-6 shadow-sm">
        <h2 class="mb-1 text-sm font-semibold text-red-700">{t("user_detail.danger_zone")}</h2>
        <p class="mb-4 text-xs text-gray-500">{t("user_detail.force_logout_desc")}</p>
        {#if forcedLogout}
            <div class="mb-4 rounded-lg border border-green-200 bg-green-50 px-4 py-2.5 text-sm text-green-700">{t("user_detail.force_logout_done")}</div>
        {/if}
        <form method="POST" action="?/forceLogout" use:enhance>
            <button
                type="submit"
                class="rounded-md border border-red-300 px-3 py-1.5 text-sm font-medium text-red-700 hover:bg-red-50"
                onclick={(e) => {
                    if (!confirm(t("user_detail.force_logout_confirm"))) e.preventDefault();
                }}>{t("user_detail.force_logout")}</button>
        </form>
    </section>
</div>
