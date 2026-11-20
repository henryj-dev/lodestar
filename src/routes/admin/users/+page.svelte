<script lang="ts">
import { enhance } from "$app/forms";
import { resolve } from "$app/paths";
import type { ActionData, PageData } from "./$types";
import { t } from "$lib/i18n.svelte";

const { data, form } = $props<{ data: PageData; form?: ActionData }>();

const dateFormatter = new Intl.DateTimeFormat("ko-KR", {
    dateStyle: "medium",
    timeStyle: "short",
});

let showCreate = $state(false);
let showInvite = $state(false);
let resetPasswordUserId = $state<string | null>(null);

const formErr = $derived((form as { error?: string } | null)?.error ?? null);
const createErr = $derived((form as { create?: boolean; error?: string } | null)?.create ? formErr : null);
const inviteErr = $derived((form as { invite?: boolean; error?: string } | null)?.invite ? formErr : null);
const resetErr = $derived((form as { resetPassword?: boolean; error?: string } | null)?.resetPassword ? formErr : null);

const STATUS_COLOR: Record<string, string> = {
    active: "bg-green-100 text-green-700",
    disabled: "bg-gray-100 text-gray-500",
    locked: "bg-red-100 text-red-600",
};

type StatusNext = { status: string; labelKey: string };
const STATUS_NEXT: Record<string, StatusNext> = {
    active: { status: "disabled", labelKey: "users.action_disable" },
    disabled: { status: "active", labelKey: "users.action_enable" },
    locked: { status: "active", labelKey: "users.action_unlock" },
};
</script>

<div class="space-y-6">
    <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-gray-900">{t("users.title")}</h1>
        <div class="flex items-center gap-2">
            <button
                type="button"
                onclick={() => {
                    showInvite = !showInvite;
                    if (showInvite) showCreate = false;
                }}
                class="rounded-md border border-blue-600 px-4 py-2 text-sm font-medium text-blue-600 transition hover:bg-blue-50">
                {showInvite ? t("common.cancel") : t("users.invite_btn")}
            </button>
            <button
                type="button"
                onclick={() => {
                    showCreate = !showCreate;
                    if (showCreate) showInvite = false;
                }}
                class="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-blue-700">
                {showCreate ? t("common.cancel") : t("users.add_btn")}
            </button>
        </div>
    </div>

    {#if showInvite}
        <div class="rounded-xl border border-blue-100 bg-blue-50 p-5">
            <h2 class="mb-1 font-semibold text-blue-900">{t("users.invite_title")}</h2>
            <p class="mb-4 text-xs text-blue-700">{t("users.invite_hint")}</p>

            {#if inviteErr}
                <div class="mb-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                    {inviteErr}
                </div>
            {/if}

            <form
                method="POST"
                action="?/invite"
                use:enhance={() => {
                    return ({ result, update }) => {
                        update();
                        if (result.type === "success") showInvite = false;
                    };
                }}
                class="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                    <label for="invite-email" class="block text-xs font-medium text-gray-700">{t("users.email_label")}</label>
                    <input
                        id="invite-email"
                        type="email"
                        name="email"
                        required
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="invite-username" class="block text-xs font-medium text-gray-700">{t("users.username_label")}</label>
                    <input id="invite-username" type="text" name="username" class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="invite-displayName" class="block text-xs font-medium text-gray-700">{t("users.display_name_label")}</label>
                    <input
                        id="invite-displayName"
                        type="text"
                        name="displayName"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="invite-role" class="block text-xs font-medium text-gray-700">{t("users.role_label")}</label>
                    <select id="invite-role" name="role" class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none">
                        <option value="user">{t("users.role_user")}</option>
                        <option value="admin">{t("users.role_admin")}</option>
                    </select>
                </div>
                <div class="flex justify-end sm:col-span-2">
                    <button type="submit" class="rounded-md bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700">{t("users.invite_submit")}</button>
                </div>
            </form>
        </div>
    {/if}

    {#if showCreate}
        <div class="rounded-xl border border-blue-100 bg-blue-50 p-5">
            <h2 class="mb-4 font-semibold text-blue-900">{t("users.create_title")}</h2>

            {#if createErr}
                <div class="mb-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                    {createErr}
                </div>
            {/if}

            <form
                method="POST"
                action="?/create"
                use:enhance={() => {
                    return ({ result, update }) => {
                        update();
                        if (result.type === "success") showCreate = false;
                    };
                }}
                class="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                    <label for="new-email" class="block text-xs font-medium text-gray-700">{t("users.email_label")}</label>
                    <input id="new-email" type="email" name="email" required class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="new-username" class="block text-xs font-medium text-gray-700">{t("users.username_label")}</label>
                    <input id="new-username" type="text" name="username" class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="new-displayName" class="block text-xs font-medium text-gray-700">{t("users.display_name_label")}</label>
                    <input
                        id="new-displayName"
                        type="text"
                        name="displayName"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                    <label for="new-role" class="block text-xs font-medium text-gray-700">{t("users.role_label")}</label>
                    <select id="new-role" name="role" class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none">
                        <option value="user">{t("users.role_user")}</option>
                        <option value="admin">{t("users.role_admin")}</option>
                    </select>
                </div>
                <div class="sm:col-span-2">
                    <label for="new-password" class="block text-xs font-medium text-gray-700">{t("users.password_label")}</label>
                    <input
                        id="new-password"
                        type="password"
                        name="password"
                        required
                        minlength="8"
                        class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
                </div>
                <div class="flex justify-end sm:col-span-2">
                    <button type="submit" class="rounded-md bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700">{t("common.add")}</button>
                </div>
            </form>
        </div>
    {/if}

    {#if formErr && !createErr && !inviteErr && !resetErr}
        <div class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {formErr}
        </div>
    {/if}

    <form method="GET" class="mb-4 flex items-center gap-2">
        <input
            type="search"
            name="q"
            value={data.search ?? ""}
            placeholder={t("users.search_placeholder")}
            class="w-full max-w-sm rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none" />
        <button type="submit" class="rounded-md bg-gray-800 px-4 py-1.5 text-sm font-medium text-white hover:bg-gray-900">{t("common.search")}</button>
    </form>

    <div class="overflow-x-auto rounded-xl border border-gray-200 bg-white shadow-sm">
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("users.col_id_email")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("users.col_name")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("users.col_role")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("common.status")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("common.created")}</th>
                    <th class="px-4 py-3 text-left text-xs font-medium tracking-wider text-gray-500 uppercase">{t("common.actions")}</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-200">
                {#if data.users.length === 0}
                    <tr>
                        <td colspan="6" class="px-6 py-8 text-center text-sm text-gray-500">{t("users.empty")}</td>
                    </tr>
                {:else}
                    {#each data.users as user (user.id)}
                        <tr class="hover:bg-gray-50">
                            <td class="px-4 py-3">
                                <a href={resolve(`/admin/users/${user.id}`)} class="block hover:underline">
                                    <p class="text-sm font-medium text-gray-900">
                                        {user.username ?? "-"}
                                    </p>
                                    <p class="flex items-center gap-1.5 text-xs text-gray-500">
                                        {user.email}
                                        {#if user.emailVerified}
                                            <span class="rounded-full bg-green-100 px-1.5 py-0.5 text-[10px] font-medium text-green-700">{t("users.badge_email_verified")}</span>
                                        {:else}
                                            <span class="rounded-full bg-gray-100 px-1.5 py-0.5 text-[10px] font-medium text-gray-500">{t("users.badge_email_unverified")}</span>
                                        {/if}
                                    </p>
                                </a>
                            </td>
                            <td class="px-4 py-3 text-sm text-gray-600">{user.displayName ?? "-"}</td>

                            <td class="px-4 py-3">
                                <form method="POST" action="?/updateRole" use:enhance>
                                    <input type="hidden" name="id" value={user.id} />
                                    <select
                                        name="role"
                                        onchange={(e) => (e.currentTarget.closest("form") as HTMLFormElement).requestSubmit()}
                                        class="rounded border border-gray-200 bg-transparent py-0.5 text-xs text-gray-700 focus:outline-none">
                                        <option value="user" selected={user.role === "user"}>{t("users.role_user_short")}</option>
                                        <option value="admin" selected={user.role === "admin"}>{t("users.role_admin")}</option>
                                    </select>
                                </form>
                            </td>

                            <td class="px-4 py-3">
                                <div class="flex items-center gap-2">
                                    <span class="rounded-full px-2 py-0.5 text-xs font-medium {STATUS_COLOR[user.status]}">
                                        {t(`users.status_${user.status}`)}
                                    </span>
                                    {#if user.pendingInvite}
                                        <span class="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-700">
                                            {t("users.badge_pending_invite")}
                                        </span>
                                    {/if}
                                    {#if STATUS_NEXT[user.status]}
                                        <form method="POST" action="?/updateStatus" use:enhance>
                                            <input type="hidden" name="id" value={user.id} />
                                            <input type="hidden" name="status" value={STATUS_NEXT[user.status].status} />
                                            <button type="submit" class="text-xs text-gray-400 hover:text-gray-700 hover:underline">
                                                {t(STATUS_NEXT[user.status].labelKey)}
                                            </button>
                                        </form>
                                    {/if}
                                </div>
                            </td>

                            <td class="px-4 py-3 text-xs text-gray-400">{dateFormatter.format(user.createdAt)}</td>

                            <td class="px-4 py-3">
                                <div class="flex items-center gap-2">
                                    <button type="button" onclick={() => (resetPasswordUserId = resetPasswordUserId === user.id ? null : user.id)} class="text-xs text-blue-500 hover:text-blue-700">
                                        {t("users.reset_password")}
                                    </button>

                                    <form method="POST" action="?/delete" use:enhance>
                                        <input type="hidden" name="id" value={user.id} />
                                        <button
                                            type="submit"
                                            class="text-xs text-red-400 hover:text-red-600"
                                            onclick={(e) => {
                                                if (!confirm(t("users.delete_confirm"))) e.preventDefault();
                                            }}>
                                            {t("common.delete")}
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>

                        {#if resetPasswordUserId === user.id}
                            <tr class="bg-blue-50">
                                <td colspan="6" class="px-4 py-3">
                                    {#if resetErr}
                                        <p class="mb-2 text-xs text-red-600">{resetErr}</p>
                                    {/if}
                                    <form
                                        method="POST"
                                        action="?/resetPassword"
                                        use:enhance={() => {
                                            return ({ result, update }) => {
                                                update();
                                                if (result.type === "success") resetPasswordUserId = null;
                                            };
                                        }}
                                        class="flex items-center gap-2">
                                        <input type="hidden" name="id" value={user.id} />
                                        <input
                                            type="password"
                                            name="newPassword"
                                            required
                                            minlength="8"
                                            placeholder={t("users.new_password_placeholder")}
                                            class="rounded-md border border-gray-300 px-3 py-1 text-sm focus:border-blue-500 focus:outline-none" />
                                        <button type="submit" class="rounded-md bg-blue-600 px-3 py-1 text-xs font-medium text-white hover:bg-blue-700">{t("common.change")}</button>
                                        <button type="button" onclick={() => (resetPasswordUserId = null)} class="text-xs text-gray-400 hover:text-gray-600">{t("common.cancel")}</button>
                                    </form>
                                </td>
                            </tr>
                        {/if}
                    {/each}
                {/if}
            </tbody>
        </table>
    </div>

    {#if data.nextCursor}
        <div class="mt-4 flex justify-center">
            <a
                href="{resolve('/admin/users')}?{new URLSearchParams({ ...(data.search ? { q: data.search } : {}), cursor: String(data.nextCursor) }).toString()}"
                class="rounded-md border border-gray-300 bg-white px-4 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50">
                {t("common.next_page")}
            </a>
        </div>
    {/if}
</div>
