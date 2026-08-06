<script lang="ts">
import type { Snippet } from "svelte";
import type { LayoutData } from "./$types";
import { resolve } from "$app/paths";
import { t } from "$lib/i18n.svelte";
import { page } from "$app/state";

const { children, data } = $props<{ children: Snippet; data: LayoutData }>();

const menuItems = [
    { route: "/admin" as const, key: "admin.dashboard" },
    { route: "/admin/users" as const, key: "admin.users" },
    { route: "/admin/oidc-clients" as const, key: "admin.oidc_clients" },
    { route: "/admin/saml-sps" as const, key: "admin.saml_sps" },
    { route: "/admin/signing-keys" as const, key: "admin.signing_keys" },
    { route: "/admin/service-tokens" as const, key: "admin.service_tokens" },
    { route: "/admin/ldap-providers" as const, key: "admin.ldap_providers" },
    { route: "/admin/skins" as const, key: "admin.skins" },
    { route: "/admin/audit" as const, key: "admin.audit" },
];

const orgMenuItems = [
    { route: "/admin/positions" as const, key: "admin.positions" },
    { route: "/admin/departments" as const, key: "admin.departments" },
    { route: "/admin/teams" as const, key: "admin.teams" },
    { route: "/admin/parts" as const, key: "admin.parts" },
];
</script>

{#if !data.currentUser}
    {@render children()}
{:else}
    <div class="flex min-h-screen bg-gray-50">
        <aside class="flex w-72 flex-col border-r border-gray-200 bg-white">
            <div class="flex h-16 items-center border-b border-gray-200 px-6">
                <a href={resolve("/admin")} class="text-xl font-bold text-gray-900">
                    {t("admin.title")}
                </a>
            </div>

            <div class="border-b border-gray-200 px-6 py-4">
                <p class="text-sm font-medium text-gray-900">
                    {data.currentUser.displayName ?? "관리자"}
                </p>
                <p class="text-sm text-gray-500">{data.currentUser.email}</p>
            </div>

            <nav class="space-y-4 p-4">
                <ul class="space-y-1">
                    {#each menuItems as item (item.key)}
                        <li>
                            <a
                                href={resolve(item.route)}
                                class="block rounded-md px-3 py-2 text-sm font-medium transition-colors {page.url.pathname === resolve(item.route)
                                    ? 'bg-blue-50 text-blue-700'
                                    : 'text-gray-700 hover:bg-gray-100'}">
                                {t(item.key)}
                            </a>
                        </li>
                    {/each}
                </ul>

                <div>
                    <p class="px-3 pb-1 text-xs font-semibold tracking-wider text-gray-400 uppercase">
                        {t("admin.org")}
                    </p>
                    <ul class="space-y-1">
                        {#each orgMenuItems as item (item.key)}
                            <li>
                                <a
                                    href={resolve(item.route)}
                                    class="block rounded-md px-3 py-2 text-sm font-medium transition-colors {page.url.pathname === resolve(item.route)
                                        ? 'bg-blue-50 text-blue-700'
                                        : 'text-gray-700 hover:bg-gray-100'}">
                                    {t(item.key)}
                                </a>
                            </li>
                        {/each}
                    </ul>
                </div>
            </nav>

            <div class="mt-auto p-4">
                <form method="POST" action={resolve("/logout")}>
                    <button type="submit" class="w-full rounded-md border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 transition hover:bg-gray-100">
                        {t("admin.logout")}
                    </button>
                </form>
            </div>
        </aside>

        <main class="flex-1 p-8">
            {@render children()}
        </main>
    </div>
{/if}
