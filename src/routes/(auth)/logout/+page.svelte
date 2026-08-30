<script lang="ts">
import { onMount } from "svelte";
import { enhance } from "$app/forms";
import { t } from "$lib/i18n.svelte";
import type { PageData } from "./$types";

const { data } = $props<{ data: PageData }>();

let formEl = $state<HTMLFormElement | undefined>();

// 스킨이 없으면 기본 폼을 즉시 자동 제출한다(기존 동작). 스킨이 있으면 스킨 안의 폼을
// /api/skin-scripts 의 logout 초기화가 제출하므로 여기서는 스크립트만 주입한다.
onMount(() => {
    if (!data.skinHtml) {
        formEl?.requestSubmit();
        return;
    }
    const el = document.createElement("script");
    el.src = "/api/skin-scripts";
    document.head.appendChild(el);
    return () => {
        if (el.parentNode) el.parentNode.removeChild(el);
    };
});
</script>

{#if data.skinHtml}
    <!-- 커스텀 스킨 — 서버가 가져와 sanitize 한 HTML. 사용자 입력은 이 슬롯에 들어오지 않는다. -->
    <!-- eslint-disable-next-line svelte/no-at-html-tags -->
    {@html data.skinHtml}
{:else}
    <form method="POST" bind:this={formEl} use:enhance>
        <p>{t("logout.in_progress")}</p>
    </form>
{/if}
