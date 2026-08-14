<script lang="ts">
import { resolve } from "$app/paths";
import type { PageData } from "./$types";

const { data } = $props<{ data: PageData }>();

const initials = $derived((data.viewer.displayName ?? data.viewer.username ?? data.viewer.email).slice(0, 2).toUpperCase());
</script>

<main class="min-h-screen bg-gray-50 px-6 py-12">
    <div class="mx-auto max-w-4xl space-y-8">
        <header class="flex items-center justify-between">
            <div class="flex items-center gap-4">
                {#if data.viewer.avatarUrl}
                    <img src={data.viewer.avatarUrl} alt="" class="h-14 w-14 rounded-full object-cover" />
                {:else}
                    <div class="flex h-14 w-14 items-center justify-center rounded-full bg-gray-900 text-lg font-semibold text-white">{initials}</div>
                {/if}
                <div>
                    <p class="text-sm text-gray-500">안녕하세요</p>
                    <h1 class="text-2xl font-semibold text-gray-900">{data.viewer.displayName ?? data.viewer.username ?? data.viewer.email}</h1>
                    <p class="text-sm text-gray-500">{data.viewer.email}</p>
                </div>
            </div>
            <form method="POST" action={resolve("/logout")}>
                <button type="submit" class="rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">로그아웃</button>
            </form>
        </header>

        <section class="grid gap-4 sm:grid-cols-2">
            <a href={resolve("/account/profile")} class="group rounded-2xl border border-gray-200 bg-white p-6 transition hover:border-blue-400 hover:shadow-sm">
                <div class="flex items-start justify-between">
                    <div>
                        <h2 class="text-base font-semibold text-gray-900">프로필</h2>
                        <p class="mt-1 text-sm text-gray-500">이름, 연락처, 표시 언어 등 기본 정보를 관리합니다.</p>
                    </div>
                    <span class="text-gray-300 group-hover:text-blue-500">→</span>
                </div>
            </a>

            <a href={resolve("/account/mfa")} class="group rounded-2xl border border-gray-200 bg-white p-6 transition hover:border-blue-400 hover:shadow-sm">
                <div class="flex items-start justify-between">
                    <div>
                        <h2 class="text-base font-semibold text-gray-900">2단계 인증 (MFA)</h2>
                        <p class="mt-1 text-sm text-gray-500">
                            {#if data.security.totpCount > 0}
                                <span class="font-medium text-green-700">활성</span> · TOTP {data.security.totpCount}개 등록됨{#if data.security.backupCodesRemaining > 0}
                                    · 백업코드 {data.security.backupCodesRemaining}개 남음
                                {/if}
                            {:else}
                                <span class="font-medium text-amber-700">비활성</span> · TOTP 또는 패스키 등록 권장
                            {/if}
                        </p>
                    </div>
                    <span class="text-gray-300 group-hover:text-blue-500">→</span>
                </div>
            </a>

            <a href={resolve("/account/passkeys")} class="group rounded-2xl border border-gray-200 bg-white p-6 transition hover:border-blue-400 hover:shadow-sm">
                <div class="flex items-start justify-between">
                    <div>
                        <h2 class="text-base font-semibold text-gray-900">패스키</h2>
                        <p class="mt-1 text-sm text-gray-500">
                            {#if data.security.webauthnCount > 0}
                                {data.security.webauthnCount}개 등록됨 · 비밀번호 없이 로그인 가능
                            {:else}
                                등록된 패스키 없음 · YubiKey/Touch ID 등록 권장
                            {/if}
                        </p>
                    </div>
                    <span class="text-gray-300 group-hover:text-blue-500">→</span>
                </div>
            </a>

            <a href={resolve("/account/connections")} class="group rounded-2xl border border-gray-200 bg-white p-6 transition hover:border-blue-400 hover:shadow-sm">
                <div class="flex items-start justify-between">
                    <div>
                        <h2 class="text-base font-semibold text-gray-900">연결된 계정</h2>
                        <p class="mt-1 text-sm text-gray-500">네이버·카카오·GitHub 등 외부 계정 연결 관리</p>
                    </div>
                    <span class="text-gray-300 group-hover:text-blue-500">→</span>
                </div>
            </a>

            {#if data.viewer.role === "admin"}
                <a href={resolve("/admin")} class="group rounded-2xl border border-gray-900 bg-gray-900 p-6 text-white transition hover:bg-gray-800">
                    <div class="flex items-start justify-between">
                        <div>
                            <h2 class="text-base font-semibold">관리자 콘솔</h2>
                            <p class="mt-1 text-sm text-gray-300">사용자, 클라이언트, 권한, 감사 로그 관리</p>
                        </div>
                        <span class="text-gray-500 group-hover:text-white">→</span>
                    </div>
                </a>
            {/if}
        </section>
    </div>
</main>
