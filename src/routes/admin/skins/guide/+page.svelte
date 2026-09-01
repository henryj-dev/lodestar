<script lang="ts">
import { resolve } from "$app/paths";
import { t } from "$lib/i18n.svelte";

// 스킨 타입은 client_skins.skin_type enum 과 1:1 이다. 여기 목록이 실제보다 적으면
// 관리자가 등록 가능한 페이지를 모르고 지나가므로 enum 을 그대로 옮겨 둔다.
const skinTypes = [
    { type: "login", path: "/login" },
    { type: "signup", path: "/signup" },
    { type: "find_id", path: "/find-id" },
    { type: "find_password", path: "/find-password" },
    { type: "mfa", path: "/mfa" },
    { type: "reset_password", path: "/reset-password" },
    { type: "verify_email", path: "/verify-email" },
    { type: "accept_invite", path: "/accept-invite" },
    { type: "confirm_email_change", path: "/account/confirm-email-change" },
    { type: "logout", path: "/logout" },
    { type: "consent", path: "/consent" },
    { type: "terms", path: "/terms" },
] as const;

// 치환자와 그것을 채우는 페이지. 서버가 채우지 않는 치환자는 빈 문자열로 지워진다.
const placeholders = [
    { key: "IDP_FORM_ACTION", pages: [], desc: () => t("skins.placeholder_form_action") },
    { key: "IDP_REDIRECT_TO", pages: [], desc: () => t("skins.placeholder_redirect_to") },
    { key: "IDP_SKIN_HINT", pages: [], desc: () => t("skins.placeholder_skin_hint") },
    { key: "IDP_FLASH_MSG", pages: [], desc: () => t("skins.placeholder_flash_msg") },
    { key: "IDP_REGISTERED", pages: ["login"], desc: () => t("skins.placeholder_registered") },
    { key: "IDP_PASSWORD_RESET", pages: ["login"], desc: () => t("skins.placeholder_password_reset") },
    { key: "IDP_SOCIAL_BUTTONS", pages: ["login"], desc: () => t("skins.placeholder_social_buttons") },
    { key: "IDP_FIND_ID_SENT", pages: ["find_id"], desc: () => t("skins.placeholder_find_id_sent") },
    { key: "IDP_MASKED_USERNAME", pages: ["find_id"], desc: () => t("skins.placeholder_masked_username") },
    { key: "IDP_FIND_PASSWORD_SENT", pages: ["find_password"], desc: () => t("skins.placeholder_find_password_sent") },
    { key: "IDP_SUBMITTED_EMAIL", pages: ["find_password"], desc: () => t("skins.placeholder_submitted_email") },
    { key: "IDP_TOKEN", pages: ["reset_password", "verify_email"], desc: () => t("skins.placeholder_token") },
    { key: "IDP_VERIFIED", pages: ["verify_email"], desc: () => t("skins.placeholder_verified") },
    { key: "IDP_CLIENT_NAME", pages: ["consent"], desc: () => t("skins.placeholder_client_name") },
    { key: "IDP_REQUIRED_SCOPES", pages: ["consent"], desc: () => t("skins.placeholder_required_scopes") },
    { key: "IDP_OPTIONAL_SCOPES", pages: ["consent"], desc: () => t("skins.placeholder_optional_scopes") },
] as const;

/** 빈 배열은 전체 페이지 공통을 뜻한다. */
function pagesLabel(pages: readonly string[]): string {
    return pages.length === 0 ? t("skins.guide_placeholder_pages_all") : pages.map((p) => t(`skins.skin_type_${p}`)).join(" · ");
}

// 페이지별 필수 폼 필드(name). 서버 액션이 읽는 이름과 정확히 같아야 한다.
const formFields = [
    { type: "login", fields: "username, password, redirectTo" },
    { type: "signup", fields: "username, email, password, confirmPassword" },
    { type: "find_id", fields: "email" },
    { type: "find_password", fields: "username, email" },
    { type: "mfa", fields: "code" },
    { type: "reset_password", fields: "token, password, confirmPassword, redirectTo, skinHint" },
    { type: "verify_email", fields: "token" },
    { type: "accept_invite", fields: "token, password, confirmPassword" },
    { type: "confirm_email_change", fields: "token" },
    { type: "logout", fields: "—" },
    { type: "consent", fields: "optionalScope (선택 항목마다 반복)" },
    { type: "terms", fields: "termsKey (항목마다 반복)" },
] as const;

const exampleHtml = `<!DOCTYPE html>
<html lang="ko">
<head>
  <title>${"로그인"}</title>
  <!-- <style> 은 허용된다. 내용은 정화되며 position/z-index 계열만 제거된다. -->
  <style>
    body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
           background:#f9fafb; font-family:sans-serif }
    .card { width:100%; max-width:360px; padding:32px; background:#fff;
            border:1px solid #e5e7eb; border-radius:12px }
    .field { display:block; width:100%; box-sizing:border-box; padding:8px 12px;
             margin:4px 0 12px; border:1px solid #d1d5db; border-radius:6px }
    .field:focus { outline:2px solid #2563eb; outline-offset:1px }   /* 의사클래스 사용 가능 */
    button { width:100%; padding:10px; background:#2563eb; color:#fff;
             border:none; border-radius:6px }
    button:hover { background:#1d4ed8 }
    #flash-msg { margin:0 0 12px; color:#b91c1c; font-size:13px }
    @media (max-width:420px) { .card { padding:20px } }             /* 미디어 쿼리 사용 가능 */
  </style>
</head>
<body>
  <!-- data-skin-type 을 맞추면 IDP 공통 스크립트가 이 페이지를 초기화한다. -->
  <div class="auth-shell" data-skin-type="login">
    <div class="card">
      <h1 style="margin:0 0 24px;font-size:20px">${"로그인"}</h1>

      <!-- 서버가 채우는 오류 메시지. 비어 있으면 아무것도 보이지 않는다. -->
      <p id="flash-msg">{{IDP_FLASH_MSG}}</p>

      <!-- action 을 비워 둔다: 정화가 외부 action 을 제거하고, 빈 action 은 IDP 로 POST 된다. -->
      <form method="POST">
        <input type="hidden" name="redirectTo" value="{{IDP_REDIRECT_TO}}">
        <input type="hidden" name="skinHint" value="{{IDP_SKIN_HINT}}">

        <label for="username" style="font-size:12px;color:#374151">${"아이디"}</label>
        <input id="username" name="username" type="text" class="field" autocomplete="username" required>

        <label for="password" style="font-size:12px;color:#374151">${"비밀번호"}</label>
        <input id="password" name="password" type="password" class="field" autocomplete="current-password" required>

        <button id="submit" type="submit">${"로그인"}</button>
      </form>

      <!-- 활성화된 소셜 로그인 버튼이 이 자리에 주입된다(없으면 빈 문자열). -->
      {{IDP_SOCIAL_BUTTONS}}
    </div>
  </div>
</body>
</html>`;
</script>

<div class="max-w-3xl space-y-8">
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">{t("skins.guide_title")}</h1>
            <p class="mt-1 text-sm text-gray-500">{t("skins.guide_subtitle")}</p>
        </div>
        <a href={resolve("/admin/skins")} class="rounded-md border border-gray-300 px-4 py-2 text-sm text-gray-600 hover:bg-gray-50">
            ← {t("skins.title")}
        </a>
    </div>

    <!-- 개요 -->
    <section class="space-y-3 rounded-xl border border-gray-200 bg-white p-6">
        <h2 class="text-base font-semibold text-gray-900">{t("skins.guide_overview_title")}</h2>
        <p class="text-sm leading-relaxed text-gray-600">{t("skins.guide_overview_desc")}</p>
        <div class="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {#each skinTypes as item (item.type)}
                <div class="rounded-lg border border-gray-100 bg-gray-50 px-3 py-2 text-center">
                    <p class="text-xs font-medium text-gray-700">{t(`skins.skin_type_${item.type}`)}</p>
                    <p class="mt-0.5 font-mono text-xs text-gray-400">{item.path}</p>
                </div>
            {/each}
        </div>
    </section>

    <!-- 테넌트 기본 스킨 -->
    <section class="space-y-3 rounded-xl border border-gray-200 bg-white p-6">
        <h2 class="text-base font-semibold text-gray-900">{t("skins.guide_default_title")}</h2>
        <p class="text-sm leading-relaxed text-gray-600">{t("skins.guide_default_desc")}</p>
        <ul class="list-inside list-disc space-y-1.5 text-sm leading-relaxed text-gray-600">
            <li>{t("skins.guide_default_1")}</li>
            <li>{t("skins.guide_default_2")}</li>
            <li>{t("skins.guide_default_3")}</li>
        </ul>
    </section>

    <!-- 동작 흐름 -->
    <section class="space-y-3 rounded-xl border border-gray-200 bg-white p-6">
        <h2 class="text-base font-semibold text-gray-900">{t("skins.guide_flow_title")}</h2>
        <ol class="list-inside list-decimal space-y-2 text-sm leading-relaxed text-gray-600">
            <li>{t("skins.guide_flow_1")}</li>
            <li>{t("skins.guide_flow_2")}</li>
            <li>{t("skins.guide_flow_3")}</li>
            <li>{t("skins.guide_flow_4")}</li>
            <li>{t("skins.guide_flow_5")}</li>
        </ol>
    </section>

    <!-- 제약: sanitize -->
    <section class="space-y-4 rounded-xl border border-amber-200 bg-amber-50/40 p-6">
        <div>
            <h2 class="text-base font-semibold text-gray-900">{t("skins.guide_limits_title")}</h2>
            <p class="mt-1 text-sm leading-relaxed text-gray-600">{t("skins.guide_limits_intro")}</p>
        </div>
        <dl class="space-y-3 text-sm">
            {#each [{ label: t("skins.guide_limits_tags_label"), value: "script, style, link, meta, iframe, object, embed, base", desc: t("skins.guide_limits_tags") }, { label: t("skins.guide_limits_attrs_label"), value: "on*, action, formaction, srcdoc, sandbox, background", desc: t("skins.guide_limits_attrs") }, { label: t("skins.guide_limits_style_label"), value: "position, top/left/right/bottom, inset*, z-index, transform*, perspective, float, clip*", desc: t("skins.guide_limits_style") }, { label: t("skins.guide_limits_uri_label"), value: "https:, http:, data:image/, data:font/, mailto:, tel:, /, #", desc: t("skins.guide_limits_uri") }] as row (row.label)}
                <div>
                    <dt class="font-medium text-gray-800">{row.label}</dt>
                    <dd class="mt-0.5 font-mono text-xs break-words text-gray-500">{row.value}</dd>
                    <dd class="mt-1 text-xs leading-relaxed text-gray-600">{row.desc}</dd>
                </div>
            {/each}
        </dl>
        <p class="rounded-lg border border-amber-200 bg-white px-4 py-3 text-xs leading-relaxed text-amber-900">{t("skins.guide_limits_css_note")}</p>
        <p class="text-xs leading-relaxed text-gray-600">{t("skins.guide_limits_transport")}</p>
    </section>

    <!-- 치환자 -->
    <section class="space-y-4 rounded-xl border border-gray-200 bg-white p-6">
        <h2 class="text-base font-semibold text-gray-900">{t("skins.guide_placeholders_title")}</h2>
        <p class="text-sm leading-relaxed text-gray-600">{t("skins.guide_placeholders_desc")}</p>
        <table class="min-w-full text-sm">
            <thead>
                <tr class="border-b border-gray-100">
                    <th class="w-56 pb-2 text-left text-xs font-medium text-gray-500 uppercase">{t("skins.guide_placeholder_col_name")}</th>
                    <th class="w-28 pb-2 text-left text-xs font-medium text-gray-500 uppercase">{t("skins.guide_placeholder_col_pages")}</th>
                    <th class="pb-2 text-left text-xs font-medium text-gray-500 uppercase">{t("skins.guide_placeholder_col_desc")}</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-50">
                {#each placeholders as row (row.key)}
                    <tr>
                        <td class="py-2.5 pr-4">
                            <code class="rounded bg-gray-100 px-2 py-0.5 font-mono text-xs text-blue-700">&#123;&#123;{row.key}&#125;&#125;</code>
                        </td>
                        <td class="py-2.5 pr-4 text-xs text-gray-500">{pagesLabel(row.pages)}</td>
                        <td class="py-2.5 text-xs text-gray-600">{row.desc()}</td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </section>

    <!-- 폼 필드 계약 -->
    <section class="space-y-3 rounded-xl border border-gray-200 bg-white p-6">
        <h2 class="text-base font-semibold text-gray-900">{t("skins.guide_fields_title")}</h2>
        <p class="text-sm leading-relaxed text-gray-600">{t("skins.guide_fields_desc")}</p>
        <table class="min-w-full text-sm">
            <tbody class="divide-y divide-gray-50">
                {#each formFields as row (row.type)}
                    <tr>
                        <td class="w-32 py-2 pr-4 text-xs font-medium text-gray-700">{t(`skins.skin_type_${row.type}`)}</td>
                        <td class="py-2 font-mono text-xs text-gray-600">{row.fields}</td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </section>

    <!-- 스크립트 훅 -->
    <section class="space-y-3 rounded-xl border border-gray-200 bg-white p-6">
        <h2 class="text-base font-semibold text-gray-900">{t("skins.guide_hooks_title")}</h2>
        <p class="text-sm leading-relaxed text-gray-600">{t("skins.guide_hooks_desc")}</p>
        <table class="min-w-full text-sm">
            <tbody class="divide-y divide-gray-50">
                {#each [{ sel: ".auth-shell[data-skin-type]", desc: t("skins.guide_hooks_shell") }, { sel: "#flash · #flash-msg", desc: t("skins.guide_hooks_flash") }, { sel: "#skin-meta[data-*]", desc: t("skins.guide_hooks_meta") }, { sel: "#username · #password · #confirm · #submit", desc: t("skins.guide_hooks_fields") }, { sel: "#passkey", desc: t("skins.guide_hooks_passkey") }] as row (row.sel)}
                    <tr>
                        <td class="w-72 py-2 pr-4 font-mono text-xs break-words text-gray-700">{row.sel}</td>
                        <td class="py-2 text-xs text-gray-600">{row.desc}</td>
                    </tr>
                {/each}
            </tbody>
        </table>
        <p class="text-xs leading-relaxed text-gray-500">{t("skins.guide_hooks_note")}</p>
    </section>

    <!-- X-IDP-Token -->
    <section class="space-y-3 rounded-xl border border-gray-200 bg-white p-6">
        <h2 class="text-base font-semibold text-gray-900">{t("skins.guide_auth_title")}</h2>
        <p class="text-sm leading-relaxed text-gray-600">{t("skins.guide_auth_desc")}</p>
        <div class="rounded-lg bg-gray-900 p-4">
            <pre class="overflow-x-auto text-xs text-green-400">{`${t("skins.guide_code_comment")}
app.get('/login-skin.html', (req, res) => {
  const token = req.headers['x-idp-token'];
  if (token !== process.env.SKIN_SECRET) {
    return res.status(401).send('Unauthorized');
  }
  res.sendFile('./login-skin.html');
});`}</pre>
        </div>
    </section>

    <!-- 스킨 HTML 예시 -->
    <section class="space-y-3 rounded-xl border border-gray-200 bg-white p-6">
        <h2 class="text-base font-semibold text-gray-900">{t("skins.guide_example_title")}</h2>
        <p class="text-sm text-gray-500">{t("skins.guide_example_login_desc")}</p>
        <div class="rounded-lg bg-gray-900 p-4">
            <pre class="overflow-x-auto text-xs text-gray-300">{exampleHtml}</pre>
        </div>
        <div class="space-y-1 rounded-lg border border-amber-100 bg-amber-50 px-4 py-3 text-xs text-amber-800">
            <p class="font-medium">{t("skins.guide_example_note_title")}</p>
            <ul class="list-inside list-disc space-y-0.5">
                <li>{t("skins.guide_example_note_1")}</li>
                <li>{t("skins.guide_example_note_2")}</li>
                <li>{t("skins.guide_example_note_3")}</li>
                <li>{t("skins.guide_example_note_4")}</li>
            </ul>
        </div>
    </section>

    <!-- 캐시 동작 -->
    <section class="space-y-3 rounded-xl border border-gray-200 bg-white p-6">
        <h2 class="text-base font-semibold text-gray-900">{t("skins.guide_cache_title")}</h2>
        <ul class="list-inside list-disc space-y-1.5 text-sm leading-relaxed text-gray-600">
            <li>{t("skins.guide_cache_1")}</li>
            <li>{t("skins.guide_cache_2")}</li>
            <li>{t("skins.guide_cache_3")}</li>
            <li>{t("skins.guide_cache_4")}</li>
        </ul>
    </section>

    <!-- 등록 방법 -->
    <section class="space-y-3 rounded-xl border border-gray-200 bg-white p-6">
        <h2 class="text-base font-semibold text-gray-900">{t("skins.guide_setup_title")}</h2>
        <ol class="list-inside list-decimal space-y-2 text-sm leading-relaxed text-gray-600">
            <li>{t("skins.guide_setup_1")}</li>
            <li>{t("skins.guide_setup_2")}</li>
            <li>{t("skins.guide_setup_3")}</li>
            <li>{t("skins.guide_setup_4")}</li>
        </ol>
        <a href={resolve("/admin/skins")} class="mt-2 inline-block rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700">
            {t("skins.title")} →
        </a>
    </section>
</div>
