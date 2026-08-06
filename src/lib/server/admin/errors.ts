/**
 * admin 서버 액션용 i18n 에러 헬퍼.
 *
 * auth 라우트의 `translate(locals.locale, ...)` 패턴을 admin 액션에도 동일하게 적용한다.
 * 모든 admin 에러 메시지는 i18n 사전의 `admin.errors.*` 네임스페이스에 대칭(ko/en)으로 존재한다.
 */
import { fail } from "@sveltejs/kit";
import type { Locale } from "$lib/i18n/core";
import { translate } from "$lib/i18n/server";
import { isValidCsrf } from "$lib/server/auth/csrf";
import type { Cookies } from "@sveltejs/kit";

/** admin.errors.<key> 를 현재 로케일로 해석한다. params 는 {{placeholder}} 치환용. */
export function adminError(locale: Locale, key: string, params?: Record<string, string | number>): string {
    return translate(locale, `admin.errors.${key}`, params);
}

/**
 * FormData 에서 필수 id 계열 필드를 파싱한다. 값이 없으면 400 fail(로케일 인지 "잘못된 요청입니다") 반환.
 * admin 라우트 전반에서 12곳+ 반복되던 `if (!id) return fail(400, { error: "잘못된 요청입니다." })` 를 일원화한다.
 *
 * 반환은 판별 유니온: ok=true 면 파싱된 id, ok=false 면 그대로 반환할 fail 결과.
 * extra 로 기존 에러 shape 의 부가 필드(예: { create: true }, { update: true, updateId })를 보존한다.
 */
export function requireFormId(
    fd: FormData,
    locale: Locale,
    opts: { field?: string; extra?: Record<string, unknown> } = {},
): { ok: true; id: string } | { ok: false; failure: ReturnType<typeof fail> } {
    const field = opts.field ?? "id";
    const id = String(fd.get(field) ?? "");
    if (!id) {
        return { ok: false, failure: fail(400, { ...(opts.extra ?? {}), error: adminError(locale, "invalid_request") }) };
    }
    return { ok: true, id };
}

/**
 * admin 액션의 double-submit CSRF 검증.
 *
 * `/admin` 은 hooks 의 Origin/Referer 검사가 이미 막고 있다(둘 다 없으면 403). 이것은 그 위의
 * 2차 계층이고, 예전에는 클라이언트 목록 화면에만 적용돼 있어 상세 화면 액션들은 빠져 있었다.
 * 계층이 화면마다 다르면 어느 것이 보호되는지 읽는 사람이 알 수 없으므로 상세 화면 전체에 맞춘다.
 *
 * 실패 시 그대로 반환할 fail(403) 을 돌려주고, 통과면 null.
 * 사용: `const bad = requireCsrf(event, fd); if (bad) return bad;`
 */
export function requireCsrf(event: { cookies: Cookies; locals: App.Locals }, formData: FormData) {
    if (isValidCsrf(event.cookies, formData)) return null;
    return fail(403, { error: adminError(event.locals.locale, "csrf_failed") });
}
