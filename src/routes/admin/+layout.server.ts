import { error, redirect } from "@sveltejs/kit";
import type { LayoutServerLoad } from "./$types";
import { requireDbContext } from "$lib/server/auth/guards";
import { acrMeetsMfa } from "$lib/server/auth/constants";
import { hasTotpCredential } from "$lib/server/auth/users";
import { translate } from "$lib/i18n/server";

export const load: LayoutServerLoad = async ({ locals, url }) => {
    // 관리자 로그인 페이지는 인증 없이 접근 가능
    if (url.pathname === "/admin/login") {
        return { currentUser: null };
    }

    const { db } = requireDbContext(locals);

    if (!locals.user) {
        throw redirect(303, `/admin/login?redirectTo=${encodeURIComponent(url.pathname + url.search)}`);
    }

    if (locals.user.role !== "admin") {
        throw redirect(303, "/");
    }

    // 관리 콘솔은 MFA 를 통과한 세션만 허용한다.
    //
    // `/admin/login` 은 원래부터 TOTP 를 강제하지만(hasTotpCredential + /mfa), `/login` 으로
    // 만든 세션도 role=admin 이면 그대로 통과해서 TOTP 미등록 관리자가 password-only 세션으로
    // 콘솔에 들어올 수 있었다. TOTP 를 등록한 관리자는 로그인 시 이미 MFA 를 거치므로(신뢰 기기·
    // 패스키 경로도 ACR_MFA 를 만족) 이 게이트에 걸리지 않는다.
    //
    // ⚠️ 이 load 는 **form action 제출 시 실행되지 않는다.** action 직접 POST 를 막는 것은
    // guards.ts 의 requireAdminContext 이고, 여기는 사용자에게 승격 화면을 보여주기 위한 것이다.
    // 둘 중 하나만 있으면 반쪽이다.
    if (!acrMeetsMfa(locals.session?.acr ?? null)) {
        // TOTP 가 없으면 승격할 수단이 없다. 재인증으로 보내면 비밀번호로 로그인해도 ACR 이
        // 올라가지 않아 /admin ↔ /login 을 무한 왕복하므로, 등록을 안내하고 끝낸다.
        // (/account/mfa 는 admin 권한을 요구하지 않으므로 여기서 막혀도 탈출로가 있다.)
        if (!(await hasTotpCredential(db, locals.user.id))) {
            throw error(403, translate(locals.locale, "admin.errors.mfa_enrollment_required"));
        }
        const stepUpUrl = new URL("/mfa", url);
        stepUpUrl.searchParams.set("stepUp", "mfa");
        stepUpUrl.searchParams.set("redirectTo", url.pathname + url.search);
        throw redirect(303, stepUpUrl.pathname + stepUpUrl.search);
    }

    return {
        currentUser: {
            email: locals.user.email,
            displayName: locals.user.displayName,
            role: locals.user.role,
        },
    };
};
