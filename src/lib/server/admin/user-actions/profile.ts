import { fail } from "@sveltejs/kit";
import type { RequestEvent } from "@sveltejs/kit";
import { and, eq } from "drizzle-orm";
import { requireAdminContext, assertNotLastAdmin, assertUserInTenant } from "$lib/server/auth/guards";
import { revokeAllUserSessions } from "$lib/server/auth/session";
import { revokeAllUserRefreshTokens } from "$lib/server/oidc/refresh";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";
import { users } from "$lib/server/db/schema";
import { adminError, requireCsrf } from "$lib/server/admin/errors";

// 사용자 상세 페이지의 프로필/역할/상태 수정 액션.
type UserActionEvent = RequestEvent<{ id: string }, "/admin/users/[id]">;

// 프로필 수정
export async function updateProfile(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const uiLocale = locals.locale;
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;
    const userId = params.id;

    const rawRole = String(fd.get("role") ?? "user");
    const rawStatus = String(fd.get("status") ?? "active");

    if (rawRole !== "admin" && rawRole !== "user") {
        return fail(400, { error: adminError(uiLocale, "invalid_role_value") });
    }
    if (rawStatus !== "active" && rawStatus !== "disabled" && rawStatus !== "locked") {
        return fail(400, { error: adminError(uiLocale, "invalid_status_value") });
    }

    const role = rawRole as "admin" | "user";
    const status = rawStatus as "active" | "disabled" | "locked";

    // ctrls C-13: cross-tenant IDOR 차단. params.id 가 본 tenant user 인지 명시 검증.
    const tenantCheck = await assertUserInTenant(db, tenant.id, userId);
    if (!tenantCheck.ok) return tenantCheck.error;

    // 변경 전 role/status 캡처 — 자기-자신 가드, race 가드, role 변경 감지 모두에 사용
    const [before] = await db
        .select({ role: users.role, status: users.status })
        .from(users)
        .where(and(eq(users.id, userId), eq(users.tenantId, tenant.id)))
        .limit(1);

    // ctrls C-12: 자기 자신의 role/status 변경은 무조건 차단.
    // 값이 현재와 같더라도 폼 안에서 admin 이 자기 권한을 손대는 흐름 자체를
    // 차단해야 race 우회 가능성을 없앤다 (다른 admin 에게 요청해야 함).
    // 또한 폼이 전송한 role/status 를 무시하고 DB 현재 값을 그대로 유지한다.
    let effectiveRole = role;
    // status enum 에 deletion_pending(셀프서비스 탈퇴)이 추가되어 users.status 추론 타입이 넓어졌다.
    // 자기-자신 편집 시 DB 현재 값(before.status)을 그대로 유지하는데, 그 값이 deletion_pending 일
    // 수도 있으므로 넓은 유니온으로 선언한다(관리자 폼 입력은 위에서 좁게 검증됨).
    let effectiveStatus: "active" | "disabled" | "locked" | "deletion_pending" = status;
    if (userId === locals.user!.id) {
        if (before && (before.role !== role || before.status !== status)) {
            return fail(400, { error: adminError(uiLocale, "cannot_change_own_role_status") });
        }
        effectiveRole = before?.role ?? role;
        effectiveStatus = before?.status ?? status;
    }

    // 마지막 활성 관리자 보호 — admin 강등 또는 active 해제 시 사전 검사
    const isAdminRemoval = effectiveRole === "user" || effectiveStatus !== "active";
    if (isAdminRemoval) {
        const lastAdminFail = await assertNotLastAdmin(db, tenant.id, userId);
        if (lastAdminFail) return lastAdminFail;
    }

    const displayName = String(fd.get("displayName") ?? "").trim() || null;
    const givenName = String(fd.get("givenName") ?? "").trim() || null;
    const familyName = String(fd.get("familyName") ?? "").trim() || null;
    const phoneNumber = String(fd.get("phoneNumber") ?? "").trim() || null;
    const bio = String(fd.get("bio") ?? "").trim() || null;
    const birthdate = String(fd.get("birthdate") ?? "").trim() || null;
    const locale = String(fd.get("locale") ?? "ko-KR").trim();
    const zoneinfo = String(fd.get("zoneinfo") ?? "Asia/Seoul").trim();
    // 주소 (OIDC address 클레임 구성요소). 빈 값은 null 로 저장.
    const addressStreet = String(fd.get("addressStreet") ?? "").trim() || null;
    const addressLocality = String(fd.get("addressLocality") ?? "").trim() || null;
    const addressRegion = String(fd.get("addressRegion") ?? "").trim() || null;
    const addressPostalCode = String(fd.get("addressPostalCode") ?? "").trim() || null;
    const addressCountry = String(fd.get("addressCountry") ?? "").trim() || null;

    await db
        .update(users)
        .set({
            displayName,
            givenName,
            familyName,
            phoneNumber,
            bio,
            birthdate,
            locale,
            zoneinfo,
            addressStreet,
            addressLocality,
            addressRegion,
            addressPostalCode,
            addressCountry,
            role: effectiveRole,
            status: effectiveStatus,
            updatedAt: new Date(),
        })
        .where(and(eq(users.id, userId), eq(users.tenantId, tenant.id)));

    // ctrls C-12: race 가드 — UPDATE 직후 invariant 재확인.
    // 두 admin 이 동시에 서로 강등하면 사전 assertNotLastAdmin 가 둘 다
    // 통과해 0 admin 상태가 될 수 있다. UPDATE 직후 활성 admin 카운트를
    // 다시 세고 0 이면 본 UPDATE 의 role/status 만 즉시 되돌린다.
    if (isAdminRemoval) {
        const remaining = await db
            .select({ id: users.id })
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.role, "admin"), eq(users.status, "active")))
            .limit(1);
        if (remaining.length === 0 && before) {
            await db
                .update(users)
                .set({ role: before.role, status: before.status, updatedAt: new Date() })
                .where(and(eq(users.id, userId), eq(users.tenantId, tenant.id)));
            return fail(409, { error: adminError(uiLocale, "last_admin_race") });
        }
    }

    // role 변경 시 기존 세션 + OIDC refresh token 전부 파기 — 이전 권한 캐시 차단
    if (before && before.role !== effectiveRole) {
        await revokeAllUserSessions(db, userId);
        await revokeAllUserRefreshTokens(db, userId);
    }

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId,
        actorId: locals.user!.id,
        kind: "user_profile_updated",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { role: effectiveRole, status: effectiveStatus },
    });

    return { updated: true };
}
