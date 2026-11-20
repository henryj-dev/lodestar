import { fail } from "@sveltejs/kit";
import { desc, eq, and, lt, gt, or, sql, inArray, isNull } from "drizzle-orm";
import type { Actions, PageServerLoad } from "./$types";
import { requireAdminContext, assertNotLastAdmin } from "$lib/server/auth/guards";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";
import { dispatchSecurityAlert } from "$lib/server/security-notify";
import { users, credentials, inviteTokens } from "$lib/server/db/schema";
import { checkPasswordPolicy, hashPassword } from "$lib/server/auth/password";
import { normalizeEmail, normalizeUsername } from "$lib/server/auth/users";
import { PASSWORD_CREDENTIAL_TYPE } from "$lib/server/auth/constants";
import { revokeUserEverywhere } from "$lib/server/oidc/revoke-everywhere";
import { deleteUserNow } from "$lib/server/auth/account-deletion";
import { adminError, requireFormId } from "$lib/server/admin/errors";
import { runAtomic } from "$lib/server/db/atomic";
import { issueInvite } from "$lib/server/auth/invite";

const PAGE_SIZE = 50;

// LIKE 패턴의 와일드카드(%, _, \)를 이스케이프해 사용자 입력이 패턴으로 오작동하지 않게 한다.
function escapeLike(input: string): string {
    return input.replace(/[\\%_]/g, (c) => `\\${c}`);
}

export const load: PageServerLoad = async ({ locals, url }) => {
    const { db, tenant } = requireAdminContext(locals);

    const search = url.searchParams.get("q")?.trim() || null;
    const cursorParam = url.searchParams.get("cursor")?.trim() || null;
    const cursorMs = cursorParam ? Number.parseInt(cursorParam, 10) : NaN;
    const cursor = Number.isFinite(cursorMs) ? new Date(cursorMs) : null;

    const conditions = [eq(users.tenantId, tenant.id)];
    if (cursor) conditions.push(lt(users.createdAt, cursor));
    if (search) {
        // lower(...) LIKE 로 방언 무관 대소문자 무시 부분 일치 (email/username/displayName).
        const pattern = `%${escapeLike(search.toLowerCase())}%`;
        const term = or(
            sql`lower(${users.email}) like ${pattern} escape '\\'`,
            sql`lower(${users.username}) like ${pattern} escape '\\'`,
            sql`lower(${users.displayName}) like ${pattern} escape '\\'`,
        );
        if (term) conditions.push(term);
    }

    // PAGE_SIZE+1 행을 조회해 다음 페이지 유무를 판단한다.
    const rowsPlusOne = await db
        .select({
            id: users.id,
            username: users.username,
            email: users.email,
            displayName: users.displayName,
            role: users.role,
            status: users.status,
            createdAt: users.createdAt,
        })
        .from(users)
        .where(and(...conditions))
        .orderBy(desc(users.createdAt))
        .limit(PAGE_SIZE + 1);

    const hasMore = rowsPlusOne.length > PAGE_SIZE;
    const rows = hasMore ? rowsPlusOne.slice(0, PAGE_SIZE) : rowsPlusOne;
    const nextCursor = hasMore && rows.length > 0 ? rows[rows.length - 1].createdAt.getTime() : null;

    // "초대중" 배지 판정: 실제 미사용·미만료 invite_token 을 보유한 사용자만.
    //
    // 과거 판정(emailVerifiedAt NULL AND password credential 부재)은 LDAP/OIDC/SAML/패스키 전용
    // 계정도 만족한다(연합 프로비저닝은 emailVerifiedAt NULL + password credential 없이 계정 생성).
    // 그래서 연합 사용자 전원이 "초대중"으로 오표시됐다. 진짜 초대 대기 계정은 accept-invite 로
    // 소비될(usedAt 세팅) 유효 토큰을 갖는다 — accept-invite 서버의 유효성 판정(isNull(usedAt) +
    // 미만료)과 동일 기준으로 이번 페이지 사용자 id 범위만 배치 조회(N+1 없음)한다.
    const pageUserIds = rows.map((r) => r.id);
    const pendingInviteUserIds = new Set<string>();
    if (pageUserIds.length > 0) {
        const now = new Date();
        const inviteRows = await db
            .select({ userId: inviteTokens.userId })
            .from(inviteTokens)
            .where(and(inArray(inviteTokens.userId, pageUserIds), isNull(inviteTokens.usedAt), gt(inviteTokens.expiresAt, now)));
        for (const t of inviteRows) pendingInviteUserIds.add(t.userId);
    }

    const usersOut = rows.map((r) => ({
        id: r.id,
        username: r.username,
        email: r.email,
        displayName: r.displayName,
        role: r.role,
        status: r.status,
        createdAt: r.createdAt,
        // 초대 대기 상태(유효한 미사용 초대 토큰 보유) 여부.
        pendingInvite: pendingInviteUserIds.has(r.id),
    }));

    return { users: usersOut, search, pageSize: PAGE_SIZE, nextCursor };
};

export const actions: Actions = {
    // ── 사용자 생성 ────────────────────────────────────────────────────────────
    create: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        const email = normalizeEmail(String(fd.get("email") ?? ""));
        const username = normalizeUsername(String(fd.get("username") ?? "")) || email.split("@")[0];
        const displayName = String(fd.get("displayName") ?? "").trim();
        const role = String(fd.get("role") ?? "user") as "admin" | "user";
        const password = String(fd.get("password") ?? "");

        if (!email || !password) {
            return fail(400, { create: true, error: adminError(locale, "email_password_required") });
        }
        const createViolation = checkPasswordPolicy(password);
        if (createViolation) {
            return fail(400, { create: true, error: adminError(locale, createViolation === "too_short" ? "password_min_length" : "password_weak") });
        }
        if (!["admin", "user"].includes(role)) {
            return fail(400, { create: true, error: adminError(locale, "invalid_role") });
        }

        // 중복 확인
        const [existing] = await db
            .select({ id: users.id })
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.email, email)))
            .limit(1);
        if (existing) {
            return fail(409, { create: true, error: adminError(locale, "email_taken") });
        }

        const [existingUsername] = await db
            .select({ id: users.id })
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.username, username)))
            .limit(1);
        if (existingUsername) {
            return fail(409, { create: true, error: adminError(locale, "username_taken") });
        }

        const userId = crypto.randomUUID();
        await db.insert(users).values({
            id: userId,
            tenantId: tenant.id,
            email,
            username,
            displayName: displayName || null,
            role,
            status: "active",
        });

        const hashed = await hashPassword(password);
        await db.insert(credentials).values({
            id: crypto.randomUUID(),
            userId,
            type: PASSWORD_CREDENTIAL_TYPE,
            secret: hashed,
            label: "비밀번호",
        });

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId,
            actorId: locals.user!.id,
            kind: "user_created",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { email, role },
        });

        return { create: true };
    },

    // ── 사용자 초대 ────────────────────────────────────────────────────────────
    // 비밀번호 없이 계정을 선생성(credentials row 생략, emailVerifiedAt NULL, status active)한 뒤
    // 초대 토큰+메일을 발급한다. 초대 링크 수락 시 최초 비밀번호가 설정된다(accept-invite).
    invite: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        const email = normalizeEmail(String(fd.get("email") ?? ""));
        const username = normalizeUsername(String(fd.get("username") ?? "")) || email.split("@")[0];
        const displayName = String(fd.get("displayName") ?? "").trim();
        const role = String(fd.get("role") ?? "user") as "admin" | "user";

        if (!email) {
            return fail(400, { invite: true, error: adminError(locale, "email_required") });
        }
        if (!["admin", "user"].includes(role)) {
            return fail(400, { invite: true, error: adminError(locale, "invalid_role") });
        }

        // 중복 확인 — create 액션과 동일 규약(이메일/아이디 중복 차단).
        const [existing] = await db
            .select({ id: users.id })
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.email, email)))
            .limit(1);
        if (existing) {
            return fail(409, { invite: true, error: adminError(locale, "email_taken") });
        }

        const [existingUsername] = await db
            .select({ id: users.id })
            .from(users)
            .where(and(eq(users.tenantId, tenant.id), eq(users.username, username)))
            .limit(1);
        if (existingUsername) {
            return fail(409, { invite: true, error: adminError(locale, "username_taken") });
        }

        const userId = crypto.randomUUID();
        // users insert 를 runAtomic 로 감싼다 — 지금은 단일 write 지만, 초대 계정에 후속 row(예: 기본
        // 프로필/그룹)를 원자적으로 함께 넣도록 확장할 때 create 액션의 비원자 패턴을 답습하지 않기 위함.
        await runAtomic(db, [
            (h) =>
                h.insert(users).values({
                    id: userId,
                    tenantId: tenant.id,
                    email,
                    username,
                    displayName: displayName || null,
                    role,
                    status: "active",
                    // emailVerifiedAt 미설정(NULL) — 초대 링크 수락 시 세팅된다.
                }),
        ]);

        // 초대 토큰 발급 + 메일(best-effort, 완전 격리). 발송 실패가 초대 응답을 실패시키지 않는다.
        // 초대 대상은 신규 계정(locale 미보유)이므로 관리자 요청 locale 로 발송한다.
        await issueInvite(db, userId, email, locale, event.platform);

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId,
            actorId: locals.user!.id,
            kind: "user_invited",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { email, role },
        });

        return { invite: true };
    },

    // ── 상태 변경 ─────────────────────────────────────────────────────────────
    updateStatus: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        const id = String(fd.get("id") ?? "");
        const status = String(fd.get("status") ?? "") as "active" | "disabled" | "locked";

        if (!id || !["active", "disabled", "locked"].includes(status)) {
            return fail(400, { error: adminError(locale, "invalid_request") });
        }

        // 자기 자신 비활성화 방지
        if (id === locals.user!.id && status !== "active") {
            return fail(400, { error: adminError(locale, "cannot_change_own_status") });
        }

        // 마지막 활성 관리자 보호 — disable/locked 로 전환 시 검사
        if (status !== "active") {
            const lastAdminFail = await assertNotLastAdmin(db, tenant.id, id);
            if (lastAdminFail) return lastAdminFail;
        }

        // 알림 대상 파악용 — 대상 유저의 이메일/locale(같은 테넌트 범위).
        const [target] = await db
            .select({ email: users.email, locale: users.locale })
            .from(users)
            .where(and(eq(users.id, id), eq(users.tenantId, tenant.id)))
            .limit(1);

        await db
            .update(users)
            .set({ status, updatedAt: new Date() })
            .where(and(eq(users.id, id), eq(users.tenantId, tenant.id)));

        // 비활성/잠금 처리 시 기존 세션 + refresh token 즉시 파기하고 RP 에도 로그아웃을 통지한다.
        if (status !== "active") {
            await revokeUserEverywhere(event, { db, tenant, userId: id, actorId: locals.user!.id, reason: `user_${status}` });
        }

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: id,
            actorId: locals.user!.id,
            kind: "user_status_changed",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { status },
        });

        // 보안 알림(best-effort, 완전 격리) — 계정 잠금/비활성 전환 시.
        if (status === "locked") {
            dispatchSecurityAlert({ to: target?.email, locale: target?.locale, kind: "account_locked", platform: event.platform });
        } else if (status === "disabled") {
            dispatchSecurityAlert({ to: target?.email, locale: target?.locale, kind: "account_disabled", platform: event.platform });
        }

        return { updateStatus: true };
    },

    // ── 역할 변경 ─────────────────────────────────────────────────────────────
    updateRole: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        const id = String(fd.get("id") ?? "");
        const role = String(fd.get("role") ?? "") as "admin" | "user";

        if (!id || !["admin", "user"].includes(role)) {
            return fail(400, { error: adminError(locale, "invalid_request") });
        }

        // 자기 자신 역할 변경 방지
        if (id === locals.user!.id) {
            return fail(400, { error: adminError(locale, "cannot_change_own_role") });
        }

        // admin → user 강등 시에만 last-admin 검사 (승격은 항상 허용)
        if (role === "user") {
            const lastAdminFail = await assertNotLastAdmin(db, tenant.id, id);
            if (lastAdminFail) return lastAdminFail;
        }

        await db
            .update(users)
            .set({ role, updatedAt: new Date() })
            .where(and(eq(users.id, id), eq(users.tenantId, tenant.id)));

        // role 변경 시 기존 세션 + refresh token 파기 — 이전 권한으로 캐시된 세션 차단(RP 포함)
        await revokeUserEverywhere(event, { db, tenant, userId: id, actorId: locals.user!.id, reason: "role_changed" });

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: id,
            actorId: locals.user!.id,
            kind: "user_role_changed",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { role },
        });

        return { updateRole: true };
    },

    // ── 비밀번호 초기화 ──────────────────────────────────────────────────────
    resetPassword: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        const id = String(fd.get("id") ?? "");
        const newPassword = String(fd.get("newPassword") ?? "");

        if (!id || !newPassword) {
            return fail(400, { resetPassword: true, error: adminError(locale, "password_required") });
        }
        const resetViolation = checkPasswordPolicy(newPassword);
        if (resetViolation) {
            return fail(400, { resetPassword: true, error: adminError(locale, resetViolation === "too_short" ? "password_min_length" : "password_weak") });
        }

        // 대상 유저가 같은 테넌트인지 확인
        const [target] = await db
            .select({ id: users.id, email: users.email, locale: users.locale })
            .from(users)
            .where(and(eq(users.id, id), eq(users.tenantId, tenant.id)))
            .limit(1);
        if (!target) return fail(404, { resetPassword: true, error: adminError(locale, "user_not_found") });

        const hashed = await hashPassword(newPassword);
        const [existing] = await db
            .select({ id: credentials.id })
            .from(credentials)
            .where(and(eq(credentials.userId, id), eq(credentials.type, PASSWORD_CREDENTIAL_TYPE)))
            .limit(1);

        if (existing) {
            await db.update(credentials).set({ secret: hashed }).where(eq(credentials.id, existing.id));
        } else {
            await db.insert(credentials).values({
                id: crypto.randomUUID(),
                userId: id,
                type: PASSWORD_CREDENTIAL_TYPE,
                secret: hashed,
                label: "비밀번호",
            });
        }

        // 비밀번호 리셋 시 기존 세션 + refresh token 전부 파기 — 탈취된 세션 무효화(RP 포함)
        await revokeUserEverywhere(event, { db, tenant, userId: id, actorId: locals.user!.id, reason: "password_reset_by_admin" });

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            userId: id,
            actorId: locals.user!.id,
            kind: "password_reset",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
        });

        // 보안 알림(best-effort, 완전 격리) — 관리자가 비밀번호를 초기화함.
        dispatchSecurityAlert({ to: target.email, locale: target.locale, kind: "password_reset_by_admin", platform: event.platform });

        return { resetPassword: true };
    },

    // ── 삭제 ─────────────────────────────────────────────────────────────────
    delete: async (event) => {
        const { locals } = event;
        const { db, tenant } = requireAdminContext(locals);
        const locale = locals.locale;

        const fd = await event.request.formData();
        const idr = requireFormId(fd, locale);
        if (!idr.ok) return idr.failure;
        const id = idr.id;

        if (id === locals.user!.id) {
            return fail(400, { error: adminError(locale, "cannot_delete_self") });
        }

        // 마지막 활성 관리자 보호 — 삭제도 동일하게 검사
        const lastAdminFail = await assertNotLastAdmin(db, tenant.id, id);
        if (lastAdminFail) return lastAdminFail;

        const [exists] = await db
            .select({ id: users.id })
            .from(users)
            .where(and(eq(users.id, id), eq(users.tenantId, tenant.id)))
            .limit(1);
        if (!exists) return fail(404, { error: adminError(locale, "user_not_found") });

        // 즉시 삭제: RP 에 로그아웃을 통지하고(행이 살아 있을 때), 식별자를 기록한 뒤 지운다.
        // 예전에는 행만 지워 cascade 로 세션이 사라졌을 뿐 RP 는 통지를 받지 못했다.
        await deleteUserNow(event, { db, tenant, userId: id, actorId: locals.user!.id, reason: "deleted_by_admin" });

        const requestMetadata = getRequestMetadata(event);
        await recordAuditEvent(db, {
            tenantId: tenant.id,
            actorId: locals.user!.id,
            kind: "user_deleted",
            outcome: "success",
            ip: requestMetadata.ip,
            userAgent: requestMetadata.userAgent,
            detail: { userId: id },
        });

        return { deleted: true };
    },
};
