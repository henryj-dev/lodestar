import { error, fail } from "@sveltejs/kit";
import { and, eq, ne, or, exists, sql } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { users, credentials, identities } from "$lib/server/db/schema";
import { acrMeetsMfa } from "./constants";

export function requireDbContext(locals: App.Locals) {
    if (!locals.db || !locals.tenant) {
        throw error(503, locals.runtimeError ?? "데이터베이스 연결을 초기화하지 못했습니다. DB 바인딩/DATABASE_URL 및 DB_DIALECT 설정을 확인해 주세요.");
    }

    // rateLimitStore 는 hooks 에서 db 와 동일 블록에서 세팅되므로 db 가 있으면 반드시 존재한다.
    // (레이트 리밋을 쓰지 않는 엔드포인트도 이 컨텍스트를 쓰므로 store 부재로 503 을 내지는 않는다.)
    return { db: locals.db, tenant: locals.tenant, rateLimitStore: locals.rateLimitStore! };
}

/**
 * 관리자 전용 엔드포인트 가드.
 * +layout.server.ts load 는 form action 제출 시 실행되지 않으므로,
 * 모든 admin action 핸들러에서 반드시 이 함수를 사용해야 한다.
 *
 * MFA 검사도 여기에 있다. 레이아웃의 게이트는 사용자를 승격 화면으로 보내기 위한 것이고,
 * 이쪽은 그 화면을 건너뛰고 action 에 직접 POST 하는 경로를 막는 백스톱이다. 리다이렉트가
 * 아니라 403 인 이유는 form action 응답에 리다이렉트를 섞으면 폼 흐름이 깨지기 때문이다.
 */
export function requireAdminContext(locals: App.Locals) {
    const ctx = requireDbContext(locals);
    if (!locals.user) {
        throw error(401, "로그인이 필요합니다.");
    }
    if (locals.user.role !== "admin") {
        throw error(403, "관리자 권한이 필요합니다.");
    }
    if (!acrMeetsMfa(locals.session?.acr ?? null)) {
        throw error(403, "관리 콘솔은 2단계 인증을 통과한 세션만 사용할 수 있습니다.");
    }
    return { ...ctx, user: locals.user };
}

/**
 * 마지막 관리자 보호 가드.
 * `userIdToBeChanged` 가 활성 admin 이면서, 같은 테넌트에 다른 활성 admin 이 없으면
 * 변경(강등/disable/locked/delete)을 거부한다.
 *
 * 사용 시점: admin → user 강등, status를 active 가 아닌 값으로 변경, 사용자 삭제.
 * 일반 user → admin 승격은 호출하지 않아도 된다.
 *
 * 반환값: 차단해야 하면 SvelteKit `fail(400, ...)` 형태의 ActionFailure, 통과면 `null`.
 */
export async function assertNotLastAdmin(db: DB, tenantId: string, userIdToBeChanged: string): Promise<ReturnType<typeof fail> | null> {
    const [target] = await db
        .select({ id: users.id, role: users.role, status: users.status })
        .from(users)
        .where(and(eq(users.id, userIdToBeChanged), eq(users.tenantId, tenantId)))
        .limit(1);

    // 대상이 없거나 이미 admin/active 가 아니면 last-admin 검사가 의미 없음
    if (!target) return null;
    if (target.role !== "admin" || target.status !== "active") return null;

    // "다른 활성 admin" 은 실제로 **로그인 가능한** 계정만 센다. status=active 지만 아직
    // credential/identity 가 없는 계정(예: 미수락 초대 admin)은 로그인 자체가 불가능하므로,
    // 이런 계정이 last-admin 보호를 완화(다른 관리자 존재로 오인)하지 못하게 한다.
    // 로그인 가능 판정: password/passkey 등 credential 이 있거나, 연합(identities) 계정이면 사용 가능.
    // (LDAP/OIDC/SAML 은 identities row, password/webauthn 은 credentials row 를 가진다.)
    const usableAdmin = or(
        exists(
            db
                .select({ one: sql`1` })
                .from(credentials)
                .where(eq(credentials.userId, users.id)),
        ),
        exists(
            db
                .select({ one: sql`1` })
                .from(identities)
                .where(eq(identities.userId, users.id)),
        ),
    );
    const otherAdmins = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.role, "admin"), eq(users.status, "active"), ne(users.id, userIdToBeChanged), usableAdmin))
        .limit(1);

    if (otherAdmins.length === 0) {
        return fail(400, { error: "마지막 활성 관리자입니다. 먼저 다른 관리자를 지정해 주세요." });
    }
    return null;
}

/**
 * ctrls C-13: cross-tenant IDOR 가드.
 *
 * `params.id` 의 user 가 현재 admin 의 tenant 에 속해 있는지 확인. admin 페이지의
 * 모든 action (params.id 사용) 진입부에서 호출. 다른 tenant 의 userId 로
 * `/admin/users/<id>` 에 POST 했을 때 권한 row 가 본 tenant 에 박혀 들어가는
 * 흐름을 차단한다. 현재 single-tenant 운영이지만 멀티테넌트 활성화 즉시 폭발하는
 * 결함이라 사전 차단.
 *
 * 반환값: 통과면 user 행, 미존재/타 tenant 면 SvelteKit `fail(404, ...)` 형태.
 */
export async function assertUserInTenant(
    db: DB,
    tenantId: string,
    userId: string,
): Promise<{ ok: true; user: { id: string; role: "admin" | "user"; status: "active" | "disabled" | "locked" | "deletion_pending" } } | { ok: false; error: ReturnType<typeof fail> }> {
    const [row] = await db
        .select({ id: users.id, role: users.role, status: users.status, tenantId: users.tenantId })
        .from(users)
        .where(and(eq(users.id, userId), eq(users.tenantId, tenantId)))
        .limit(1);
    if (!row) {
        return { ok: false, error: fail(404, { error: "사용자를 찾을 수 없습니다." }) };
    }
    return { ok: true, user: { id: row.id, role: row.role as "admin" | "user", status: row.status as "active" | "disabled" | "locked" | "deletion_pending" } };
}
