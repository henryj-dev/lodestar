import { fail } from "@sveltejs/kit";
import type { RequestEvent } from "@sveltejs/kit";
import { and, eq, gt, inArray, isNull, or } from "drizzle-orm";
import { requireAdminContext, assertUserInTenant } from "$lib/server/auth/guards";
import { recordAuditEvent, getRequestMetadata } from "$lib/server/audit/index";
import { oidcClients, samlSps, serviceEntitlements, serviceRoles, userServiceAssignments, userServiceEntitlements } from "$lib/server/db/schema";
import { adminError, requireCsrf, requireFormId } from "$lib/server/admin/errors";
import { isUniqueViolation } from "$lib/server/db/errors";
import type { DB } from "$lib/server/db";
import { runAtomic } from "$lib/server/db/atomic";
import { getActiveAssignment, listActiveEntitlements } from "$lib/server/access/service-permissions";
import { getActiveSigningKey } from "$lib/server/crypto/keys";
import { resolveIssuerUrl } from "$lib/server/auth/runtime";
import { getRoleChangeTarget, sendRoleChangeSet } from "$lib/server/oidc/role-change";
import { revokeRefreshTokenFamily } from "$lib/server/oidc/refresh";

// 사용자 상세 페이지의 서비스 권한(assignment) 액션.
type UserActionEvent = RequestEvent<{ id: string }, "/admin/users/[id]">;

/**
 * OIDC role 변경 SET 을 대상 클라이언트로 fire-and-forget 발행한다.
 *
 * DB 변경(부여/회수) **직후** 호출한다. 변경 후의 권위 있는 최종 roles·entitlements 를
 * `getActiveAssignment`/`listActiveEntitlements` 로 다시 읽어(로그인 시 token/userinfo 가 쓰는 것과
 * 동일 경로) 스냅샷으로 담는다:
 *   - 부여/역할변경 후 active role 존재 → `[role.key]`
 *   - 회수 후(또는 role 없음) → `[]`  → RP 가 user 로 강등
 *   - entitlements 는 배정이 살아 있으면 활성 권한 키, 배정이 사라졌으면 `[]`
 *
 * 발행 지점은 셋이다: 배정 부여(`addAssignment`) · 배정 회수(`revokeAssignment`) ·
 * **권한만 변경**(`setAssignmentEntitlements`). 마지막 것이 없으면 권한 회수가 RP 세션 수명 동안
 * 조용히 남는다 — 자체 세션으로 인가를 들고 가는 RP 에게는 이 SET 이 되돌리는 유일한 수단이다.
 *
 * serviceType !== 'oidc' 이거나, role_change_uri 미설정 클라이언트, 서명키/issuer 미비 등에서는
 * 조용히 skip 한다. 전송/조립 오류는 삼킨다(재시도 없음, back-channel logout 과 동일).
 */
export async function emitRoleChangeSet(event: RequestEvent, db: DB, tenantId: string, userId: string, serviceType: string, serviceRefId: string): Promise<void> {
    if (serviceType !== "oidc") return;
    try {
        const { locals, url, platform } = event;
        const signingKeySecrets = locals.runtimeConfig.signingKeySecrets;
        if (signingKeySecrets.length === 0) return;

        const target = await getRoleChangeTarget(db, tenantId, serviceRefId);
        if (!target) return; // role_change_uri 미설정/비활성 클라이언트 → skip

        // 변경 후 권위 있는 최종 roles / entitlements (로그인 클레임과 동일 값·동일 조회 경로).
        // 배정이 사라졌으면 둘 다 [] — RP 는 그것을 "전부 회수됨"으로 읽는다.
        const assignment = await getActiveAssignment(db, { tenantId, userId, serviceType: "oidc", serviceRefId });
        const roles = assignment?.role ? [assignment.role.key] : [];
        const entitlements = assignment ? await listActiveEntitlements(db, assignment, tenantId) : [];

        const issuerUrl = resolveIssuerUrl(locals.runtimeConfig, url.origin, locals.tenant?.slug ?? undefined);
        const signingKey = await getActiveSigningKey(db, tenantId, signingKeySecrets);
        if (!signingKey) return;

        const actorId = locals.user?.id ?? null;
        const meta = getRequestMetadata(event);
        const auditDetail = { clientId: target.clientId, roleChangeUri: target.roleChangeUri, roles, entitlements };
        // 전송 + 결과 audit 를 한 묶음으로 처리한다 — 응답 이후 실행(waitUntil)이므로 여기서 완결한다.
        // 성공/실패를 kind="role_change_set_sent" + outcome 으로 남긴다(발행 실패도 추적 가능).
        const task = sendRoleChangeSet(target, userId, roles, entitlements, issuerUrl, signingKey.privateKey, signingKey.kid, platform?.env?.OIDC_WEBHOOK_QUEUE)
            .then((result) =>
                recordAuditEvent(db, {
                    tenantId,
                    userId,
                    actorId,
                    spOrClientId: serviceRefId,
                    kind: "role_change_set_sent",
                    outcome: "success",
                    ip: meta.ip,
                    userAgent: meta.userAgent,
                    detail: { ...auditDetail, ...result },
                }),
            )
            .catch(() =>
                recordAuditEvent(db, {
                    tenantId,
                    userId,
                    actorId,
                    spOrClientId: serviceRefId,
                    kind: "role_change_set_sent",
                    outcome: "failure",
                    ip: meta.ip,
                    userAgent: meta.userAgent,
                    detail: auditDetail,
                }).catch(() => undefined),
            );

        const wait = platform?.ctx?.waitUntil?.bind(platform.ctx);
        if (wait) {
            wait(task);
        } else {
            await task;
        }
    } catch {
        // 발행/기록 실패는 삼킨다 — role 변경 자체(및 granted/revoked audit)는 이미 커밋됐다.
    }
}

// ── 서비스 권한 부여 ──────────────────────────────────────────────────────
export async function addAssignment(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const locale = locals.locale;
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;
    const userId = params.id;

    // ctrls C-13: 다른 tenant 의 userId 가 본 tenant 의 권한 row 로 박혀 들어가는
    // cross-tenant IDOR 차단. 기존엔 service ref 만 tenant 검증하고 userId 는
    // 검증 없이 INSERT 했음.
    const tenantCheck = await assertUserInTenant(db, tenant.id, userId);
    if (!tenantCheck.ok) return tenantCheck.error;

    // form 의 service 필드는 "oidc:<id>" 또는 "saml:<id>" 형태.
    const serviceRaw = String(fd.get("service") ?? "");
    const colonIdx = serviceRaw.indexOf(":");
    if (colonIdx <= 0) return fail(400, { error: adminError(locale, "select_service") });
    const serviceType = serviceRaw.slice(0, colonIdx);
    const serviceRefId = serviceRaw.slice(colonIdx + 1);
    if (serviceType !== "oidc" && serviceType !== "saml") return fail(400, { error: adminError(locale, "invalid_service_type") });
    if (!serviceRefId) return fail(400, { error: adminError(locale, "invalid_service_id") });

    const serviceRoleIdRaw = String(fd.get("serviceRoleId") ?? "").trim();
    const serviceRoleId = serviceRoleIdRaw || null;
    const expiresAtRaw = String(fd.get("expiresAt") ?? "").trim();
    const attributesJsonRaw = String(fd.get("attributesJson") ?? "").trim();

    // service ref 가 우리 테넌트의 활성 서비스인지 검증
    if (serviceType === "oidc") {
        const [c] = await db
            .select({ id: oidcClients.id })
            .from(oidcClients)
            .where(and(eq(oidcClients.id, serviceRefId), eq(oidcClients.tenantId, tenant.id)))
            .limit(1);
        if (!c) return fail(404, { error: adminError(locale, "oidc_client_not_found") });
    } else {
        const [s] = await db
            .select({ id: samlSps.id })
            .from(samlSps)
            .where(and(eq(samlSps.id, serviceRefId), eq(samlSps.tenantId, tenant.id)))
            .limit(1);
        if (!s) return fail(404, { error: adminError(locale, "saml_sp_not_found") });
    }

    // role 이 지정됐다면, 같은 service 의 role 인지 검증
    if (serviceRoleId) {
        const [r] = await db
            .select({ id: serviceRoles.id })
            .from(serviceRoles)
            .where(and(eq(serviceRoles.id, serviceRoleId), eq(serviceRoles.tenantId, tenant.id), eq(serviceRoles.serviceType, serviceType), eq(serviceRoles.serviceRefId, serviceRefId)))
            .limit(1);
        if (!r) return fail(400, { error: adminError(locale, "role_not_in_service") });
    }

    let expiresAt: Date | null = null;
    if (expiresAtRaw) {
        const d = new Date(expiresAtRaw);
        if (Number.isNaN(d.getTime())) return fail(400, { error: adminError(locale, "invalid_expiry_format") });
        expiresAt = d;
    }

    let attributesJson: string | null = null;
    if (attributesJsonRaw) {
        try {
            const parsed = JSON.parse(attributesJsonRaw) as unknown;
            if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
                return fail(400, { error: adminError(locale, "attributes_not_object") });
            }
            attributesJson = JSON.stringify(parsed);
        } catch {
            return fail(400, { error: adminError(locale, "attributes_parse_failed") });
        }
    }

    try {
        await db.insert(userServiceAssignments).values({
            id: crypto.randomUUID(),
            tenantId: tenant.id,
            userId,
            serviceType,
            serviceRefId,
            serviceRoleId,
            attributesJson,
            grantedBy: locals.user!.id,
            expiresAt,
        });
    } catch {
        // unique (tenantId, userId, serviceType, serviceRefId)
        return fail(409, { error: adminError(locale, "assignment_exists") });
    }

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId,
        actorId: locals.user!.id,
        spOrClientId: serviceRefId,
        kind: "service_assignment_granted",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        // attributesJson 은 토큰 클레임으로 머지되는 값이다 — 무엇을 넣었는지 남기지 않으면
        // 클레임을 바꾸고도 흔적이 남지 않는 경로가 된다.
        detail: { serviceType, serviceRefId, serviceRoleId, expiresAt, attributesJson },
    });

    // role 변경을 대상 RP 에 push (oidc + role_change_uri 설정 시). 변경 후 active role 스냅샷.
    await emitRoleChangeSet(event, db, tenant.id, userId, serviceType, serviceRefId);

    return { addedAssignment: true };
}

export async function revokeAssignment(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;
    const idr = requireFormId(fd, locals.locale, { field: "assignmentId" });
    if (!idr.ok) return idr.failure;
    const assignmentId = idr.id;

    // 삭제 전 대상 서비스를 읽어 둔다 — 회수 후 role-change SET(roles: []) 발행에 필요.
    const [target] = await db
        .select({ serviceType: userServiceAssignments.serviceType, serviceRefId: userServiceAssignments.serviceRefId })
        .from(userServiceAssignments)
        .where(and(eq(userServiceAssignments.id, assignmentId), eq(userServiceAssignments.userId, params.id), eq(userServiceAssignments.tenantId, tenant.id)))
        .limit(1);

    // IDOR 가드: 본 페이지 user 의 assignment 만 영향
    await db.delete(userServiceAssignments).where(and(eq(userServiceAssignments.id, assignmentId), eq(userServiceAssignments.userId, params.id), eq(userServiceAssignments.tenantId, tenant.id)));

    // 회수 → RP 에 roles: [] push (oidc + role_change_uri 설정 시). 삭제 후이므로 active role 없음.
    if (target) {
        // ctrls M-3: 탈권한(assignment 회수) 시 해당 OIDC 클라이언트에 대한 이 사용자의 활성
        // refresh token 을 폐기한다. role-change SET 은 계약상 세션을 끊지 않으므로, 이것이
        // 없으면 탈권한 사용자가 보유 중인 refresh token 으로 최대 30일간 access/id token 을
        // 계속 재발급받을 수 있었다. (access token 은 자체완결형 5분 TTL — 최대 5분 내 만료.
        //  refresh grant 의 hasServiceAccess 재검증(token/+server.ts)이 이중 방어.)
        if (target.serviceType === "oidc") {
            const [oc] = await db
                .select({ clientId: oidcClients.clientId })
                .from(oidcClients)
                .where(and(eq(oidcClients.id, target.serviceRefId), eq(oidcClients.tenantId, tenant.id)))
                .limit(1);
            if (oc) {
                await revokeRefreshTokenFamily(db, tenant.id, params.id, oc.clientId);
            }
        }
        await emitRoleChangeSet(event, db, tenant.id, params.id, target.serviceType, target.serviceRefId);
    }

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId: params.id,
        actorId: locals.user!.id,
        kind: "service_assignment_revoked",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { assignmentId },
    });

    return { revokedAssignment: true };
}

export async function updateAssignmentExpiry(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const locale = locals.locale;
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;
    const idr = requireFormId(fd, locale, { field: "assignmentId" });
    if (!idr.ok) return idr.failure;
    const assignmentId = idr.id;

    const expiresAtRaw = String(fd.get("expiresAt") ?? "").trim();
    let expiresAt: Date | null = null;
    if (expiresAtRaw) {
        const d = new Date(expiresAtRaw);
        if (Number.isNaN(d.getTime())) return fail(400, { error: adminError(locale, "invalid_expiry_format") });
        expiresAt = d;
    }

    const scope = and(eq(userServiceAssignments.id, assignmentId), eq(userServiceAssignments.userId, params.id), eq(userServiceAssignments.tenantId, tenant.id));

    const [before] = await db
        .select({ serviceType: userServiceAssignments.serviceType, serviceRefId: userServiceAssignments.serviceRefId, expiresAt: userServiceAssignments.expiresAt })
        .from(userServiceAssignments)
        .where(scope)
        .limit(1);
    if (!before) return fail(404, { error: adminError(locale, "assignment_not_found") });

    await db.update(userServiceAssignments).set({ expiresAt }).where(scope);

    // **만료 변경은 인가 변경이다.** 과거로 당기면 roles·entitlements 가 전부 사라지고, 미래로
    // 밀면 만료됐던 배정과 **그 배정에 남아 있던 권한이 통째로 되살아난다**(권한 행은 배정 행에
    // FK 로 매달려 있고 이 경로는 행을 지우지 않는다). 어느 쪽이든 RP 가 알아야 한다.
    const now = Date.now();
    const wasActive = before.expiresAt === null || before.expiresAt.getTime() > now;
    const isActive = expiresAt === null || expiresAt.getTime() > now;

    const meta = getRequestMetadata(event);
    await recordAuditEvent(db, {
        tenantId: tenant.id,
        userId: params.id,
        actorId: locals.user!.id,
        spOrClientId: before.serviceRefId,
        kind: "service_assignment_expiry_updated",
        outcome: "success",
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: { assignmentId, from: before.expiresAt?.toISOString() ?? null, to: expiresAt?.toISOString() ?? null, wasActive, isActive },
    });

    // 활성 → 비활성은 회수다. 정책 C 의 "제거" 와 같이 refresh family 도 폐기한다.
    if (wasActive && !isActive && before.serviceType === "oidc") {
        const [oc] = await db
            .select({ clientId: oidcClients.clientId })
            .from(oidcClients)
            .where(and(eq(oidcClients.id, before.serviceRefId), eq(oidcClients.tenantId, tenant.id)))
            .limit(1);
        if (oc) await revokeRefreshTokenFamily(db, tenant.id, params.id, oc.clientId);
    }
    if (wasActive !== isActive) {
        await emitRoleChangeSet(event, db, tenant.id, params.id, before.serviceType, before.serviceRefId);
    }

    return { updatedExpiry: true };
}

// ── 배정별 권한(entitlement) 설정 ─────────────────────────────────────────────
/**
 * 체크박스 그룹 제출을 받아 배정의 권한 집합을 **선언적으로** 맞춘다(diff 후 추가/삭제).
 *
 * 부여/회수를 따로 두지 않는 이유: UI 가 체크박스라 사용자가 표현하는 것은 "최종 상태" 이고,
 * 개별 토글로 쪼개면 두 요청 사이에 중간 상태가 생긴다. 감사에는 diff 를 건별로 남기므로
 * "무엇이 늘고 줄었는가" 는 그대로 추적된다.
 *
 * **권한 간 의존은 강제하지 않는다.** `plan.approve_own` 이 `plan.approve` 를 요구한다는 것은
 * RP 의 의미론이고, 다른 RP 에서는 같은 모양의 두 키가 무관할 수 있다. 그것을 IdP 가 알면
 * entitlement 가 피하려던 결합이 그대로 생긴다. 관리 화면은 displayOrder 로 순서만 보여 준다.
 */
export async function setAssignmentEntitlements(event: UserActionEvent) {
    const { locals, params, request } = event;
    const { db, tenant } = requireAdminContext(locals);
    const locale = locals.locale;
    const fd = await request.formData();
    const csrfFail = requireCsrf(event, fd);
    if (csrfFail) return csrfFail;
    const userId = params.id;

    const tenantCheck = await assertUserInTenant(db, tenant.id, userId);
    if (!tenantCheck.ok) return tenantCheck.error;

    const idr = requireFormId(fd, locale, { field: "assignmentId" });
    if (!idr.ok) return idr.failure;
    const assignmentId = idr.id;

    // IDOR 가드: 이 페이지 사용자의, 이 테넌트의 배정만 대상.
    const [assignment] = await db
        .select({ id: userServiceAssignments.id, serviceType: userServiceAssignments.serviceType, serviceRefId: userServiceAssignments.serviceRefId })
        .from(userServiceAssignments)
        .where(
            and(
                eq(userServiceAssignments.id, assignmentId),
                eq(userServiceAssignments.userId, userId),
                eq(userServiceAssignments.tenantId, tenant.id),
                // 읽기 경로(getActiveAssignment)와 같은 활성 조건을 쓴다. 이게 없으면 만료·회수된
                // 배정에 권한을 미리 적재해 둘 수 있고, 나중에 만료가 연장되는 순간 통지 없이 살아난다.
                or(isNull(userServiceAssignments.expiresAt), gt(userServiceAssignments.expiresAt, new Date())),
            ),
        )
        .limit(1);
    if (!assignment) return fail(404, { error: adminError(locale, "assignment_not_found") });

    // 후보는 **그 배정이 가리키는 서비스에 정의된 권한**뿐이다. 타 서비스/타 테넌트 id 가 폼으로
    // 들어오면 조용히 무시하지 않고 거부한다 — 정상 UI 는 그런 값을 보내지 않으므로 위조 신호다.
    const defined = await db
        .select({ id: serviceEntitlements.id, key: serviceEntitlements.key })
        .from(serviceEntitlements)
        .where(and(eq(serviceEntitlements.tenantId, tenant.id), eq(serviceEntitlements.serviceType, assignment.serviceType), eq(serviceEntitlements.serviceRefId, assignment.serviceRefId)));
    const keyById = new Map(defined.map((d) => [d.id, d.key]));

    const requested = [
        ...new Set(
            fd
                .getAll("entitlementId")
                .map((v) => String(v))
                .filter(Boolean),
        ),
    ];
    for (const id of requested) {
        if (!keyById.has(id)) return fail(400, { error: adminError(locale, "entitlement_not_in_service") });
    }

    const current = await db.select({ serviceEntitlementId: userServiceEntitlements.serviceEntitlementId }).from(userServiceEntitlements).where(eq(userServiceEntitlements.assignmentId, assignmentId));
    const currentIds = new Set(current.map((c) => c.serviceEntitlementId));
    const requestedIds = new Set(requested);

    const toAdd = requested.filter((id) => !currentIds.has(id));
    const toRemove = [...currentIds].filter((id) => !requestedIds.has(id));

    // 추가와 삭제를 원자적으로 적용한다. 따로 실행하면 사이에서 실패했을 때 절반만 반영된 채
    // 감사와 SET 이 실행되지 않아 DB 와 RP 가 어긋나고, 그 사실이 어디에도 남지 않는다.
    // runAtomic 이 d1/sqlite=batch, postgres/mysql=transaction 분기를 흡수한다.
    const writes: ((h: Pick<DB, "insert" | "delete">) => unknown)[] = [];
    if (toAdd.length > 0) {
        writes.push((h) =>
            h.insert(userServiceEntitlements).values(
                toAdd.map((serviceEntitlementId) => ({
                    id: crypto.randomUUID(),
                    tenantId: tenant.id,
                    assignmentId,
                    serviceEntitlementId,
                    grantedBy: locals.user!.id,
                })),
            ),
        );
    }
    if (toRemove.length > 0) {
        writes.push((h) => h.delete(userServiceEntitlements).where(and(eq(userServiceEntitlements.assignmentId, assignmentId), inArray(userServiceEntitlements.serviceEntitlementId, toRemove))));
    }
    if (writes.length > 0) {
        try {
            await runAtomic(db, writes as Parameters<typeof runAtomic>[1]);
        } catch (err) {
            // diff 는 직전 읽기 기준이라 동시 제출(더블클릭/두 관리자)이면 unique 위반이 난다.
            // addAssignment 와 같이 409 로 돌려준다 — 원자적이므로 부분 적용은 없다.
            if (!isUniqueViolation(err)) throw err;
            return fail(409, { error: adminError(locale, "entitlement_conflict") });
        }
    }

    // 감사는 건별로 — "언제 누가 무엇을 줬다/뺐다" 가 이력이 남는 유일한 자리다
    // (userServiceEntitlements 에는 revokedAt 을 두지 않았다).
    const meta = getRequestMetadata(event);
    for (const [ids, kind] of [
        [toAdd, "user_entitlement_granted"],
        [toRemove, "user_entitlement_revoked"],
    ] as const) {
        for (const id of ids) {
            await recordAuditEvent(db, {
                tenantId: tenant.id,
                userId,
                actorId: locals.user!.id,
                spOrClientId: assignment.serviceRefId,
                kind,
                outcome: "success",
                ip: meta.ip,
                userAgent: meta.userAgent,
                detail: { serviceType: assignment.serviceType, serviceRefId: assignment.serviceRefId, entitlementKey: keyById.get(id) ?? null },
            });
        }
    }

    // 바뀐 게 없으면 통지도 하지 않는다 — 같은 집합 재제출은 no-op 이다.
    if (toAdd.length > 0 || toRemove.length > 0) {
        // ctrls M-3 의 권한 판(정책 C): **제거가 있을 때만** refresh family 를 폐기한다.
        // 추가는 확대라 급하지 않고 재로그인 비용만 물리지만, 제거는 축소라 즉시 반영돼야 한다.
        // (배정 회수 경로가 이미 같은 함수를 쓴다.)
        //
        // 다만 이것이 안전망은 아니다: refresh token 을 받지 않고 자체 세션으로 인가를 들고 가는
        // RP 에게는 아무것도 닫아 주지 못한다. 그런 RP 를 되돌리는 수단은 아래 SET 하나뿐이다.
        if (toRemove.length > 0 && assignment.serviceType === "oidc") {
            const [oc] = await db
                .select({ clientId: oidcClients.clientId })
                .from(oidcClients)
                .where(and(eq(oidcClients.id, assignment.serviceRefId), eq(oidcClients.tenantId, tenant.id)))
                .limit(1);
            if (oc) await revokeRefreshTokenFamily(db, tenant.id, userId, oc.clientId);
        }

        // 권한만 바뀐 경우에도 SET 을 발행한다. 배정 부여/회수에서만 나가던 것을 여기까지 넓히는 것이
        // P6 의 본체다 — 이게 없으면 권한 회수가 RP 세션 수명 동안 조용히 남는다.
        await emitRoleChangeSet(event, db, tenant.id, userId, assignment.serviceType, assignment.serviceRefId);
    }

    return { entitlementsUpdated: true, added: toAdd.length, removed: toRemove.length };
}
