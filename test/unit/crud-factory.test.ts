import { describe, it, expect } from "vitest";
import { z } from "zod";
import type { RequestEvent } from "@sveltejs/kit";
import { createAdminCrudRoute } from "$lib/server/admin/crud-factory";
import { positions } from "$lib/server/db/schema";
import { ACR_MFA } from "$lib/server/auth/constants";

// ── 순수 로직 검증용 목(mock) ──────────────────────────────────────────────
// 실제 쿼리는 실행하지 않는다. insert/update/delete 에 넘어온 값만 캡처해
// 팩토리의 에러 shape 매핑 · audit kind 생성 · tenant 스코프 값을 검증한다.
function makeDb() {
    const inserts: Record<string, unknown>[] = [];
    const updates: Record<string, unknown>[] = [];
    let deleteCount = 0;
    const db = {
        insert: () => ({
            values: async (v: Record<string, unknown>) => {
                inserts.push(v);
            },
        }),
        update: () => ({
            set: (v: Record<string, unknown>) => ({
                where: async () => {
                    updates.push(v);
                },
            }),
        }),
        delete: () => ({
            where: async () => {
                deleteCount += 1;
            },
        }),
    };
    return {
        db,
        inserts,
        updates,
        get deleteCount() {
            return deleteCount;
        },
    };
}

function makeEvent(db: unknown, form: Record<string, string>): RequestEvent {
    const fd = new FormData();
    for (const [k, v] of Object.entries(form)) fd.set(k, v);
    return {
        // session.acr 이 필요한 이유: requireAdminContext 가 관리 콘솔을 MFA 세션으로 제한한다.
        // 이 스위트는 CRUD 팩토리의 계약을 보는 것이므로 게이트를 통과하는 세션을 준다.
        locals: {
            db,
            tenant: { id: "tenant-1" },
            user: { id: "user-1", role: "admin" },
            session: { id: "session-1", acr: ACR_MFA },
            locale: "ko",
        },
        request: { formData: async () => fd, headers: new Headers() },
    } as unknown as RequestEvent;
}

const createSchema = z.object({ name: z.string().trim().min(1, "이름은 필수입니다.") });
const updateSchema = z.object({
    id: z.string("id는 필수입니다.").min(1, "id는 필수입니다."),
    name: z.string("이름은 필수입니다.").trim().min(1, "이름은 필수입니다."),
});

function makeRoute(overrides: Partial<Parameters<typeof createAdminCrudRoute>[0]> = {}) {
    return createAdminCrudRoute({
        table: positions,
        auditPrefix: "widget",
        createSchema,
        updateSchema,
        load: async () => ({ ok: true }),
        ...overrides,
    });
}

/** fail(...) 결과에서 status/data 를 안전하게 꺼낸다. */
function asFailure(result: unknown): { status: number; data: Record<string, unknown> } {
    const r = result as { status?: number; data?: Record<string, unknown> };
    return { status: r.status ?? 0, data: r.data ?? {} };
}

/** 캡처된 insert 중 audit row(=kind 보유)를 찾는다. */
function findAudit(inserts: Record<string, unknown>[]): Record<string, unknown> | undefined {
    return inserts.find((r) => typeof r.kind === "string");
}

describe("createAdminCrudRoute - create", () => {
    it("검증 실패 시 fail(400, { create:true, error }) 계약", async () => {
        const { db, inserts } = makeDb();
        const route = makeRoute();
        const res = asFailure(await route.actions.create(makeEvent(db, { name: "  " })));
        expect(res.status).toBe(400);
        expect(res.data.create).toBe(true);
        expect(res.data.error).toBe("이름은 필수입니다.");
        expect(inserts.length).toBe(0); // insert 도, audit 도 없어야 함
    });

    it("성공 시 tenant 스코프 insert + audit kind `${prefix}_created`", async () => {
        const { db, inserts } = makeDb();
        const route = makeRoute();
        const ok = await route.actions.create(makeEvent(db, { name: "위젯" }));
        expect(ok).toEqual({ created: true });

        const entity = inserts.find((r) => r.name === "위젯");
        expect(entity?.tenantId).toBe("tenant-1");

        const audit = findAudit(inserts);
        expect(audit?.kind).toBe("widget_created");
        expect(audit?.outcome).toBe("success");
        expect(audit?.actorId).toBe("user-1");
        expect(audit?.tenantId).toBe("tenant-1");
    });

    it("beforeCreate 훅이 에러 문자열 반환 시 create fail(400,{create:true}) + insert 없음", async () => {
        const { db, inserts } = makeDb();
        const route = makeRoute({ beforeCreate: () => "FK 없음" });
        const res = asFailure(await route.actions.create(makeEvent(db, { name: "위젯" })));
        expect(res.status).toBe(400);
        expect(res.data.create).toBe(true);
        expect(res.data.error).toBe("FK 없음");
        expect(inserts.length).toBe(0);
    });

    it("beforeCreate 훅은 검증된 값을 받는다", async () => {
        const { db } = makeDb();
        let seen: unknown;
        const route = makeRoute({
            beforeCreate: (_ctx, values) => {
                seen = values;
                return null;
            },
        });
        await route.actions.create(makeEvent(db, { name: "  트림됨  " }));
        expect(seen).toEqual({ name: "트림됨" });
    });
});

describe("createAdminCrudRoute - update", () => {
    it("검증 실패 시 fail(400, { error }) — create 플래그 없음", async () => {
        const { db } = makeDb();
        const route = makeRoute();
        const res = asFailure(await route.actions.update(makeEvent(db, { name: "위젯" }))); // id 누락
        expect(res.status).toBe(400);
        expect(res.data.error).toBe("id는 필수입니다.");
        expect(res.data.create).toBeUndefined();
    });

    it("성공 시 set 은 id 제외 + updatedAt 포함, audit kind `${prefix}_updated`", async () => {
        const { db, inserts, updates } = makeDb();
        const route = makeRoute();
        const ok = await route.actions.update(makeEvent(db, { id: "w1", name: "새이름" }));
        expect(ok).toEqual({ updated: true });

        expect(updates.length).toBe(1);
        expect(updates[0].name).toBe("새이름");
        expect(updates[0].id).toBeUndefined(); // id 는 set 에 넣지 않는다
        expect(updates[0].updatedAt).toBeInstanceOf(Date);

        expect(findAudit(inserts)?.kind).toBe("widget_updated");
    });

    it("beforeUpdate 훅 실패 시 fail(400,{error}) + update 없음", async () => {
        const { db, updates } = makeDb();
        const route = makeRoute({ beforeUpdate: () => "계층 오류" });
        const res = asFailure(await route.actions.update(makeEvent(db, { id: "w1", name: "x" })));
        expect(res.status).toBe(400);
        expect(res.data.error).toBe("계층 오류");
        expect(res.data.create).toBeUndefined();
        expect(updates.length).toBe(0);
    });
});

describe("createAdminCrudRoute - delete", () => {
    it("id 없으면 fail(400,{error:'잘못된 요청입니다.'})", async () => {
        const { db } = makeDb();
        const route = makeRoute();
        const res = asFailure(await route.actions.delete(makeEvent(db, {})));
        expect(res.status).toBe(400);
        expect(res.data.error).toBe("잘못된 요청입니다.");
    });

    it("성공 시 삭제 + audit kind `${prefix}_deleted`, detail={id}", async () => {
        const store = makeDb();
        const { db, inserts } = store;
        const route = makeRoute();
        const ok = await route.actions.delete(makeEvent(db, { id: "w9" }));
        expect(ok).toEqual({ deleted: true });
        expect(store.deleteCount).toBe(1);

        const audit = findAudit(inserts);
        expect(audit?.kind).toBe("widget_deleted");
        expect(audit?.detailJson).toBe(JSON.stringify({ id: "w9" }));
    });
});

describe("createAdminCrudRoute - load", () => {
    it("requireAdminContext 통과 후 config.load 결과 반환", async () => {
        const { db } = makeDb();
        const route = makeRoute();
        const data = await route.load({
            locals: { db, tenant: { id: "tenant-1" }, user: { id: "user-1", role: "admin" }, session: { id: "session-1", acr: ACR_MFA } },
        } as unknown as { locals: App.Locals });
        expect(data).toEqual({ ok: true });
    });
});
