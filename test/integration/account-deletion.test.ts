import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { actions as loginActions } from "../../src/routes/(auth)/login/+page.server";
import { runExpiredDataGc } from "../../src/lib/server/db/gc";
import { users } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, seedUser, makeEvent, catchRedirect, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Tenant, User } from "../../src/lib/server/db/schema";

// Phase 8: 셀프서비스 계정 삭제(deletion_pending) → 유예 내 로그인 복구, 유예 경과 시 GC 하드삭제.
// 삭제 신청 자체는 세션+step-up 재인증이 얽혀 있어, DB 상태(deletion_pending)를 직접 구성하고
// 실제 login 액션(복구 분기)과 실제 GC 하드삭제 조건을 검증한다(가짜 통과 없이 실 로직 구동).

let mem: MemoryDb;
let tenant: Tenant;

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
});

afterEach(() => mem.close());

async function statusOf(userId: string): Promise<string | undefined> {
    const [u] = await mem.db.select().from(users).where(eq(users.id, userId)).limit(1);
    return u?.status;
}

describe("Phase 8 — 계정 삭제 신청/복구/GC", () => {
    it("유예 기간 내 deletion_pending 계정은 로그인(recover=1)으로 active 복구된다", async () => {
        const user: User = await seedUser(mem.db, {
            tenantId: tenant.id,
            email: "carol@test.example",
            username: "carol",
            password: "carol-password",
            status: "deletion_pending",
            deletionScheduledAt: new Date(Date.now() + 20 * 24 * 60 * 60 * 1000), // 유예 내(20일 후 예정)
        });

        // 1단계: recover 없이 로그인 → 복구 확인 프롬프트 반환(세션 생성/복구 없음)
        const step1 = (await loginActions.default(
            makeEvent({
                method: "POST",
                url: `${TEST_ISSUER_URL}/login`,
                form: { username: "carol", password: "carol-password" },
                locals: { db: mem.db, tenant, env: mem.env },
            }),
        )) as { recovery?: boolean };
        expect(step1.recovery).toBe(true);
        expect(await statusOf(user.id)).toBe("deletion_pending"); // 아직 복구 안 됨

        // 2단계: recover=1 로 재제출 → 복구 후 정상 로그인(리다이렉트)
        const redirect = await catchRedirect(() =>
            loginActions.default(
                makeEvent({
                    method: "POST",
                    url: `${TEST_ISSUER_URL}/login`,
                    form: { username: "carol", password: "carol-password", recover: "1" },
                    locals: { db: mem.db, tenant, env: mem.env },
                }),
            ),
        );
        expect(redirect.status).toBe(303);
        expect(await statusOf(user.id)).toBe("active");
        const [restored] = await mem.db.select().from(users).where(eq(users.id, user.id)).limit(1);
        expect(restored.deletionScheduledAt).toBeNull();
    });

    it("유예 경과한 deletion_pending 계정은 복구가 거부되고(400), GC 가 하드 삭제한다", async () => {
        const elapsed: User = await seedUser(mem.db, {
            tenantId: tenant.id,
            email: "dave@test.example",
            username: "dave",
            password: "dave-password",
            status: "deletion_pending",
            deletionScheduledAt: new Date(Date.now() - 1000), // 유예 경과(과거)
        });

        // 로그인 복구 시도 → 유예 경과로 거부(400)
        const res = (await loginActions.default(
            makeEvent({
                method: "POST",
                url: `${TEST_ISSUER_URL}/login`,
                form: { username: "dave", password: "dave-password", recover: "1" },
                locals: { db: mem.db, tenant, env: mem.env },
            }),
        )) as { status?: number };
        expect(res.status).toBe(400);
        expect(await statusOf(elapsed.id)).toBe("deletion_pending"); // 여전히 존재

        // GC 실행 → 유예 경과 deletion_pending 만 하드 삭제
        const result = await runExpiredDataGc(mem.db, { isWorkers: true });
        const usersGc = result.tables.find((t) => t.table === "users");
        expect(usersGc?.ok).toBe(true);
        expect(await statusOf(elapsed.id)).toBeUndefined(); // 하드 삭제됨
    });

    it("GC 는 활성 계정과 유예 미경과 계정을 삭제하지 않는다(보수적 조건)", async () => {
        const active = await seedUser(mem.db, { tenantId: tenant.id, email: "erin@test.example", username: "erin", status: "active" });
        const pendingFuture = await seedUser(mem.db, {
            tenantId: tenant.id,
            email: "frank@test.example",
            username: "frank",
            status: "deletion_pending",
            deletionScheduledAt: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000),
        });

        await runExpiredDataGc(mem.db, { isWorkers: true });

        expect(await statusOf(active.id)).toBe("active");
        expect(await statusOf(pendingFuture.id)).toBe("deletion_pending");
    });
});
