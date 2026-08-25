/**
 * Lodestar IdP — DB seed 스크립트 (방언 무관: d1 / sqlite / postgres / mysql)
 *
 * 모드:
 * - `ignore` (기본):  기존 데이터 보존, 누락된 기본값만 INSERT (idempotent)
 * - `replace`:       모든 사용자 테이블 DROP → 방언별 마이그레이션 재적용 → seed
 *
 * 활성 방언은 `DB_DIALECT`(기본 d1) 로 결정되며 연결 정보는 방언별로 다르다:
 * - postgres/mysql/sqlite : DATABASE_URL
 * - d1                    : CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN(or _D1_TOKEN) /
 *                           CLOUDFLARE_D1_DATABASE_ID (CLOUDFLARE_IS_PREVIEW=true 면 PREVIEW)
 *
 * 선택 환경변수 (지정 시 admin 자동 생성):
 * - IDP_BOOTSTRAP_ADMIN_USERNAME, IDP_BOOTSTRAP_ADMIN_EMAIL,
 *   IDP_BOOTSTRAP_ADMIN_PASSWORD, IDP_BOOTSTRAP_ADMIN_NAME
 *
 * 사용:
 *   DB_DIALECT=postgres bun scripts/seed.ts     # postgres
 *   bun scripts/seed.ts                          # d1 (기본)
 */
import * as readline from "node:readline";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { and, eq } from "drizzle-orm";
import { openScriptDb, type ScriptDb, type Dialect } from "./lib/db";
import { hashPassword } from "../src/lib/server/auth/password";

function ask(question: string): Promise<string> {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((res) => rl.question(question, (a) => (rl.close(), res(a.trim().toLowerCase()))));
}

function uuid(): string {
    return crypto.randomUUID();
}

// ─── 방언별 마이그레이션 디렉터리 ──────────────────────────────────────────────
const MIGRATIONS_DIR_BY_DIALECT: Record<Dialect, string> = {
    d1: "drizzle",
    sqlite: "drizzle/sqlite",
    postgres: "drizzle/pg",
    mysql: "drizzle/mysql",
};

// ─── reset (replace 모드) ──────────────────────────────────────────────────────
async function resetDatabase(h: ScriptDb): Promise<void> {
    const tables = await h.listUserTables();

    console.log(`  Dropping ${tables.length} tables...`);
    if (h.dialect === "postgres") {
        // CASCADE 로 FK 순서 무시. 식별자 인용.
        for (const name of tables) await h.execRaw(`DROP TABLE IF EXISTS "${name}" CASCADE`);
        await h.execRaw(`DROP TABLE IF EXISTS "__drizzle_migrations" CASCADE`);
        await h.execRaw(`DROP TABLE IF EXISTS "_seed_migrations" CASCADE`);
    } else if (h.dialect === "mysql") {
        await h.execRaw("SET FOREIGN_KEY_CHECKS = 0");
        for (const name of tables) await h.execRaw(`DROP TABLE IF EXISTS \`${name}\``);
        await h.execRaw("DROP TABLE IF EXISTS `__drizzle_migrations`");
        await h.execRaw("DROP TABLE IF EXISTS `_seed_migrations`");
        await h.execRaw("SET FOREIGN_KEY_CHECKS = 1");
    } else {
        // sqlite / d1
        await h.execRaw("PRAGMA foreign_keys = OFF");
        for (const name of tables) await h.execRaw(`DROP TABLE IF EXISTS "${name}"`);
        await h.execRaw(`DROP TABLE IF EXISTS "__drizzle_migrations"`);
        await h.execRaw(`DROP TABLE IF EXISTS "_seed_migrations"`);
        await h.execRaw("PRAGMA foreign_keys = ON");
    }
    console.log("  All tables dropped.");

    // 방언별 마이그레이션 파일 재적용
    const dir = resolve(process.cwd(), MIGRATIONS_DIR_BY_DIALECT[h.dialect]);
    if (!existsSync(dir)) {
        throw new Error(`마이그레이션 디렉터리가 없습니다: ${dir}\n먼저 마이그레이션을 생성하세요 (예: DB_DIALECT=${h.dialect} bun run db:generate).`);
    }
    const sqlFiles = readdirSync(dir)
        .filter((f) => f.endsWith(".sql"))
        .sort();
    console.log(`Running ${sqlFiles.length} migration file(s) from ${MIGRATIONS_DIR_BY_DIALECT[h.dialect]}...`);
    for (const file of sqlFiles) {
        const content = readFileSync(join(dir, file), "utf-8").split("--> statement-breakpoint").join("\n");
        await h.execRaw(content);
        console.log(`  ${file} done`);
    }
}

// ─── seed (idempotent) ─────────────────────────────────────────────────────────
async function seedDefaults(h: ScriptDb, mode: "replace" | "ignore"): Promise<void> {
    const { db, schema } = h;
    const now = new Date();
    const { tenants, users, credentials, identities } = schema;

    // 1. 기본 tenant — slug='default'
    const tenantRows = await db.select({ id: tenants.id }).from(tenants).where(eq(tenants.slug, "default")).limit(1);
    let tenantId: string;
    if (tenantRows.length > 0) {
        tenantId = tenantRows[0].id;
        if (mode === "ignore") console.log(`  ✓ tenant 'default' already exists (id=${tenantId})`);
    } else {
        tenantId = uuid();
        await db.insert(tenants).values({ id: tenantId, slug: "default", name: "Default", status: "active", createdAt: now, updatedAt: now });
        console.log(`  + created tenant 'default' (id=${tenantId})`);
    }

    // 2. bootstrap admin (env 로 지정된 경우만)
    const adminUsername = process.env.IDP_BOOTSTRAP_ADMIN_USERNAME;
    const adminEmail = process.env.IDP_BOOTSTRAP_ADMIN_EMAIL;
    const adminPassword = process.env.IDP_BOOTSTRAP_ADMIN_PASSWORD;
    const adminName = process.env.IDP_BOOTSTRAP_ADMIN_NAME ?? "Admin";

    if (!(adminUsername && adminEmail && adminPassword)) {
        console.log("  · IDP_BOOTSTRAP_ADMIN_* 미설정 — admin 미생성. 'bun run setup' 또는 IdP UI 로 등록.");
        return;
    }

    const existing = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.email, adminEmail)))
        .limit(1);
    let userId: string;
    if (existing.length > 0) {
        userId = existing[0].id;
        console.log(`  ✓ admin user '${adminUsername}' already exists (id=${userId})`);
    } else {
        userId = uuid();
        await db.insert(users).values({
            id: userId,
            tenantId,
            username: adminUsername,
            email: adminEmail,
            emailVerifiedAt: now,
            displayName: adminName,
            role: "admin",
            status: "active",
            createdAt: now,
            updatedAt: now,
        });
        console.log(`  + created admin user '${adminUsername}' (id=${userId})`);
    }

    // 3. password credential
    const credExists = await db
        .select({ id: credentials.id })
        .from(credentials)
        .where(and(eq(credentials.userId, userId), eq(credentials.type, "password")))
        .limit(1);
    if (credExists.length > 0) {
        console.log(`  ✓ password credential already exists`);
    } else {
        const hashed = await hashPassword(adminPassword);
        await db.insert(credentials).values({ id: uuid(), userId, type: "password", secret: hashed, label: "비밀번호", createdAt: now });
        console.log(`  + created password credential`);
    }

    // 4. local identity
    const idExists = await db
        .select({ id: identities.id })
        .from(identities)
        .where(and(eq(identities.userId, userId), eq(identities.provider, "local")))
        .limit(1);
    if (idExists.length > 0) {
        console.log(`  ✓ local identity already exists`);
    } else {
        await db.insert(identities).values({ id: uuid(), tenantId, userId, provider: "local", subject: adminEmail, email: adminEmail, linkedAt: now });
        console.log(`  + created local identity`);
    }

    // 5. 등록된 모든 서비스에 표준 role 시드 + admin 유저에게 admin role 매핑
    await seedServicePermissions(h, tenantId, userId, now);
}

async function seedServicePermissions(h: ScriptDb, tenantId: string, adminUserId: string, now: Date): Promise<void> {
    const { db, schema } = h;
    const { oidcClients, samlSps, serviceRoles, userServiceAssignments } = schema;

    const oidc = await db.select({ id: oidcClients.id, name: oidcClients.name }).from(oidcClients).where(eq(oidcClients.tenantId, tenantId));
    const saml = await db.select({ id: samlSps.id, name: samlSps.name }).from(samlSps).where(eq(samlSps.tenantId, tenantId));

    const services: { type: "oidc" | "saml"; id: string; name: string }[] = [
        ...oidc.map((c: { id: string; name: string }) => ({ type: "oidc" as const, id: c.id, name: c.name })),
        ...saml.map((s: { id: string; name: string }) => ({ type: "saml" as const, id: s.id, name: s.name })),
    ];

    if (services.length === 0) {
        console.log("  · 등록된 서비스가 없어 service_roles 시드 생략");
        return;
    }

    const standardRoles = [
        { key: "admin", label: "관리자", description: "서비스 관리 권한", isDefault: false, displayOrder: 0 },
        { key: "editor", label: "편집자", description: "쓰기/수정 권한", isDefault: false, displayOrder: 10 },
        { key: "member", label: "멤버", description: "기본 사용자", isDefault: true, displayOrder: 20 },
    ];

    for (const svc of services) {
        for (const r of standardRoles) {
            const existing = await db
                .select({ id: serviceRoles.id })
                .from(serviceRoles)
                .where(and(eq(serviceRoles.serviceType, svc.type), eq(serviceRoles.serviceRefId, svc.id), eq(serviceRoles.key, r.key)))
                .limit(1);
            if (existing.length > 0) continue;
            await db.insert(serviceRoles).values({
                id: uuid(),
                tenantId,
                serviceType: svc.type,
                serviceRefId: svc.id,
                key: r.key,
                label: r.label,
                description: r.description,
                isDefault: r.isDefault,
                displayOrder: r.displayOrder,
                createdAt: now,
                updatedAt: now,
            });
            console.log(`  + service_roles: ${svc.type}:${svc.name} key=${r.key}`);
        }

        const adminRole = await db
            .select({ id: serviceRoles.id })
            .from(serviceRoles)
            .where(and(eq(serviceRoles.serviceType, svc.type), eq(serviceRoles.serviceRefId, svc.id), eq(serviceRoles.key, "admin")))
            .limit(1);
        if (adminRole.length === 0) continue;

        const existingAssignment = await db
            .select({ id: userServiceAssignments.id })
            .from(userServiceAssignments)
            .where(
                and(
                    eq(userServiceAssignments.tenantId, tenantId),
                    eq(userServiceAssignments.userId, adminUserId),
                    eq(userServiceAssignments.serviceType, svc.type),
                    eq(userServiceAssignments.serviceRefId, svc.id),
                ),
            )
            .limit(1);
        if (existingAssignment.length > 0) {
            console.log(`  ✓ assignment exists: ${svc.type}:${svc.name}`);
            continue;
        }

        await db.insert(userServiceAssignments).values({
            id: uuid(),
            tenantId,
            userId: adminUserId,
            serviceType: svc.type,
            serviceRefId: svc.id,
            serviceRoleId: adminRole[0].id,
            grantedBy: adminUserId,
            grantedAt: now,
            createdAt: now,
        });
        console.log(`  + assignment: admin -> ${svc.type}:${svc.name} role=admin`);
    }
}

// ─── main ────────────────────────────────────────────────────────────────────
async function main() {
    const h = await openScriptDb();
    console.log(`Seeding idp database (dialect=${h.dialect})...`);

    try {
        // 비대화 실행 지원: SEED_RESET=1 → 초기화, SEED_RESET=0 또는 non-TTY → 기존 보존.
        // (setup.ts 및 CI 에서 프롬프트 없이 호출)
        let shouldReset: boolean;
        if (process.env.SEED_RESET === "1") {
            shouldReset = true;
        } else if (process.env.SEED_RESET === "0" || !process.stdin.isTTY) {
            shouldReset = false;
        } else {
            const answer = await ask("기존 테이블을 모두 삭제하고 초기화하시겠습니까? (y/N): ");
            shouldReset = answer === "y" || answer === "yes";
        }

        if (shouldReset) {
            console.log("Resetting database...");
            await resetDatabase(h);
            await seedDefaults(h, "replace");
        } else {
            console.log("Skipping existing data, inserting only new rows...");
            await seedDefaults(h, "ignore");
        }

        console.log("✅ Seed complete!");
    } finally {
        await h.close();
    }
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
