/**
 * 관리자(또는 임의 사용자) 비밀번호 리셋 스크립트.
 *
 * 배경: 과거 seed 가 PBKDF2 600,000회로 해싱했으나 Cloudflare Workers WebCrypto 는
 * PBKDF2 반복을 100,000 으로 제한한다. 그래서 그렇게 시드된 계정은 Workers 에서
 * 로그인 검증(deriveBits)이 NotSupportedError 로 실패한다. 이 스크립트는 기존
 * 사용자의 password credential 을 앱 정규 해시(scrypt — `hashPassword` 가 내는 형식)로
 * 교체해 로그인을 복구한다. seed 재실행은 idempotent 라 기존 해시를 덮어쓰지 않으므로
 * 이 전용 스크립트가 필요하다.
 *
 * 사용법 (비밀번호는 shell 히스토리/프로세스 목록 노출을 피해 env 로 전달):
 *   DB_DIALECT=postgres \
 *   RESET_ADMIN_USERNAME=admin \
 *   RESET_ADMIN_PASSWORD='새-강력한-비밀번호' \
 *   [RESET_ADMIN_TENANT_SLUG=default] \
 *   bun scripts/reset-admin-password.ts
 *
 * 식별 우선순위: RESET_ADMIN_USERNAME 또는 RESET_ADMIN_EMAIL 중 하나 필수.
 * 둘 다 주면 username 우선. 테넌트는 slug 로 지정(기본 "default").
 *
 * 이 스크립트는 원격 DB 를 직접 변경한다 — 프로젝트 규칙상 자동 실행하지 않으며,
 * 운영자가 값 확인 후 직접 실행해야 한다.
 */
import { and, eq } from "drizzle-orm";
import { openScriptDb } from "./lib/db";
import { hashPassword, verifyPassword } from "../src/lib/server/auth/password";

function readEnv(key: string): string | undefined {
    const v = process.env[key];
    return v && v.length > 0 ? v : undefined;
}

function uuid(): string {
    return crypto.randomUUID();
}

// 앱(users.ts normalizeUsername)과 동일: NFKC 정규화 + 소문자화. Unicode confusable 방지.
// users.ts 는 $lib alias 를 import 해 bun 스크립트에서 해석되지 않으므로 여기 인라인한다.
function normalizeUsername(username: string): string {
    return username.trim().normalize("NFKC").toLowerCase();
}

function normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
}

async function main(): Promise<void> {
    const rawUsername = readEnv("RESET_ADMIN_USERNAME");
    const rawEmail = readEnv("RESET_ADMIN_EMAIL");
    const password = readEnv("RESET_ADMIN_PASSWORD");
    const tenantSlug = readEnv("RESET_ADMIN_TENANT_SLUG") ?? "default";

    if (!password) {
        console.error("✗ RESET_ADMIN_PASSWORD 가 필요합니다 (env 로 전달). 예:");
        console.error("  DB_DIALECT=postgres RESET_ADMIN_USERNAME=admin RESET_ADMIN_PASSWORD='...' bun scripts/reset-admin-password.ts");
        process.exit(1);
    }
    if (!rawUsername && !rawEmail) {
        console.error("✗ RESET_ADMIN_USERNAME 또는 RESET_ADMIN_EMAIL 중 하나가 필요합니다.");
        process.exit(1);
    }
    if (password.length < 8) {
        console.error("✗ 비밀번호가 너무 짧습니다 (최소 8자).");
        process.exit(1);
    }

    const h = await openScriptDb();
    const { db, schema } = h;
    const { tenants, users, credentials } = schema;

    try {
        console.log(`비밀번호 리셋 (dialect=${h.dialect}, tenant slug='${tenantSlug}')...`);

        // 1. 테넌트 확인
        const [tenant] = await db.select({ id: tenants.id }).from(tenants).where(eq(tenants.slug, tenantSlug)).limit(1);
        if (!tenant) {
            console.error(`✗ 테넌트 slug='${tenantSlug}' 를 찾을 수 없습니다. RESET_ADMIN_TENANT_SLUG 를 확인하세요.`);
            process.exit(1);
        }

        // 2. 사용자 조회 (username 우선, 없으면 email)
        const [user] = rawUsername
            ? await db
                  .select({ id: users.id, username: users.username, email: users.email, role: users.role, status: users.status })
                  .from(users)
                  .where(and(eq(users.tenantId, tenant.id), eq(users.username, normalizeUsername(rawUsername))))
                  .limit(1)
            : await db
                  .select({ id: users.id, username: users.username, email: users.email, role: users.role, status: users.status })
                  .from(users)
                  .where(and(eq(users.tenantId, tenant.id), eq(users.email, normalizeEmail(rawEmail as string))))
                  .limit(1);

        if (!user) {
            console.error(`✗ 사용자를 찾을 수 없습니다 (${rawUsername ? `username='${normalizeUsername(rawUsername)}'` : `email='${normalizeEmail(rawEmail as string)}'`}).`);
            process.exit(1);
        }
        console.log(`  대상 사용자: username='${user.username}' email='${user.email}' role='${user.role}' status='${user.status}' (id=${user.id})`);

        // 3. 정규 해시(scrypt) 생성
        const hashed = await hashPassword(password);
        const now = new Date();

        // 4. 기존 password credential 조회 → 있으면 UPDATE, 없으면 INSERT
        const [cred] = await db
            .select({ id: credentials.id, secret: credentials.secret })
            .from(credentials)
            .where(and(eq(credentials.userId, user.id), eq(credentials.type, "password")))
            .limit(1);

        if (cred) {
            const oldPrefix = (cred.secret ?? "").slice(0, 16);
            await db.update(credentials).set({ secret: hashed, lastUsedAt: null }).where(eq(credentials.id, cred.id));
            console.log(`  ✎ password credential 교체 (id=${cred.id}, 이전 형식='${oldPrefix}...' → scrypt)`);
        } else {
            await db.insert(credentials).values({ id: uuid(), userId: user.id, type: "password", secret: hashed, label: "비밀번호", createdAt: now });
            console.log(`  + password credential 신규 생성 (기존 없음)`);
        }

        // 5. 자체 검증 — 저장된 해시가 정규 형식(scrypt)이고 방금 비밀번호로 검증되는지 확인
        const [check] = await db
            .select({ secret: credentials.secret })
            .from(credentials)
            .where(and(eq(credentials.userId, user.id), eq(credentials.type, "password")))
            .limit(1);
        const stored = check?.secret ?? "";
        if (!stored.startsWith("scrypt$")) {
            console.error(`✗ 검증 실패: 저장된 해시가 scrypt 형식이 아닙니다 ('${stored.slice(0, 16)}...').`);
            process.exit(1);
        }
        const result = await verifyPassword(password, stored);
        if (!result.valid) {
            console.error("✗ 검증 실패: 저장된 해시가 입력 비밀번호로 검증되지 않습니다.");
            process.exit(1);
        }

        console.log("✅ 리셋 완료 — scrypt 해시로 교체되었고 검증도 통과했습니다. 이제 Workers 에서 로그인 가능합니다.");
    } finally {
        await h.close();
    }
}

main().catch((err) => {
    console.error("✗ 오류:", err instanceof Error ? err.message : err);
    process.exit(1);
});
