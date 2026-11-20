import { and, eq } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { credentials, type Credential, type User, users } from "$lib/server/db/schema";
import { PASSWORD_CREDENTIAL_TYPE, TOTP_CREDENTIAL_TYPE } from "./constants";
import { verifyPassword } from "./password";

// S1(타이밍 계정 열거 차단): username 미존재/비활성/자격증명 부재 경로에서도 실제 scrypt 1회
// 비용을 발생시켜 존재/미존재 계정의 응답시간을 균등화한다. 아래 상수는 운영 파라미터
// (scrypt N=2^16, r=8, p=2)와 동일 비용으로 사전 생성한 고정 더미 해시로, 모듈 로드 시 생성하면
// cold start 비용이 들므로 상수 문자열로 박아 둔다. verifyPassword 는 이 scrypt 레코드에 대해
// 파생 1회만 수행하고(비교 실패 → rehash 없음) 결과는 폐기된다.
const TIMING_DUMMY_HASH = "scrypt$N=65536,r=8,p=2$hVmifHhlsivEhcuMH7TzxA==$d+O6MqRdeYS7W67a6bV6U82qevX56IyHCLzbLe2krwk=";

async function equalizeAuthTiming(password: string): Promise<void> {
    // 결과는 의도적으로 폐기 — 존재/미존재 계정 응답시간 균등화 목적의 더미 검증.
    await verifyPassword(password, TIMING_DUMMY_HASH);
}

export function normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
}

export function normalizeUsername(username: string): string {
    // Unicode confusable / homoglyph 공격 방지를 위해 NFKC 로 정규화한 뒤 소문자화.
    return username.trim().normalize("NFKC").toLowerCase();
}

export async function findUserByEmail(db: DB, tenantId: string, email: string): Promise<User | null> {
    const [user] = await db
        .select()
        .from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.email, normalizeEmail(email))))
        .limit(1);

    return user ?? null;
}

export async function findUserByUsername(db: DB, tenantId: string, username: string): Promise<User | null> {
    const [user] = await db
        .select()
        .from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.username, normalizeUsername(username))))
        .limit(1);

    return user ?? null;
}

export async function findPasswordCredential(db: DB, userId: string): Promise<Credential | null> {
    const [credential] = await db
        .select()
        .from(credentials)
        .where(and(eq(credentials.userId, userId), eq(credentials.type, PASSWORD_CREDENTIAL_TYPE)))
        .limit(1);

    return credential ?? null;
}

export async function authenticateLocalUser(db: DB, tenantId: string, username: string, password: string): Promise<User | null> {
    const user = await findUserByUsername(db, tenantId, username);

    if (!user || user.status !== "active") {
        // 존재-오답 경로와 동일하게 scrypt 1회 비용을 태워 타이밍 오라클을 제거.
        await equalizeAuthTiming(password);
        return null;
    }

    const credential = await findPasswordCredential(db, user.id);

    if (!credential?.secret) {
        await equalizeAuthTiming(password);
        return null;
    }

    const result = await verifyPassword(password, credential.secret);

    if (!result.valid) {
        return null;
    }

    if (result.rehash) {
        await db.update(credentials).set({ secret: result.rehash, lastUsedAt: new Date() }).where(eq(credentials.id, credential.id));
    }

    return user;
}

/**
 * 탈퇴 신청(soft-delete) 상태 계정의 복구용 재인증.
 *
 * `authenticateLocalUser` 는 status='active' 만 통과시키므로 deletion_pending 계정은 항상 null 을
 * 반환한다. 로그인 액션에서 그 null 경로 뒤에 이 함수를 호출해 "비밀번호는 맞지만 탈퇴 예정" 인
 * 계정을 식별하고 복구 확인 흐름으로 분기한다.
 *
 * 타이밍/열거 방어: status 가 deletion_pending 이 아니거나 credential 이 없으면 실제 검증 대신
 * 동일 비용의 더미 scrypt 1회를 태운다. 따라서 이 함수는 어느 경로에서도 정확히 scrypt 1회를
 * 수행하며, authenticateLocalUser 의 null 경로(역시 scrypt 1회)와 합쳐 실패 로그인의 총 비용이
 * 계정 상태와 무관하게 균등해진다(deletion_pending 존재를 타이밍으로 노출하지 않음).
 *
 * status='deletion_pending' 이고 비밀번호가 일치할 때만 해당 User 를 반환한다.
 */
export async function authenticatePendingDeletionUser(db: DB, tenantId: string, username: string, password: string): Promise<User | null> {
    const user = await findUserByUsername(db, tenantId, username);

    if (!user || user.status !== "deletion_pending") {
        await equalizeAuthTiming(password);
        return null;
    }

    const credential = await findPasswordCredential(db, user.id);

    if (!credential?.secret) {
        await equalizeAuthTiming(password);
        return null;
    }

    const result = await verifyPassword(password, credential.secret);

    if (!result.valid) {
        return null;
    }

    return user;
}

export async function findActiveUserById(db: DB, userId: string): Promise<User | null> {
    const [user] = await db
        .select()
        .from(users)
        .where(and(eq(users.id, userId), eq(users.status, "active")))
        .limit(1);
    return user ?? null;
}

export async function hasTotpCredential(db: DB, userId: string): Promise<boolean> {
    const [row] = await db
        .select({ id: credentials.id })
        .from(credentials)
        .where(and(eq(credentials.userId, userId), eq(credentials.type, TOTP_CREDENTIAL_TYPE)))
        .limit(1);
    return Boolean(row);
}
