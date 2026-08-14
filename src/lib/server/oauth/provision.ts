/**
 * 외부 인증 성공 후 "이 사람을 어떤 KeyStone 계정으로 볼 것인가" 를 결정한다.
 * (계획서 §2.4 연결 정책 + §2.8 연합 회원가입)
 *
 * `ldap/provision.ts` 가 세운 원칙을 그대로 계승한다 — **이메일이 같다는 이유만으로
 * 기존 계정에 자동 연결하지 않는다.** 프로바이더가 이메일을 조작하면 관리자 계정까지
 * 탈취될 수 있기 때문이다.
 *
 * 이 모듈은 결정을 내리고 필요한 쓰기만 수행하며, HTTP 응답(리다이렉트/쿠키)은
 * 호출하는 라우트가 담당한다.
 */

import { and, eq } from "drizzle-orm";
import type { DB } from "$lib/server/db";
import { identities, users, type User } from "$lib/server/db/schema";
import { runAtomic } from "$lib/server/db/atomic";
import type { PendingLinkClaims } from "$lib/server/auth/pending-link";
import type { NormalizedProfile, OAuthProviderConfig, ProvisioningMode } from "./types";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_REGEX = /^[a-z0-9_]{3,32}$/;

/** 외부 신원 해석 결과. 라우트가 이 union 을 보고 다음 화면을 정한다. */
export type ResolveOutcome =
    /** 기존 계정 확정 — 세션을 발급하면 된다. */
    | { type: "login"; user: User }
    /** 매칭 계정 없음 — 프리필된 가입 폼으로 보낸다. */
    | { type: "signup_form"; claims: Omit<PendingLinkClaims, "redirectTo" | "skinHint"> }
    /** 같은 이메일의 기존 계정이 있음 — 자동 연결하지 않고 수동 연결을 안내한다. */
    | { type: "link_required"; email: string }
    /** 가입/로그인 거부. `reason` 은 i18n 키 suffix 로 쓴다. */
    | { type: "denied"; reason: "signup_disabled" | "account_disabled" | "account_deleting" | "no_email" };

export interface ResolveParams {
    db: DB;
    tenantId: string;
    /** `identities.provider` 값 — 예: `oauth:naver`. */
    provider: string;
    /** 가입 폼 안내 문구에 쓸 표시명 — 예: "네이버". */
    providerLabel: string;
    profile: NormalizedProfile;
    config: OAuthProviderConfig;
}

/** 소셜 프로바이더의 기본 프로비저닝 모드. LDAP 은 호출부에서 `jit` 을 넘긴다. */
const DEFAULT_MODE: ProvisioningMode = "signup_form";

/** 로그인 상태에서의 연결 시도 결과. */
export type LinkOutcome =
    | { type: "linked" }
    /** 이 외부 신원이 이미 **다른** 계정에 연결돼 있다. */
    | { type: "already_linked_elsewhere" }
    /** 이미 내 계정에 연결돼 있다(멱등 — 오류가 아니다). */
    | { type: "already_linked" };

/**
 * 이미 로그인한 사용자의 계정에 외부 신원을 연결한다 (`/account/connections` 경로).
 *
 * 콜백에서 세션이 살아 있으면 이 경로를 탄다. 로그인 플로우와 달리 이메일 일치를
 * 따지지 않는다 — 사용자가 본인 계정에 로그인한 상태에서 명시적으로 연결하는 것이라
 * 이메일이 달라도 정당하다(회사 메일 계정에 개인 GitHub 을 붙이는 등).
 */
export async function linkIdentityToUser(params: { db: DB; tenantId: string; userId: string; provider: string; profile: NormalizedProfile }): Promise<LinkOutcome> {
    const { db, tenantId, userId, provider, profile } = params;

    const [existing] = await db
        .select({ userId: identities.userId })
        .from(identities)
        .where(and(eq(identities.tenantId, tenantId), eq(identities.provider, provider), eq(identities.subject, profile.subject)))
        .limit(1);

    if (existing) {
        // 하나의 외부 신원이 두 계정에 연결되면 어느 쪽으로 로그인되는지 모호해진다.
        return existing.userId === userId ? { type: "already_linked" } : { type: "already_linked_elsewhere" };
    }

    await db.insert(identities).values({
        tenantId,
        userId,
        provider,
        subject: profile.subject,
        email: profile.email?.toLowerCase() ?? null,
        rawProfileJson: JSON.stringify(profile.raw),
        lastLoginAt: new Date(),
    });

    return { type: "linked" };
}

/**
 * 외부 닉네임 등을 username 규칙(`^[a-z0-9_]{3,32}$`)에 맞게 다듬는다.
 * 규칙을 만족시키지 못하면 undefined — 가입 폼에서 사용자가 직접 입력한다.
 */
export function suggestUsername(raw: string | undefined): string | undefined {
    if (!raw) return undefined;
    const cleaned = raw
        .toLowerCase()
        .replace(/[^a-z0-9_]/g, "_")
        .replace(/_+/g, "_")
        .replace(/^_+|_+$/g, "")
        .slice(0, 32);
    return USERNAME_REGEX.test(cleaned) ? cleaned : undefined;
}

/** 이미 쓰이는 username 이면 짧은 랜덤 suffix 를 붙여 충돌을 피한다. */
async function ensureUniqueUsername(db: DB, tenantId: string, base: string): Promise<string> {
    const [conflict] = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.tenantId, tenantId), eq(users.username, base)))
        .limit(1);
    if (!conflict) return base;

    const suffix = `_${crypto.randomUUID().slice(0, 6)}`;
    return `${base.slice(0, 32 - suffix.length)}${suffix}`;
}

/** 계정 상태를 로그인 가능 여부로 변환한다. */
function statusOutcome(user: User): Extract<ResolveOutcome, { type: "denied" }> | null {
    if (user.status === "active") return null;
    // 탈퇴 예정 계정의 복구는 비밀번호 재확인을 요구하는 별도 흐름이다(로그인 페이지).
    // 소셜 콜백에서는 그 확인을 할 수 없으므로 여기서 막고 안내한다.
    if (user.status === "deletion_pending") return { type: "denied", reason: "account_deleting" };
    return { type: "denied", reason: "account_disabled" };
}

/**
 * 외부 프로필을 KeyStone 계정으로 해석한다.
 *
 * 쓰기가 발생하는 경우는 두 가지뿐이다: 기존 identity 의 lastLoginAt 갱신,
 * 그리고 `jit` 모드 또는 `autoLinkVerifiedEmail` 이 켜진 자동 연결.
 */
export async function resolveFederatedIdentity(params: ResolveParams): Promise<ResolveOutcome> {
    const { db, tenantId, provider, providerLabel, profile, config } = params;
    const mode = config.provisioningMode ?? DEFAULT_MODE;
    const email = profile.email && EMAIL_REGEX.test(profile.email) ? profile.email.toLowerCase() : null;

    // ── 1. 이미 연결된 신원 ────────────────────────────────────────────────────
    const [existingIdentity] = await db
        .select({ userId: identities.userId })
        .from(identities)
        .where(and(eq(identities.tenantId, tenantId), eq(identities.provider, provider), eq(identities.subject, profile.subject)))
        .limit(1);

    if (existingIdentity) {
        const [user] = await db.select().from(users).where(eq(users.id, existingIdentity.userId)).limit(1);
        if (!user) return { type: "denied", reason: "account_disabled" };

        const denied = statusOutcome(user);
        if (denied) return denied;

        // identities 쪽 메타만 갱신한다. **users.email 은 절대 덮어쓰지 않는다** —
        // 프로바이더가 이메일을 바꿔 보내는 것만으로 KeyStone 계정의 신원이 바뀌면
        // 그 자체가 탈취 경로가 된다. (LDAP 은 admin 이 통제하는 소스라 예외적으로 동기화한다.)
        await db
            .update(identities)
            .set({ email, lastLoginAt: new Date() })
            .where(and(eq(identities.tenantId, tenantId), eq(identities.provider, provider), eq(identities.subject, profile.subject)));

        return { type: "login", user };
    }

    // ── 2. 같은 이메일의 기존 계정 ──────────────────────────────────────────────
    if (email) {
        const [existingUser] = await db
            .select()
            .from(users)
            .where(and(eq(users.tenantId, tenantId), eq(users.email, email)))
            .limit(1);

        if (existingUser) {
            const denied = statusOutcome(existingUser);
            if (denied) return denied;

            // 프로바이더가 이메일 검증을 단언했고, 관리자가 그 프로바이더를 신뢰하기로
            // 명시한 경우에만 자동 연결한다. 둘 중 하나라도 아니면 수동 연결로 보낸다.
            if (profile.emailVerified && config.autoLinkVerifiedEmail === true) {
                await db.insert(identities).values({
                    tenantId,
                    userId: existingUser.id,
                    provider,
                    subject: profile.subject,
                    email,
                    rawProfileJson: JSON.stringify(profile.raw),
                    lastLoginAt: new Date(),
                });
                return { type: "login", user: existingUser };
            }

            return { type: "link_required", email };
        }
    }

    // ── 3. 신규 ────────────────────────────────────────────────────────────────
    if (mode === "deny") return { type: "denied", reason: "signup_disabled" };

    if (mode === "jit") {
        // 무음 생성은 신뢰할 수 있는 이메일이 있을 때만 가능하다.
        if (!email) return { type: "denied", reason: "no_email" };

        const base = suggestUsername(profile.suggestedUsername) ?? suggestUsername(email.split("@")[0]) ?? `user_${crypto.randomUUID().slice(0, 8)}`;
        const username = await ensureUniqueUsername(db, tenantId, base);
        const userId = crypto.randomUUID();
        const now = new Date();

        await runAtomic(db, [
            (h) =>
                h.insert(users).values({
                    id: userId,
                    tenantId,
                    username,
                    email,
                    emailVerifiedAt: profile.emailVerified ? now : null,
                    displayName: profile.displayName ?? username,
                    givenName: profile.givenName,
                    familyName: profile.familyName,
                    role: "user",
                    status: "active",
                }),
            (h) =>
                h.insert(identities).values({
                    tenantId,
                    userId,
                    provider,
                    subject: profile.subject,
                    email,
                    rawProfileJson: JSON.stringify(profile.raw),
                    lastLoginAt: now,
                }),
        ]);

        const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
        if (!user) return { type: "denied", reason: "account_disabled" };
        return { type: "login", user };
    }

    // signup_form — 아직 아무것도 쓰지 않는다. 사용자가 폼을 제출해야 계정이 생긴다.
    return {
        type: "signup_form",
        claims: {
            tenantId,
            provider,
            subject: profile.subject,
            providerLabel,
            email,
            emailVerified: profile.emailVerified,
            displayName: profile.displayName,
            givenName: profile.givenName,
            familyName: profile.familyName,
            suggestedUsername: suggestUsername(profile.suggestedUsername) ?? (email ? suggestUsername(email.split("@")[0]) : undefined),
            allowPassword: true,
            allowUsernameEdit: true,
        },
    };
}
