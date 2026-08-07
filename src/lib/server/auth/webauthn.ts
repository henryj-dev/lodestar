/**
 * WebAuthn / Passkey 구현 (M3.5)
 *
 * - 등록/인증 챌린지를 HMAC-서명 쿠키로 단기 저장 (5분 TTL)
 * - @simplewebauthn/server v13, Workers WebCrypto 전용
 * - residentKey: 'required' → username-less(discoverable) 로그인 지원
 */

import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from "@simplewebauthn/server";
import type { AuthenticatorTransportFuture, AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { type DB, DB_DIALECT } from "$lib/server/db";
import { credentials, users, webauthnChallenges } from "$lib/server/db/schema";
import { eq, and, isNull, gt, lt } from "drizzle-orm";
import { b64uEncode, b64uDecode } from "$lib/server/crypto/keys";

export const WEBAUTHN_CHALLENGE_COOKIE = "idp_webauthn_challenge";
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5분

// ── Challenge cookie ──────────────────────────────────────────────────────────

interface ChallengeCookiePayload {
    challenge: string; // base64url
    type: "register" | "authenticate";
    userId?: string; // register 시에만 세팅
    exp: number;
}

async function importHmacKey(secret: string, usage: "sign" | "verify"): Promise<CryptoKey> {
    return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}

export async function createChallengeCookie(payload: Omit<ChallengeCookiePayload, "exp">, signingKeySecret: string): Promise<string> {
    const enc = new TextEncoder();
    const full: ChallengeCookiePayload = { ...payload, exp: Date.now() + CHALLENGE_TTL_MS };
    const data = b64uEncode(enc.encode(JSON.stringify(full)));
    const key = await importHmacKey(signingKeySecret, "sign");
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
    return `${data}.${b64uEncode(new Uint8Array(sig))}`;
}

export async function verifyChallengeCookie(token: string, signingKeySecret: string, expectedType: "register" | "authenticate"): Promise<ChallengeCookiePayload | null> {
    try {
        const lastDot = token.lastIndexOf(".");
        if (lastDot === -1) return null;
        const data = token.slice(0, lastDot);
        const sigPart = token.slice(lastDot + 1);
        const enc = new TextEncoder();
        const key = await importHmacKey(signingKeySecret, "verify");
        const valid = await crypto.subtle.verify("HMAC", key, b64uDecode(sigPart), enc.encode(data));
        if (!valid) return null;
        const payload = JSON.parse(new TextDecoder().decode(b64uDecode(data))) as ChallengeCookiePayload;
        if (payload.exp < Date.now()) return null;
        if (payload.type !== expectedType) return null;
        return payload;
    } catch {
        return null;
    }
}

// ── RP 설정 ────────────────────────────────────────────────────────────────────

export function getWebAuthnConfig(url: URL) {
    return {
        rpID: url.hostname,
        rpName: "IdP",
        origin: url.origin,
    };
}

// ── 등록 (Registration) ────────────────────────────────────────────────────────

export async function buildRegistrationOptions(db: DB, userId: string, userEmail: string, userDisplayName: string | null, rpID: string, rpName: string) {
    // 이미 등록된 passkeys → excludeCredentials 에 포함(중복 방지)
    const existing = await db
        .select({ credentialId: credentials.credentialId })
        .from(credentials)
        .where(and(eq(credentials.userId, userId), eq(credentials.type, "webauthn")));

    const excludeCredentials = existing.filter((c) => c.credentialId !== null).map((c) => ({ id: c.credentialId! }));

    return generateRegistrationOptions({
        rpID,
        rpName,
        userName: userEmail,
        userDisplayName: userDisplayName || userEmail,
        userID: new TextEncoder().encode(userId) as Uint8Array<ArrayBuffer>,
        attestationType: "none",
        authenticatorSelection: {
            residentKey: "required",
            userVerification: "required",
        },
        excludeCredentials,
    });
}

export async function savePasskey(db: DB, userId: string, label: string, verificationResult: Awaited<ReturnType<typeof verifyRegistrationResponse>>): Promise<void> {
    const info = verificationResult.registrationInfo;
    if (!info) throw new Error("registrationInfo 가 없습니다");
    const { credential } = info;
    await db.insert(credentials).values({
        id: crypto.randomUUID(),
        userId,
        type: "webauthn",
        label: label || "패스키",
        credentialId: credential.id,
        publicKey: b64uEncode(new Uint8Array(credential.publicKey)),
        counter: credential.counter,
        transports: credential.transports ? JSON.stringify(credential.transports) : null,
    });
}

// ── 인증 (Authentication) ──────────────────────────────────────────────────────

export async function buildAuthenticationOptions(rpID: string) {
    return generateAuthenticationOptions({
        rpID,
        userVerification: "required",
        // allowCredentials 미지정 → discoverable credential (username-less)
    });
}

// ── 1회용 Challenge (DB 저장) ──────────────────────────────────────────────────

/** options 생성 시 challenge 를 DB 에 저장. */
export async function saveChallenge(db: DB, tenantId: string, challenge: string, userId?: string | null): Promise<void> {
    await db.insert(webauthnChallenges).values({
        id: crypto.randomUUID(),
        tenantId,
        userId: userId ?? null,
        challenge,
        expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
    });
}

/**
 * verify 시 challenge 소진. atomic UPDATE … WHERE used_at IS NULL RETURNING 으로
 * 동시 요청에서도 정확히 한 번만 성공한다.
 * tenantId 격리: 다른 테넌트의 challenge 는 매칭되지 않는다.
 */
export async function consumeChallenge(db: DB, tenantId: string, challenge: string): Promise<boolean> {
    const now = new Date();
    const consumeWhere = and(eq(webauthnChallenges.tenantId, tenantId), eq(webauthnChallenges.challenge, challenge), isNull(webauthnChallenges.usedAt), gt(webauthnChallenges.expiresAt, now));

    if (DB_DIALECT === "mysql") {
        // MySQL 은 UPDATE ... RETURNING 미지원 → affectedRows 로 소진 성공 여부 판정.
        const res = (await db.update(webauthnChallenges).set({ usedAt: now }).where(consumeWhere)) as unknown as [{ affectedRows: number }];
        return (res?.[0]?.affectedRows ?? 0) > 0;
    }

    // d1 / postgres: UPDATE ... RETURNING.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const updateBuilder = db.update(webauthnChallenges).set({ usedAt: now }).where(consumeWhere) as any;
    const rows = (await updateBuilder.returning({ id: webauthnChallenges.id })) as Array<{ id: string }>;
    return rows.length > 0;
}

/**
 * 만료된 챌린지 정리 (필요 시 주기적 호출).
 *
 * **`Date` 를 drizzle 연산자에 넘긴다 — raw SQL 에 `Date.now()` 숫자를 박으면 안 된다.**
 * sqlite/d1 은 timestamp 를 정수(ms)로 저장해 `expires_at <= 1786…` 비교가 통하지만,
 * postgres 는 `timestamptz`, mysql 은 `datetime` 이라 정수와 비교되지 않아 쿼리가 던진다.
 * `lt(col, new Date())` 는 컬럼의 방언별 매퍼를 타므로 4방언 모두에서 성립한다.
 */
export async function purgeExpiredChallenges(db: DB): Promise<void> {
    await db.delete(webauthnChallenges).where(lt(webauthnChallenges.expiresAt, new Date()));
}

export interface PasskeyVerifyResult {
    userId: string;
    credentialDbId: string;
    newCounter: number;
}

export async function verifyPasskeyAuthentication(
    db: DB,
    response: AuthenticationResponseJSON,
    expectedChallenge: string,
    rpID: string,
    origin: string,
    tenantId: string,
): Promise<PasskeyVerifyResult | null> {
    const credentialId = response.id;

    // 테넌트 격리: credential 의 소유 user 가 같은 tenant 인 경우만 채택.
    // ctrls H-AUTH-3: disabled/locked 사용자도 verify 단계를 통과하지 못하도록
    // active 필터를 SELECT 단계에서 강제. 이전엔 verify 통과 후 별도 status 검사를
    // 호출자에게 위임했으나, 호출자가 검사를 빠뜨리면 비활성 사용자 인증으로 직결.
    const [row] = await db
        .select({
            cred: credentials,
            userTenantId: users.tenantId,
        })
        .from(credentials)
        .innerJoin(users, eq(credentials.userId, users.id))
        .where(and(eq(credentials.credentialId, credentialId), eq(credentials.type, "webauthn"), eq(users.tenantId, tenantId), eq(users.status, "active")))
        .limit(1);

    const cred = row?.cred ?? null;
    const valid = !!cred && !!cred.publicKey;

    // 타이밍 누출 방지: credential 이 없거나 잘못 매칭되더라도 동일한 검증 비용을 지불한다.
    const publicKey = valid ? b64uDecode(cred.publicKey!) : DUMMY_PUBLIC_KEY;
    const transports = valid && cred.transports ? (JSON.parse(cred.transports) as AuthenticatorTransportFuture[]) : undefined;

    let verified: boolean;
    let newCounter = 0;
    try {
        const verification = await verifyAuthenticationResponse({
            response,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            credential: {
                id: credentialId,
                publicKey,
                counter: valid ? cred.counter : 0,
                transports,
            },
        });
        verified = verification.verified;
        newCounter = verification.authenticationInfo.newCounter;
    } catch {
        verified = false;
    }

    if (!valid || !verified) return null;

    await db.update(credentials).set({ counter: newCounter, lastUsedAt: new Date() }).where(eq(credentials.id, cred.id));

    return { userId: cred.userId, credentialDbId: cred.id, newCounter };
}

// 32바이트 더미 P-256 공개키 자리 표시자. 실제 검증은 실패하지만 호출 비용을 동일하게 만든다.
const DUMMY_PUBLIC_KEY: Uint8Array<ArrayBuffer> = (() => {
    const arr = new Uint8Array(77) as Uint8Array<ArrayBuffer>;
    arr[0] = 0xa5;
    return arr;
})();

// ── verifyRegistrationResponse 재익스포트 (API 라우트에서 사용) ──────────────────

export { verifyRegistrationResponse };
export type { RegistrationResponseJSON, AuthenticationResponseJSON };
