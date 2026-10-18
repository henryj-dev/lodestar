import { describe, it, expect } from "vitest";
import { createTotpEnrollTicket, verifyTotpEnrollTicket, TOTP_ENROLL_TICKET_TTL_S } from "../../src/lib/server/auth/totp-enroll-ticket";

// 등록 티켓은 init 이 발급한 (userId, secret) 을 confirm 에 묶는 유일한 근거다.
// 하나라도 다르면 거부해야 하고, 시크릿 회전 중(previous)에도 이미 발급된 티켓은 통과해야 한다.

const CURRENT = "current-signing-secret-0123456789abcdef";
const PREVIOUS = "previous-signing-secret-0123456789abcdef";
const base = { tenantId: "tenant-a", userId: "user-a", totpSecret: "JBSWY3DPEHPK3PXP" };

describe("TOTP 등록 티켓", () => {
    it("발급한 값 그대로면 통과한다", async () => {
        const ticket = await createTotpEnrollTicket(base, CURRENT);
        expect(await verifyTotpEnrollTicket(ticket, base, [CURRENT])).toEqual({ ok: true });
    });

    it("secret 이 다르면 거부한다 (발급하지 않은 secret 주입 차단)", async () => {
        const ticket = await createTotpEnrollTicket(base, CURRENT);
        expect(await verifyTotpEnrollTicket(ticket, { ...base, totpSecret: "KRSXG5CTMVRXEZLU" }, [CURRENT])).toEqual({ ok: false, reason: "mismatch" });
    });

    it("userId 가 다르면 거부한다 (다른 사용자에게 재사용 차단)", async () => {
        const ticket = await createTotpEnrollTicket(base, CURRENT);
        expect(await verifyTotpEnrollTicket(ticket, { ...base, userId: "user-b" }, [CURRENT])).toEqual({ ok: false, reason: "mismatch" });
    });

    it("tenant 가 다르면 거부한다", async () => {
        const ticket = await createTotpEnrollTicket(base, CURRENT);
        expect(await verifyTotpEnrollTicket(ticket, { ...base, tenantId: "tenant-b" }, [CURRENT])).toEqual({ ok: false, reason: "mismatch" });
    });

    it("만료되면 거부한다", async () => {
        const issuedAt = Date.now();
        const ticket = await createTotpEnrollTicket(base, CURRENT, issuedAt);
        const later = issuedAt + (TOTP_ENROLL_TICKET_TTL_S + 1) * 1000;
        expect(await verifyTotpEnrollTicket(ticket, base, [CURRENT], later)).toEqual({ ok: false, reason: "expired" });
    });

    it("다른 시크릿으로 서명한 티켓은 거부한다", async () => {
        const ticket = await createTotpEnrollTicket(base, "attacker-chosen-secret-0123456789abcdef");
        expect(await verifyTotpEnrollTicket(ticket, base, [CURRENT])).toEqual({ ok: false, reason: "bad_signature" });
    });

    it("payload 를 바꾸면 서명이 깨진다", async () => {
        const ticket = await createTotpEnrollTicket(base, CURRENT);
        const [, sig] = ticket.split(".");
        const forged = btoa(JSON.stringify({ v: 1, tid: "tenant-a", uid: "user-b", sh: "x", exp: 9999999999 })).replace(/=+$/, "");
        expect(await verifyTotpEnrollTicket(`${forged}.${sig}`, { ...base, userId: "user-b" }, [CURRENT])).toEqual({ ok: false, reason: "bad_signature" });
    });

    it("회전 중에는 previous 로 서명한 티켓도 통과한다", async () => {
        const ticket = await createTotpEnrollTicket(base, PREVIOUS);
        expect(await verifyTotpEnrollTicket(ticket, base, [CURRENT, PREVIOUS])).toEqual({ ok: true });
    });

    it("형식이 깨진 값은 malformed 로 거부한다", async () => {
        expect(await verifyTotpEnrollTicket("not-a-ticket", base, [CURRENT])).toEqual({ ok: false, reason: "malformed" });
        expect(await verifyTotpEnrollTicket(".", base, [CURRENT])).toEqual({ ok: false, reason: "malformed" });
    });

    it("대소문자·공백·패딩만 다른 secret 은 같은 secret 으로 본다 (base32 디코딩과 같은 기준)", async () => {
        const ticket = await createTotpEnrollTicket(base, CURRENT);
        expect(await verifyTotpEnrollTicket(ticket, { ...base, totpSecret: "jbsw y3dp ehpk 3pxp==" }, [CURRENT])).toEqual({ ok: true });
    });

    it("secret 원문을 티켓에 싣지 않는다", async () => {
        const ticket = await createTotpEnrollTicket(base, CURRENT);
        const payload = atob(ticket.split(".")[0].replace(/-/g, "+").replace(/_/g, "/"));
        expect(payload).not.toContain(base.totpSecret);
    });
});
