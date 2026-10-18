/**
 * 로그인·가입·재설정 요청 본문 크기 제한(회원 공통 정책 2026-10-18).
 *
 * 비밀번호 최대 길이를 없앤 대신, 비밀번호를 받는 요청 전체를 64 KiB 로 묶어 KDF·파서 자원 낭비를 막는다.
 * Content-Length 가 있으면 그것으로 판정하고, 없으면(chunked) 본문 복제본을 한도까지만 읽어 본다.
 */
export const AUTH_BODY_LIMIT_BYTES = 64 * 1024;

/** 비밀번호를 받는 경로. 다른 인증 경로(MFA 등)는 고정 길이 입력이라 제외한다. */
export const AUTH_BODY_LIMITED_PATHS = /^\/(login|signup|reset-password|accept-invite)(\/|$)/;

export async function exceedsBodyLimit(request: Request, limit = AUTH_BODY_LIMIT_BYTES): Promise<boolean> {
    const declared = request.headers.get("content-length");
    if (declared !== null) {
        const n = Number(declared);
        return !Number.isFinite(n) || n > limit;
    }
    if (!request.body) return false;

    const reader = request.clone().body!.getReader();
    let total = 0;
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) return false;
            total += value.byteLength;
            if (total > limit) return true;
        }
    } finally {
        reader.cancel().catch(() => undefined);
    }
}
