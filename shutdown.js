// graceful shutdown — 커스텀 서버 엔트리(`server.js`) 전용.
//
// 왜 필요한가: Node 의 **SIGTERM 기본 동작은 즉시 종료**다. k8s 롤아웃에서 kubelet 이
// SIGTERM 을 보내면 프로세스가 그 자리에서 죽는데, Service 엔드포인트 제거는 비동기라
// (kube-proxy/CNI 가 반영할 때까지 지연) 그 사이 이미 라우팅된 요청은 connection reset 을
// 받는다. `terminationGracePeriodSeconds` 가 설정돼 있어도 **프로세스가 스스로 즉시 나가면
// 쓰이지 않는다.**
//
// 창은 보통 수백 ms 로 짧지만, IdP 는 로그인 흐름 한가운데서 끊기면 사용자가 즉시 체감한다.
// 또 시그널 핸들러가 없으면 Node 가 143(128+15)으로 종료해 k8s 가 파드를 `Error` 로 표시한다
// — 정상 종료(`Completed`)가 아니라서 롤아웃 로그가 상시 지저분해진다.
//
// **`server.js` 에서 분리한 이유는 테스트 때문이다** — `server.js` 를 import 하면 그 자리에서
// `listen()` 이 돌아 유닛 테스트가 불가능하다. 여기는 주입 가능한 순수 로직만 둔다.

/** 드레이닝 최대 대기(ms). 초과하면 강제 종료한다 — 무한 대기 금지. */
export const DEFAULT_SHUTDOWN_TIMEOUT_MS = 10_000;

/**
 * `SHUTDOWN_TIMEOUT_MS` 환경변수를 ms 로 해석한다. 못 쓸 값이면 경고하고 기본값을 쓴다.
 *
 * **왜 별도 검증이 필요한가**: `Number.parseInt` 는 조용히 망가진다.
 * - `"10s"` → `10` — 10초로 적었는데 **10밀리초**가 된다.
 * - `""`·`"abc"` → `NaN` — `setTimeout(fn, NaN)` 은 던지지 않고 **지연 1ms 로 강등**된다.
 * - `"0"`·`"-1"` → 즉시 발화.
 *
 * 셋 다 결과가 같다: SIGTERM 을 받자마자 강제 종료 경로로 빠져 **드레이닝이 통째로
 * 무력화된다.** graceful shutdown 을 넣은 이유 자체가 사라지는데, 로그에는 "상한 초과"로만
 * 찍혀 원인이 매니페스트 오타라는 사실이 드러나지 않는다. 그래서 던지지 않고 기본값으로
 * 폴백하되 **경고를 남긴다** — 종료 경로에서 죽는 것보다 안전하게 도는 쪽이 낫다.
 *
 * @param {string | undefined} raw
 * @param {(...args: unknown[]) => void} [warn]
 * @returns {number}
 */
export function resolveShutdownTimeoutMs(raw, warn = console.warn) {
    if (raw === undefined || raw === "") return DEFAULT_SHUTDOWN_TIMEOUT_MS;
    // parseInt 대신 Number 를 쓴다 — "10s" 를 10 으로 받아들이지 않고 NaN 으로 거절한다.
    const parsed = Number(raw);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        warn(`[lodestar] SHUTDOWN_TIMEOUT_MS='${raw}' 를 해석할 수 없음 — 기본값 ${DEFAULT_SHUTDOWN_TIMEOUT_MS}ms 사용 (양의 정수 ms 여야 한다)`);
        return DEFAULT_SHUTDOWN_TIMEOUT_MS;
    }
    return Math.floor(parsed);
}

/**
 * 시그널 핸들러를 만든다(설치는 하지 않는다 — 테스트에서 직접 호출하기 위함).
 *
 * @param {import("node:http").Server | import("node:https").Server} server
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs] 드레이닝 상한. 기본 {@link DEFAULT_SHUTDOWN_TIMEOUT_MS}.
 * @param {(code: number) => void} [opts.exit] 종료 함수(테스트 주입용).
 * @param {(...args: unknown[]) => void} [opts.log]
 * @param {(...args: unknown[]) => void} [opts.error]
 * @returns {(signal: string) => void}
 */
export function createShutdownHandler(server, opts = {}) {
    // 호출부가 이미 걸러야 하지만, 여기서도 방어한다 — 못 쓸 값이 들어오면 타이머가 1ms 로
    // 강등되어 드레이닝 없이 강제 종료된다(resolveShutdownTimeoutMs 주석 참조).
    const rawTimeout = opts.timeoutMs ?? DEFAULT_SHUTDOWN_TIMEOUT_MS;
    const timeoutMs = Number.isFinite(rawTimeout) && rawTimeout > 0 ? Math.floor(rawTimeout) : DEFAULT_SHUTDOWN_TIMEOUT_MS;
    const exit = opts.exit ?? ((code) => process.exit(code));
    const log = opts.log ?? console.log;
    const error = opts.error ?? console.error;

    let shuttingDown = false;

    return function shutdown(signal) {
        // 두 번째 시그널은 무시한다. `server.close()` 를 두 번 부르면 두 번째 호출이
        // ERR_SERVER_NOT_RUNNING 으로 콜백되어, 정상 드레이닝 중인데 실패로 오인해
        // exit(1) 로 나가게 된다.
        if (shuttingDown) return;
        shuttingDown = true;

        log(`[lodestar] ${signal} 수신 — 드레이닝 시작 (최대 ${timeoutMs}ms)`);

        // 안전망. keep-alive 커넥션이 남아 close 콜백이 영영 오지 않을 수 있다.
        // unref 로 이 타이머 자체가 프로세스를 붙잡지 않게 한다(드레이닝이 먼저 끝나면
        // 이벤트 루프가 타이머를 기다리지 않고 나간다).
        const forced = setTimeout(() => {
            error(`[lodestar] ${timeoutMs}ms 내 드레이닝 미완료 — 강제 종료`);
            exit(1);
        }, timeoutMs);
        forced.unref?.();

        server.close((err) => {
            clearTimeout(forced);
            if (err) {
                error("[lodestar] server.close 실패:", err);
                exit(1);
                return;
            }
            log("[lodestar] 드레이닝 완료 — 정상 종료");
            exit(0);
        });

        // 진행 중인 요청은 그대로 두고 **유휴** keep-alive 커넥션만 끊는다.
        // 이게 없으면 브라우저가 붙잡고 있는 유휴 소켓 때문에 close 콜백이 위 타임아웃까지
        // 늦어진다(= 매 롤아웃마다 강제 종료). closeAllConnections 는 진행 중 요청까지
        // 끊으므로 쓰지 않는다.
        server.closeIdleConnections?.();
    };
}

/**
 * SIGTERM/SIGINT 에 graceful shutdown 을 설치한다.
 *
 * @param {import("node:http").Server | import("node:https").Server} server
 * @param {Parameters<typeof createShutdownHandler>[1]} [opts]
 */
export function installGracefulShutdown(server, opts = {}) {
    const shutdown = createShutdownHandler(server, opts);
    for (const signal of ["SIGTERM", "SIGINT"]) {
        process.on(signal, () => shutdown(signal));
    }
    return shutdown;
}
