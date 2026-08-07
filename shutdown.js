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
    const timeoutMs = opts.timeoutMs ?? DEFAULT_SHUTDOWN_TIMEOUT_MS;
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

        log(`[keystone] ${signal} 수신 — 드레이닝 시작 (최대 ${timeoutMs}ms)`);

        // 안전망. keep-alive 커넥션이 남아 close 콜백이 영영 오지 않을 수 있다.
        // unref 로 이 타이머 자체가 프로세스를 붙잡지 않게 한다(드레이닝이 먼저 끝나면
        // 이벤트 루프가 타이머를 기다리지 않고 나간다).
        const forced = setTimeout(() => {
            error(`[keystone] ${timeoutMs}ms 내 드레이닝 미완료 — 강제 종료`);
            exit(1);
        }, timeoutMs);
        forced.unref?.();

        server.close((err) => {
            clearTimeout(forced);
            if (err) {
                error("[keystone] server.close 실패:", err);
                exit(1);
                return;
            }
            log("[keystone] 드레이닝 완료 — 정상 종료");
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
