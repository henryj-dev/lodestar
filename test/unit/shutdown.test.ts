import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createShutdownHandler, DEFAULT_SHUTDOWN_TIMEOUT_MS } from "../../shutdown.js";

// graceful shutdown 은 롤아웃 순간에만 도는 코드라 수동 확인이 어렵다.
// server.close 콜백/타임아웃/중복 시그널을 주입으로 고정한다.

type CloseCb = (err?: Error) => void;

/** node http.Server 중 이 로직이 쓰는 두 메서드만 흉내낸 fake. */
function makeServer(opts: { hasCloseIdle?: boolean } = {}) {
    const state = {
        closeCalls: 0,
        closeIdleCalls: 0,
        /** server.close 에 전달된 콜백 — 테스트가 원하는 시점에 발화시킨다. */
        cb: undefined as CloseCb | undefined,
    };
    const server = {
        close(cb: CloseCb) {
            state.closeCalls++;
            state.cb = cb;
        },
        ...(opts.hasCloseIdle === false
            ? {}
            : {
                  closeIdleConnections() {
                      state.closeIdleCalls++;
                  },
              }),
    };
    return { server, state };
}

function makeHandler(server: unknown, opts: { timeoutMs?: number } = {}) {
    const exits: number[] = [];
    const shutdown = createShutdownHandler(server as Parameters<typeof createShutdownHandler>[0], {
        ...opts,
        exit: (code: number) => exits.push(code),
        log: () => {},
        error: () => {},
    });
    return { shutdown, exits };
}

beforeEach(() => {
    vi.useFakeTimers();
});
afterEach(() => {
    vi.useRealTimers();
});

describe("createShutdownHandler", () => {
    it("드레이닝이 끝나면 exit(0) — 정상 종료", () => {
        const { server, state } = makeServer();
        const { shutdown, exits } = makeHandler(server);

        shutdown("SIGTERM");
        expect(state.closeCalls).toBe(1);
        expect(exits).toEqual([]); // 아직 진행 중 요청이 있으므로 종료하지 않는다

        state.cb!(); // 드레이닝 완료
        expect(exits).toEqual([0]);
    });

    it("유휴 keep-alive 커넥션을 끊는다 (없으면 매 롤아웃이 타임아웃까지 늦어진다)", () => {
        const { server, state } = makeServer();
        const { shutdown } = makeHandler(server);

        shutdown("SIGTERM");
        expect(state.closeIdleCalls).toBe(1);
    });

    it("closeIdleConnections 가 없는 런타임에서도 던지지 않는다", () => {
        const { server, state } = makeServer({ hasCloseIdle: false });
        const { shutdown, exits } = makeHandler(server);

        expect(() => shutdown("SIGTERM")).not.toThrow();
        state.cb!();
        expect(exits).toEqual([0]);
    });

    it("상한 내 드레이닝이 끝나지 않으면 강제 종료한다(무한 대기 금지)", () => {
        const { server } = makeServer();
        const { shutdown, exits } = makeHandler(server, { timeoutMs: 5_000 });

        shutdown("SIGTERM");
        vi.advanceTimersByTime(4_999);
        expect(exits).toEqual([]);

        vi.advanceTimersByTime(1);
        expect(exits).toEqual([1]);
    });

    it("드레이닝이 끝나면 강제 종료 타이머가 해제된다(뒤늦은 exit 없음)", () => {
        const { server, state } = makeServer();
        const { shutdown, exits } = makeHandler(server, { timeoutMs: 5_000 });

        shutdown("SIGTERM");
        state.cb!();
        expect(exits).toEqual([0]);

        vi.advanceTimersByTime(60_000);
        expect(exits).toEqual([0]); // 타이머가 살아 있었다면 여기서 1 이 붙는다
    });

    it("두 번째 시그널은 무시한다", () => {
        // server.close 를 두 번 부르면 두 번째가 ERR_SERVER_NOT_RUNNING 으로 콜백되어
        // 정상 드레이닝 중인데 실패로 오인해 exit(1) 로 나가게 된다.
        const { server, state } = makeServer();
        const { shutdown, exits } = makeHandler(server);

        shutdown("SIGTERM");
        shutdown("SIGINT");
        shutdown("SIGTERM");

        expect(state.closeCalls).toBe(1);
        expect(state.closeIdleCalls).toBe(1);

        state.cb!();
        expect(exits).toEqual([0]);
    });

    it("server.close 가 에러를 주면 exit(1)", () => {
        const { server, state } = makeServer();
        const { shutdown, exits } = makeHandler(server);

        shutdown("SIGTERM");
        state.cb!(new Error("boom"));
        expect(exits).toEqual([1]);
    });

    it("기본 상한은 10초", () => {
        const { server } = makeServer();
        const { shutdown, exits } = makeHandler(server);

        shutdown("SIGTERM");
        vi.advanceTimersByTime(DEFAULT_SHUTDOWN_TIMEOUT_MS - 1);
        expect(exits).toEqual([]);
        vi.advanceTimersByTime(1);
        expect(exits).toEqual([1]);
    });
});
