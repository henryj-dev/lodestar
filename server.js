// 커스텀 서버 엔트리 — adapter-node 의 handler 를 직접 감싼다.
//
// 왜 필요한가: adapter-node 의 기본 엔트리(`node build`)는 평문 HTTP 만 서빙한다.
// ingress controller 나 리버스 프록시가 앞에 있으면 그걸로 충분하지만, 그런 계층이
// 없는 환경에서는 앱이 직접 TLS 를 끝내야 한다. IdP 는 **브라우저가 직접 붙는**
// 서비스이고 OIDC 는 issuer 가 https 여야 하므로(ORIGIN/IDP_ISSUER_URL 이 https),
// 평문으로 서빙하면 로그인 흐름이 깨진다.
//
// TLS 는 **fail-hard** 다. TLS_DIR 을 줬는데 인증서를 못 읽으면 평문으로 폴백하지 않고
// 죽는다 — TLS 로 뜨라고 지시했는데 조용히 평문으로 뜨는 것은 사고다. 특히 IdP 는
// 평문으로 뜨면 자격증명이 그대로 노출된다.
//
// TLS_DIR 을 주지 않으면 평문 = 기존 동작 그대로다. 따라서 리버스 프록시 뒤에서 쓰던
// 배포에는 아무 영향이 없다.
//
// BUILD_TARGET=node 로 빌드했을 때만 의미가 있다(cloudflare 어댑터는 build/handler.js 를
// 만들지 않는다). `node server.js` 로 실행한다.
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { handler } from "./build/handler.js";
import { installGracefulShutdown, resolveShutdownTimeoutMs } from "./shutdown.js";

const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
const HOST = process.env.HOST ?? "0.0.0.0";
const TLS_DIR = process.env.TLS_DIR;

// 드레이닝 상한(**밀리초**). k8s 라면 terminationGracePeriodSeconds 보다 작게 두어야 한다 —
// 크면 우리가 정리를 끝내기 전에 SIGKILL 이 먼저 온다.
// 단위 접미사("10s")나 빈 문자열은 거부하고 기본값으로 폴백한다(shutdown.js 주석 참조).
const SHUTDOWN_TIMEOUT_MS = resolveShutdownTimeoutMs(process.env.SHUTDOWN_TIMEOUT_MS);

function loadTls(dir) {
    // readFileSync 가 던지면 그대로 죽인다 — 폴백하지 않는다.
    return {
        cert: readFileSync(join(dir, "tls.crt")),
        key: readFileSync(join(dir, "tls.key")),
    };
}

const server = TLS_DIR ? createHttpsServer(loadTls(TLS_DIR), handler) : createHttpServer(handler);

server.listen(PORT, HOST, () => {
    console.log(`[lodestar] listening on ${HOST}:${PORT} (${TLS_DIR ? "TLS" : "plaintext"})`);
});

// SIGTERM(k8s 롤아웃)·SIGINT(로컬 Ctrl-C) 에 진행 중 요청을 마저 처리하고 나간다.
// 없으면 Node 기본 동작대로 즉시 죽어 그 순간의 요청이 connection reset 을 받는다.
installGracefulShutdown(server, { timeoutMs: SHUTDOWN_TIMEOUT_MS });
