import { EventEmitter } from "node:events";
import { Buffer } from "node:buffer";

/**
 * Cloudflare Workers VPC 네트워크 바인딩 (wrangler 의 vpc_networks 로 주입).
 * connect() 는 Cloudflare Tunnel 을 경유해 사설망 호스트로의 raw TCP 소켓을 연다
 * — 현재 plaintext TCP 전용(TLS/startTls 미지원)이므로 sslmode 없는 연결 문자열과
 * 함께 사용해야 한다.
 */
export interface VpcNetwork {
    connect(address: string): {
        readable: ReadableStream<Uint8Array>;
        writable: WritableStream<Uint8Array>;
        closed: Promise<void>;
        close(): Promise<void>;
    };
}

/** postgres.js 가 socket 팩토리에 넘기는 파싱된 옵션 중 여기서 쓰는 부분. */
interface PgSocketOptions {
    host: string | string[];
    port: number | number[];
}

/**
 * postgres.js 의 `socket` 옵션에 넘길 커스텀 소켓 팩토리.
 *
 * postgres.js 워커 빌드(cf/)는 기본적으로 `cloudflare:sockets` 의 connect() 로
 * 공인망에 나가는데, 사설 IP(RFC1918) 는 거기서 도달할 수 없다. 이 팩토리는
 * postgres/cf/polyfills.js 의 Socket 과 같은 이벤트 인터페이스를 VPC 바인딩의
 * connect() 위에 재구현해, 드라이버의 TCP 트래픽을 Cloudflare Tunnel 사설망으로
 * 라우팅한다. 목적지 host:port 는 연결 문자열(DATABASE_URL)에서 온 options 값이다.
 *
 * ⚠️ postgres.js 는 `options.socket` 이 있으면 소켓의 connect() 를 호출하지 않고
 * 곧바로 startup 메시지를 write 한다 — 따라서 팩토리 호출 시점에 즉시 연결을 열고,
 * ready 전의 write 는 WritableStream 버퍼링에 맡긴다. 연결이 닫히면 postgres.js 가
 * 소켓을 버리고 팩토리를 다시 호출하므로 호출마다 새 VPC 소켓을 연다.
 */
export function vpcSocket(vpc: VpcNetwork) {
    return (options: PgSocketOptions) => {
        const host = Array.isArray(options.host) ? options.host[0] : options.host;
        const port = Array.isArray(options.port) ? options.port[0] : options.port;

        const tcp = Object.assign(new EventEmitter(), {
            readyState: "opening",
            destroyed: false,
            write,
            end,
            destroy,
        });

        const raw = vpc.connect(`${host}:${port}`);
        const writer = raw.writable.getWriter();
        const reader = raw.readable.getReader();
        raw.closed.then(close, error);
        writer.ready.then(() => {
            tcp.readyState = "open";
            tcp.emit("connect");
        }, error);
        void read();
        return tcp;

        function close() {
            if (tcp.readyState === "closed") return;
            tcp.readyState = "closed";
            tcp.emit("close");
        }

        function write(data: Uint8Array, cb?: () => void) {
            writer.write(data).then(cb, error);
            return true;
        }

        function end(data?: Uint8Array) {
            return data ? write(data, () => void raw.close()) : raw.close();
        }

        function destroy() {
            tcp.destroyed = true;
            end();
        }

        async function read() {
            try {
                let done: boolean | undefined;
                let value: Uint8Array | undefined;
                while ((({ done, value } = await reader.read()), !done)) tcp.emit("data", Buffer.from(value!));
                close();
            } catch (err) {
                error(err);
            }
        }

        function error(err: unknown) {
            tcp.emit("error", err);
            close();
        }
    };
}
