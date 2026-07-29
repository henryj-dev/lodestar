// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces
declare global {
    namespace App {
        interface Platform {
            // HYPERDRIVE: DB_DIALECT=postgres|mysql 일 때 Postgres/MySQL 연결 문자열을 제공하는
            // Cloudflare Hyperdrive 바인딩 (wrangler 의 hyperdrive 설정으로 주입).
            // VPC: Workers VPC 네트워크 바인딩 (wrangler 의 vpc_networks 설정으로 주입).
            // DB_DIALECT=postgres 에서 Cloudflare Tunnel 사설망의 DB 로 직결할 때 사용하며,
            // 접속 주소/계정은 DATABASE_URL secret 이 제공한다. 없는 배포도 있으므로 optional.
            // DB: DB_DIALECT=d1 일 때만 존재하는 Cloudflare D1 바인딩. D1 은 선택적 방언이므로
            // 모든 wrangler.jsonc 가 선언하지는 않는다 — optional 로 두어 non-d1 배포에서도 타입이 성립한다.
            // EMAIL: Cloudflare Email Sending 바인딩(send_email). 설정 시 Workers 에서
            // nodemailer 대신 이 바인딩으로 트랜잭션 메일을 발송한다. wrangler.jsonc 의
            // send_email 로 주입되며, 없는 배포도 있으므로 optional.
            env: Env & {
                SKIN_CACHE?: R2Bucket;
                HYPERDRIVE?: { connectionString: string };
                VPC?: import("$lib/server/db/vpc-socket").VpcNetwork;
                DB?: D1Database;
                EMAIL?: SendEmail;
            };
            ctx: ExecutionContext;
            caches: CacheStorage;
            cf?: IncomingRequestCfProperties;
        }

        // interface Error {}
        interface Locals {
            db?: import("$lib/server/db").DB;
            // 요청당 레이트 리밋 저장소. Workers=DB, Node=in-memory. db 와 함께 hooks 에서 세팅.
            rateLimitStore?: import("$lib/server/ratelimit").RateLimitStore;
            tenant: import("$lib/server/db/schema").Tenant | null;
            session: import("$lib/server/db/schema").Session | null;
            user: import("$lib/server/db/schema").User | null;
            runtimeConfig: import("$lib/server/auth/runtime").RuntimeConfig;
            runtimeError: string | null;
            locale: import("$lib/i18n.svelte").Locale;
        }
        // interface PageData {}
        // interface PageState {}
    }
}

export {};
