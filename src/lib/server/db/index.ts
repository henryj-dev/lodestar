import { sql } from "drizzle-orm";
import * as schema from "./schema";
import type { DB } from "$db-active-driver";

export { DB_DIALECT } from "./dialect";
export type { DbDialect } from "./dialect";

/**
 * 앱 전역에서 사용하는 정규(canonical) DB 타입.
 *
 * 활성 방언(DB_DIALECT)에 맞는 drizzle 인스턴스 타입으로, `$db-active-driver` alias
 * 를 통해 방언별 driver-*.ts 중 하나로 해석된다(활성 스키마 배럴과 짝을 이룸).
 * 덕분에 대부분의 쿼리 코드는 방언과 무관하게 그대로 컴파일된다. 방언마다 갈라지는
 * 소수의 호출부(onConflict / batch / returning)만 `DB_DIALECT` 로 런타임 분기한다.
 */
export type { DB };

// vite.config.ts 의 define 으로 빌드 시 리터럴로 치환됨. 이 리터럴 분기를 esbuild 가
// dead-code-elimination 하여, 번들에는 활성 방언의 드라이버만 포함된다.
declare const __DB_DIALECT__: "d1" | "sqlite" | "postgres" | "mysql" | undefined;

// 순수 Node(adapter-node) 처럼 프로세스가 장수하는 환경에서는 드라이버 클라이언트를
// 전역에서 재사용해 연결 생성 비용을 아낀다. 반대로 Cloudflare Workers 는 요청마다
// 격리(isolate)되며 I/O 객체(소켓)를 요청 간 공유할 수 없으므로 절대 전역 재사용하면
// 안 된다 — 이전 요청의 죽은 소켓을 다음 요청이 붙잡고 hang 한다. Workers 여부는
// `platform.ctx.waitUntil` 존재로 판별하고, Workers 에서는 요청당 새 연결을 열고
// 응답 후 dispose() 로 닫는다.
let pgSql: unknown;
let mysqlPool: unknown;
let libsqlClient: unknown;

/**
 * getDb() 결과. `dispose` 는 Workers 에서 요청당 연 연결을 응답 완료 후 닫기 위한
 * 정리 함수다(hooks 가 `ctx.waitUntil(dispose())` 로 호출). Node 전역 재사용 경로나
 * D1 처럼 닫을 필요가 없으면 undefined.
 */
export interface DbHandle {
    db: DB;
    dispose?: () => Promise<void>;
}

/**
 * libSQL(sqlite) 연결 정보를 해석한다.
 * url: DATABASE_URL 또는 SQLITE_URL. `file:`/`libsql:`/`http(s):` 스킴이 없으면
 *      로컬 파일 경로로 보고 `file:` 을 붙인다. (예: "./data/keystone.db")
 * authToken: Turso 등 원격 libSQL 용 (선택).
 */
function resolveLibsqlConfig(platform: App.Platform | undefined): { url: string; authToken?: string } {
    const platformEnv = platform?.env as Record<string, unknown> | undefined;
    const nodeEnv = typeof process !== "undefined" ? (process.env as Record<string, string | undefined>) : undefined;
    const read = (key: string): string | undefined => {
        const fromPlatform = platformEnv?.[key];
        if (typeof fromPlatform === "string" && fromPlatform.length > 0) return fromPlatform;
        const fromNode = nodeEnv?.[key];
        return fromNode && fromNode.length > 0 ? fromNode : undefined;
    };
    const raw = read("DATABASE_URL") ?? read("SQLITE_URL");
    if (!raw) {
        throw new Error("DB_DIALECT=sqlite 연결 정보를 찾을 수 없습니다. DATABASE_URL(또는 SQLITE_URL)을 설정하세요. 로컬 파일은 `file:./keystone.db` 또는 경로만(`./keystone.db`) 가능합니다.");
    }
    const url = /^(file:|libsql:|https?:|wss?:)/.test(raw) ? raw : `file:${raw}`;
    return { url, authToken: read("DATABASE_AUTH_TOKEN") ?? read("SQLITE_AUTH_TOKEN") };
}

/**
 * postgres/mysql 연결 문자열을 해석한다. 우선순위:
 *   1. platform.env.HYPERDRIVE.connectionString  (Cloudflare Workers + Hyperdrive)
 *   2. platform.env.DATABASE_URL                  (Workers 직결 — var/secret. VPC 바인딩이
 *                                                  있으면 이 주소로 터널 경유 TCP 연결)
 *   3. process.env.DATABASE_URL                   (순수 Node 환경)
 * 이 순서 덕분에 Workers(Hyperdrive/VPC/직결)와 Node 환경을 모두 지원한다.
 */
function resolveConnectionString(platform: App.Platform | undefined, dialect: string): string {
    const fromHyperdrive = platform?.env?.HYPERDRIVE?.connectionString;
    if (fromHyperdrive) return fromHyperdrive;

    const platformEnv = platform?.env as Record<string, unknown> | undefined;
    const fromPlatformUrl = platformEnv?.DATABASE_URL;
    if (typeof fromPlatformUrl === "string" && fromPlatformUrl.length > 0) return fromPlatformUrl;

    const fromNodeEnv = typeof process !== "undefined" ? process.env?.DATABASE_URL : undefined;
    if (fromNodeEnv && fromNodeEnv.length > 0) return fromNodeEnv;

    throw new Error(
        `DB_DIALECT=${dialect} 연결 문자열을 찾을 수 없습니다. Cloudflare 에서는 HYPERDRIVE 바인딩(또는 DATABASE_URL var/secret), 순수 Node 환경에서는 DATABASE_URL 환경변수를 설정하세요.`,
    );
}

/**
 * 활성 방언에 맞는 drizzle 인스턴스를 반환한다.
 * - d1:       platform.env.DB (D1 바인딩, Workers 전용), 요청마다 FK 제약 활성화(PRAGMA).
 * - sqlite:   libSQL 로컬 파일(file:) 또는 Turso — DATABASE_URL/SQLITE_URL.
 * - postgres: Hyperdrive / DATABASE_URL → postgres-js.
 * - mysql:    Hyperdrive / DATABASE_URL → mysql2.
 *
 * 반환값의 `dispose` 는 Workers 에서 요청당 연 postgres/mysql 연결을 응답 완료 후
 * 닫기 위한 함수다(호출부가 `ctx.waitUntil(dispose())`). Node 전역 재사용 경로와
 * D1/sqlite 는 닫지 않으므로 undefined.
 */
export async function getDb(platform: App.Platform | undefined): Promise<DbHandle> {
    // Cloudflare Workers 판별: isolate 는 요청 간 I/O 객체(소켓)를 공유할 수 없으므로
    // postgres/mysql 연결을 전역 재사용하면 hang 한다. Workers 에서는 요청당 연결을
    // 새로 열고 dispose 로 닫는다. Node(adapter-node)는 platform.ctx 가 없어 전역 재사용.
    const isWorkers = typeof platform?.ctx?.waitUntil === "function";

    if (__DB_DIALECT__ === "postgres") {
        const connectionString = resolveConnectionString(platform, "postgres");
        const { drizzle } = await import("drizzle-orm/postgres-js");
        const postgres = (await import("postgres")).default;
        // Hyperdrive 뒤에서는 fetch_types 조회가 불필요/불가하므로 비활성화.
        // max: Workers 는 invocation 당 최대 6 연결 — Hyperdrive 권장값 5.
        if (isWorkers) {
            // VPC 바인딩(wrangler vpc_networks)이 있으면 드라이버 TCP 를 Cloudflare
            // Tunnel 사설망으로 라우팅한다 — postgres.js 문서화되지 않은 `socket` 옵션.
            const vpc = platform?.env?.VPC;
            const socketOpts = vpc ? { socket: (await import("./vpc-socket")).vpcSocket(vpc) } : {};
            const client = postgres(connectionString, { max: 5, fetch_types: false, ...(socketOpts as object) });
            return {
                db: drizzle(client, { schema: schema as never }) as unknown as DB,
                dispose: () => client.end({ timeout: 5 }),
            };
        }
        if (!pgSql) {
            pgSql = postgres(connectionString, { max: 5, fetch_types: false });
        }
        return { db: drizzle(pgSql as never, { schema: schema as never }) as unknown as DB };
    }

    if (__DB_DIALECT__ === "mysql") {
        const connectionString = resolveConnectionString(platform, "mysql");
        const { drizzle } = await import("drizzle-orm/mysql2");
        const mysql = (await import("mysql2/promise")).default;
        if (isWorkers) {
            // disableEval: Workers 런타임에서 mysql2 의 eval 기반 코드 생성이 금지됨.
            const pool = mysql.createPool({ uri: connectionString, connectionLimit: 5, disableEval: true });
            return {
                db: drizzle(pool, { schema: schema as never, mode: "default" }) as unknown as DB,
                dispose: () => pool.end(),
            };
        }
        if (!mysqlPool) {
            mysqlPool = mysql.createPool({ uri: connectionString, connectionLimit: 5 });
        }
        return { db: drizzle(mysqlPool as never, { schema: schema as never, mode: "default" }) as unknown as DB };
    }

    if (__DB_DIALECT__ === "sqlite") {
        // libSQL — 로컬 파일(file:) 또는 Turso 원격. HTTP 기반이라 소켓을 장기 점유하지
        // 않으므로 전역 재사용해도 안전하다.
        const { url, authToken } = resolveLibsqlConfig(platform);
        const { drizzle } = await import("drizzle-orm/libsql");
        const { createClient } = await import("@libsql/client");
        if (!libsqlClient) {
            libsqlClient = createClient({ url, authToken });
        }
        const db = drizzle(libsqlClient as never, { schema: schema as never });
        // SQLite 은 연결마다 FK 제약이 비활성화됨 — 명시적으로 활성화
        await db.run(sql`PRAGMA foreign_keys = ON`);
        return { db: db as unknown as DB };
    }

    if (__DB_DIALECT__ === "d1" || typeof __DB_DIALECT__ === "undefined") {
        // Cloudflare D1 (Workers 전용)
        if (!platform?.env?.DB) {
            throw new Error(
                'D1 binding "DB" is not available. D1 은 Cloudflare Workers 전용입니다. 순수 Node 환경(adapter-node)에서는 DB_DIALECT=postgres 또는 mysql 을 사용하세요. Workers 라면 wrangler.jsonc 와 platform.env 를 확인하세요.',
            );
        }
        const { drizzle } = await import("drizzle-orm/d1");
        const db = drizzle(platform.env.DB, { schema: schema as never });
        // D1(SQLite)은 연결마다 FK 제약이 비활성화됨 — 매 요청에 명시적으로 활성화
        await db.run(sql`PRAGMA foreign_keys = ON`);
        return { db: db as unknown as DB };
    }

    throw new Error(`Unknown DB_DIALECT: ${String(__DB_DIALECT__)}`);
}
