import { defineConfig } from "drizzle-kit";

// 활성 DB 방언 (배포 단위). d1(기본) | postgres | mysql.
// db:generate 는 스키마만 읽으므로 자격증명 불필요.
// db:migrate / db:push 실행 시 드리즐이 자체적으로 검증.
const DB_DIALECT: string = process.env.DB_DIALECT || "d1";

// 방언별 스키마 파일과 마이그레이션 출력 디렉터리를 분리한다.
// (drizzle*/ 마이그레이션 트랙은 커밋 대상 — 4방언 스냅샷/journal 을 형상 관리한다.
//  db:generate 는 로컬 스냅샷 기준으로 diff 하며 자격증명 없이 동작한다.)
function pgConfig() {
    return defineConfig({
        schema: "./src/lib/server/db/schema.pg.ts",
        out: "./drizzle/pg",
        dialect: "postgresql",
        dbCredentials: { url: process.env.DATABASE_URL ?? "" },
        verbose: true,
        strict: true,
    });
}

function mysqlConfig() {
    return defineConfig({
        schema: "./src/lib/server/db/schema.mysql.ts",
        out: "./drizzle/mysql",
        dialect: "mysql",
        dbCredentials: { url: process.env.DATABASE_URL ?? "" },
        verbose: true,
        strict: true,
    });
}

function sqliteConfig() {
    // libSQL 로컬 파일/Turso. 스키마는 D1 과 동일한 schema.sqlite.ts 를 공유하며
    // 생성 DDL 도 동일하다. 마이그레이션 journal 만 분리해 둔다.
    return defineConfig({
        schema: "./src/lib/server/db/schema.sqlite.ts",
        out: "./drizzle/sqlite",
        dialect: "sqlite",
        dbCredentials: { url: process.env.DATABASE_URL ?? "file:./lodestar.db" },
        verbose: true,
        strict: true,
    });
}

function d1Config() {
    const accountId = process.env.CLOUDFLARE_ACCOUNT_ID ?? "";
    const isPreview = process.env.CLOUDFLARE_IS_PREVIEW === "true";
    const databaseId = isPreview ? process.env.CLOUDFLARE_D1_PREVIEW_DATABASE_ID : process.env.CLOUDFLARE_D1_DATABASE_ID;
    const token = process.env.CLOUDFLARE_D1_TOKEN ?? process.env.CLOUDFLARE_API_TOKEN ?? "";

    // 하드코딩 fallback 제거 — 미설정 시 phantom DB 에 마이그레이션이 적용되는 사고를 방지.
    // (db:generate 는 자격증명 없이 동작하므로 빈 값 허용. db:migrate 는 dbCredentials 검증에서 실패한다.)
    return defineConfig({
        schema: "./src/lib/server/db/schema.sqlite.ts",
        // D1 마이그레이션은 기존과 동일하게 drizzle/ 루트에 둔다
        // (seed/setup 스크립트와 wrangler migrations_dir 이 이 경로를 참조).
        out: "./drizzle",
        dialect: "sqlite",
        driver: "d1-http",
        dbCredentials: { accountId, databaseId: databaseId ?? "", token },
        verbose: true,
        strict: true,
    });
}

export default DB_DIALECT === "postgres" ? pgConfig() : DB_DIALECT === "mysql" ? mysqlConfig() : DB_DIALECT === "sqlite" ? sqliteConfig() : d1Config();
