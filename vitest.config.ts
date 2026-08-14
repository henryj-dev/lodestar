import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// 서버 라이브러리 순수 함수 유닛 테스트 전용 설정.
// SvelteKit 플러그인 없이 필요한 alias 만 명시 해석한다 ($app/$env 해석 이슈 회피).
const resolvePath = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
    define: {
        // vite.config.ts 와 동일하게 활성 방언 리터럴 주입 (기본 d1/sqlite).
        __DB_DIALECT__: JSON.stringify("d1"),
    },
    resolve: {
        alias: {
            $lib: resolvePath("./src/lib"),
            "$db-active-schema": resolvePath("./src/lib/server/db/schema.sqlite.ts"),
            "$db-active-driver": resolvePath("./src/lib/server/db/driver-sqlite.ts"),
            "$env/dynamic/private": resolvePath("./test/stubs/env-dynamic-private.ts"),
            "$env/static/private": resolvePath("./test/stubs/env-dynamic-private.ts"),
            // 통합 테스트(test/integration)가 실 서버 모듈을 직접 구동할 때 필요한 $app/environment 스텁.
            // 순수 유닛 테스트는 이 모듈을 import 하지 않으므로 영향이 없다.
            "$app/environment": resolvePath("./test/stubs/app-environment.ts"),
            // 폼 액션이 있는 페이지 서버 모듈(signup 등)은 resolve() 로 링크를 만든다.
            "$app/paths": resolvePath("./test/stubs/app-paths.ts"),
        },
    },
    test: {
        environment: "node",
        include: ["test/**/*.test.ts", "src/**/*.test.ts"],
        coverage: {
            // @vitest/coverage-v8 기반. 게이트(threshold)는 강제하지 않고 리포트만 산출한다.
            provider: "v8",
            reporter: ["text", "html"],
            reportsDirectory: "./coverage",
            include: ["src/lib/**/*.ts"],
        },
    },
});
