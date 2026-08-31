import { defineConfig, configDefaults } from "vitest/config";
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
        // test/workers 는 Cloudflare 전역 HTMLRewriter 를 쓰는 모듈을 검증하므로 node 에서 돌 수 없다.
        // `bun test` 가 따로 실행한다(package.json 의 test 스크립트가 vitest 뒤에 이어 붙인다).
        exclude: [...configDefaults.exclude, "test/workers/**"],
        // 통합 테스트는 실 DB(libSQL) + scrypt(N=2^15, 약 32MiB) 를 태운다. 파일 수가 늘면서
        // 코어 수만큼 워커를 띄우면 메모리 대역폭이 포화돼, 순차 로그인을 11회 돌리는 레이트리밋
        // 테스트처럼 무거운 케이스가 굶어 죽었다(어서션 실패가 아니라 시간 초과). 워커를 절반으로
        // 제한해 무거운 테스트가 CPU 를 확보하게 하고, 타임아웃에도 여유를 준다.
        testTimeout: 20_000,
        hookTimeout: 20_000,
        poolOptions: { threads: { maxThreads: 5 } },
        coverage: {
            // @vitest/coverage-v8 기반. 게이트(threshold)는 강제하지 않고 리포트만 산출한다.
            provider: "v8",
            reporter: ["text", "html"],
            reportsDirectory: "./coverage",
            include: ["src/lib/**/*.ts"],
        },
    },
});
