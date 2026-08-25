#!/usr/bin/env bun
/**
 * 프로젝트 최초 클론 후 셋업 자동화 스크립트
 * Usage: bun run scripts/setup.ts [options]
 */

import * as readline from "node:readline";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { spawnSync, spawn } from "node:child_process";
import { hashPassword } from "../src/lib/server/auth/password";

// ─── ANSI Colors ─────────────────────────────────────────────────────────────
const C = {
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    red: "\x1b[31m",
    cyan: "\x1b[36m",
    reset: "\x1b[0m",
    bold: "\x1b[1m",
} as const;

function green(s: string) {
    return `${C.green}${s}${C.reset}`;
}
function yellow(s: string) {
    return `${C.yellow}${s}${C.reset}`;
}
function red(s: string) {
    return `${C.red}${s}${C.reset}`;
}
function cyan(s: string) {
    return `${C.cyan}${s}${C.reset}`;
}

// ─── Paths ────────────────────────────────────────────────────────────────────
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WRANGLER_EXAMPLE = path.join(ROOT, "wrangler.example.jsonc");
const WRANGLER_JSONC = path.join(ROOT, "wrangler.jsonc");
const ENV_EXAMPLE = path.join(ROOT, ".env.example");
const ENV_FILE = path.join(ROOT, ".env");

// ─── CLI Argument Parsing ─────────────────────────────────────────────────────
interface Args {
    dialect?: string;
    databaseUrl?: string;
    hyperdriveId?: string;
    dbId?: string;
    dbName?: string;
    previewDbId?: string;
    previewDbName?: string;
    noPreview: boolean;
    migrate?: boolean;
    migratePreview?: boolean;
    r2BucketName?: string;
    noR2: boolean;
    signingKey?: string;
    tenantName?: string;
    adminUsername?: string;
    adminEmail?: string;
    adminName?: string;
    adminPassword?: string;
    issuerUrl?: string;
    yes: boolean;
    help: boolean;
}

function parseArgs(argv: string[]): Args {
    const args: Args = {
        noPreview: false,
        noR2: false,
        yes: false,
        help: false,
    };

    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        switch (arg) {
            case "--dialect":
                args.dialect = argv[++i];
                break;
            case "--database-url":
                args.databaseUrl = argv[++i];
                break;
            case "--hyperdrive-id":
                args.hyperdriveId = argv[++i];
                break;
            case "--db-id":
                args.dbId = argv[++i];
                break;
            case "--db-name":
                args.dbName = argv[++i];
                break;
            case "--preview-db-id":
                args.previewDbId = argv[++i];
                break;
            case "--preview-db-name":
                args.previewDbName = argv[++i];
                break;
            case "--no-preview":
                args.noPreview = true;
                break;
            case "--migrate":
                args.migrate = true;
                break;
            case "--no-migrate":
                args.migrate = false;
                break;
            case "--migrate-preview":
                args.migratePreview = true;
                break;
            case "--no-migrate-preview":
                args.migratePreview = false;
                break;
            case "--r2-bucket-name":
                args.r2BucketName = argv[++i];
                break;
            case "--no-r2":
                args.noR2 = true;
                break;
            case "--signing-key":
                args.signingKey = argv[++i];
                break;
            case "--tenant-name":
                args.tenantName = argv[++i];
                break;
            case "--admin-username":
                args.adminUsername = argv[++i];
                break;
            case "--admin-email":
                args.adminEmail = argv[++i];
                break;
            case "--admin-name":
                args.adminName = argv[++i];
                break;
            case "--admin-password":
                args.adminPassword = argv[++i];
                break;
            case "--issuer-url":
                args.issuerUrl = argv[++i];
                break;
            case "-y":
            case "--yes":
                args.yes = true;
                break;
            case "-h":
            case "--help":
                args.help = true;
                break;
        }
    }

    return args;
}

function printHelp() {
    console.log(`
${cyan("사용법:")} bun run scripts/setup.ts [옵션]

${cyan("옵션:")}
  --dialect <d>            DB 방언: d1(기본) | postgres | mysql | sqlite
  --database-url <url>     postgres/mysql/sqlite 연결 문자열
  --hyperdrive-id <id>     (postgres/mysql) Cloudflare Hyperdrive 구성 ID
  --db-id <id>              기존 D1 DB ID 직접 지정
  --db-name <name>          새로 생성할 D1 DB 이름
  --preview-db-id <id>      기존 프리뷰 D1 DB ID 직접 지정
  --preview-db-name <name>  새로 생성할 프리뷰 D1 DB 이름
  --no-preview              프리뷰 DB 미사용
  --migrate                 마이그레이션 자동 진행
  --no-migrate              마이그레이션 건너뜀
  --migrate-preview         프리뷰 DB 마이그레이션 자동 진행
  --no-migrate-preview      프리뷰 DB 마이그레이션 건너뜀
  --r2-bucket-name <name>   R2 버킷 이름 (기본값: lodestar-skin-cache)
  --no-r2                   R2 버킷 생성 건너뜀
  --signing-key <secret>    IDP_SIGNING_KEY_SECRET 값
  --tenant-name <name>      조직(테넌트) 이름
  --admin-username <id>     초기 관리자 아이디
  --admin-email <email>     초기 관리자 이메일
  --admin-name <name>       초기 관리자 표시 이름
  --admin-password <pass>   초기 관리자 비밀번호 (생략 시 자동 생성)
  --issuer-url <url>        IDP Issuer URL (배포 도메인)
  -y, --yes                 모든 확인 프롬프트 자동 승인
  -h, --help                도움말 출력
`);
}

// ─── Readline Helpers ─────────────────────────────────────────────────────────
let rl: readline.Interface | null = null;

function getRL(): readline.Interface {
    if (!rl) {
        rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
        });
    }
    return rl;
}

function closeRL() {
    if (rl) {
        rl.close();
        rl = null;
    }
}

async function ask(prompt: string, defaultVal?: string): Promise<string> {
    const displayPrompt = defaultVal !== undefined ? `${yellow(prompt)} [기본값: ${defaultVal}]: ` : `${yellow(prompt)}: `;

    return new Promise((resolve) => {
        getRL().question(displayPrompt, (answer: string) => {
            const trimmed = answer.trim();
            resolve(trimmed === "" && defaultVal !== undefined ? defaultVal : trimmed);
        });
    });
}

async function confirm(prompt: string, defaultYes = true): Promise<boolean> {
    const hint = defaultYes ? "[Y/n]" : "[y/N]";
    const displayPrompt = `${yellow(prompt)} ${hint}: `;

    return new Promise((resolve) => {
        getRL().question(displayPrompt, (answer: string) => {
            const trimmed = answer.trim().toLowerCase();
            if (trimmed === "") {
                resolve(defaultYes);
            } else {
                resolve(trimmed === "y" || trimmed === "yes");
            }
        });
    });
}

async function select(prompt: string, options: string[]): Promise<number> {
    console.log(`\n${cyan(prompt)}`);
    options.forEach((opt, i) => {
        console.log(`  ${i + 1}) ${opt}`);
    });

    return new Promise((resolve) => {
        const ask = () => {
            getRL().question(`${yellow("선택")} (1-${options.length}): `, (answer: string) => {
                const num = parseInt(answer.trim(), 10);
                if (num >= 1 && num <= options.length) {
                    resolve(num);
                } else {
                    console.log(red(`1에서 ${options.length} 사이의 숫자를 입력하세요.`));
                    ask();
                }
            });
        };
        ask();
    });
}

// ─── Spinner ──────────────────────────────────────────────────────────────────
const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

async function runWithSpinner(
    label: string,
    cmd: string,
    args: string[],
    options: { env?: Record<string, string> } = {},
): Promise<{ success: boolean; stdout: string; stderr: string; exitCode: number }> {
    let frameIdx = 0;
    process.stdout.write(`  ${SPINNER_FRAMES[0]} ${label}`);
    const interval = setInterval(() => {
        process.stdout.write(`\r  ${SPINNER_FRAMES[frameIdx++ % SPINNER_FRAMES.length]} ${label}`);
    }, 80);

    return new Promise((resolve) => {
        const child = spawn(cmd, args, {
            cwd: ROOT,
            env: options.env ? { ...process.env, ...options.env } : process.env,
        });
        let stdout = "";
        let stderr = "";
        child.stdout?.on("data", (d: Buffer) => {
            stdout += d.toString();
        });
        child.stderr?.on("data", (d: Buffer) => {
            stderr += d.toString();
        });
        child.on("close", (code: number | null) => {
            clearInterval(interval);
            const success = (code ?? 1) === 0;
            process.stdout.write(`\r  ${success ? green("✓") : red("✗")} ${label}\n`);
            resolve({ success, stdout, stderr, exitCode: code ?? 1 });
        });
    });
}

// ─── Command (inherit 모드용 — db:generate, db:migrate 등) ────────────────────
function runCommand(
    cmd: string,
    args: string[],
    options: { inherit?: boolean; env?: Record<string, string> } = {},
): {
    success: boolean;
    stdout: string;
    stderr: string;
    exitCode: number;
} {
    const result = spawnSync(cmd, args, {
        stdio: options.inherit ? "inherit" : "pipe",
        cwd: ROOT,
        encoding: "utf-8",
        env: options.env ? { ...process.env, ...options.env } : process.env,
    });

    return {
        success: result.status === 0,
        stdout: typeof result.stdout === "string" ? result.stdout : "",
        stderr: typeof result.stderr === "string" ? result.stderr : "",
        exitCode: result.status ?? 1,
    };
}

// ─── Wrangler Helpers ─────────────────────────────────────────────────────────
interface D1Database {
    name: string;
    uuid: string;
}

/** wrangler whoami → { loggedIn, accountId } */
async function wranglerWhoami(): Promise<{ loggedIn: boolean; accountId: string | null }> {
    const result = await runWithSpinner("wrangler 인증 확인 중...", "wrangler", ["whoami"]);
    const combined = result.stdout + result.stderr;
    const loggedIn = result.success && !combined.includes("You are not authenticated");
    const match = combined.match(/([0-9a-f]{32})/i);
    return { loggedIn, accountId: match ? match[1] : null };
}

async function createD1Database(name: string): Promise<string | null> {
    const result = await runWithSpinner(`D1 DB 생성 중: ${name}`, "wrangler", ["d1", "create", name]);
    if (!result.success) {
        console.error(red(`  D1 DB 생성 실패:\n${result.stderr}`));
        return null;
    }
    const combined = result.stdout + result.stderr;
    const match = combined.match(/"?database_id"?\s*[=:]\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"/i);
    if (!match) {
        console.error(red(`  D1 생성 결과에서 database_id를 찾을 수 없습니다:\n${combined}`));
        return null;
    }
    return match[1];
}

let _cachedDbList: D1Database[] | null | undefined = undefined;

async function listD1Databases(): Promise<D1Database[] | null> {
    if (_cachedDbList !== undefined) return _cachedDbList;
    const result = await runWithSpinner("D1 DB 목록 조회 중...", "wrangler", ["d1", "list", "--json"]);
    if (!result.success) {
        console.error(red(`  D1 목록 조회 실패:\n${result.stderr}`));
        _cachedDbList = null;
        return null;
    }
    try {
        _cachedDbList = JSON.parse(result.stdout) as D1Database[];
        return _cachedDbList;
    } catch {
        console.error(red(`  D1 목록 파싱 실패:\n${result.stdout}`));
        _cachedDbList = null;
        return null;
    }
}

// ─── File Helpers ─────────────────────────────────────────────────────────────
function copyFile(src: string, dest: string) {
    fs.copyFileSync(src, dest);
}

function readFile(filePath: string): string {
    return fs.readFileSync(filePath, "utf-8");
}

function writeFile(filePath: string, content: string) {
    fs.writeFileSync(filePath, content, "utf-8");
}

/** mkdtempSync으로 안전한 임시 파일 생성 (symlink attack 방지) */
function createTempFile(prefix: string, content: string): { filePath: string; cleanup: () => void } {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    const filePath = path.join(tmpDir, "content.sql");
    fs.writeFileSync(filePath, content, { mode: 0o600 });
    return {
        filePath,
        cleanup: () => {
            try {
                fs.unlinkSync(filePath);
            } catch {
                /* ignore */
            }
            try {
                fs.rmdirSync(tmpDir);
            } catch {
                /* ignore */
            }
        },
    };
}

function replaceAll(content: string, search: string, replacement: string): string {
    return content.split(search).join(replacement);
}

/** .env 파일을 파싱해 key=value 맵 반환 */
function loadEnvFile(envPath: string): Record<string, string> {
    if (!fs.existsSync(envPath)) return {};
    const env: Record<string, string> = {};
    for (const line of readFile(envPath).split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eq = trimmed.indexOf("=");
        if (eq < 0) continue;
        const key = trimmed.slice(0, eq).trim();
        let val = trimmed.slice(eq + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1);
        }
        if (key) env[key] = val;
    }
    return env;
}

/**
 * .env.example 의 KEY 중 현재 .env 에 없는 항목만 append.
 * 주석 블록(연속된 # 라인 + 다음 KEY=) 단위로 묶어서 통째로 추가하므로 가독성 유지.
 */
function mergeEnvFromExample(envPath: string, examplePath: string): { added: string[] } {
    if (!fs.existsSync(examplePath)) return { added: [] };
    const current = loadEnvFile(envPath);
    const exampleLines = readFile(examplePath).split("\n");

    // 예시 파일을 "주석 블록 + KEY= 라인" 단위로 묶는다.
    const blocks: { keys: string[]; lines: string[] }[] = [];
    let buffer: string[] = [];
    for (const line of exampleLines) {
        buffer.push(line);
        const trimmed = line.trim();
        const eq = trimmed.indexOf("=");
        const isAssign = !trimmed.startsWith("#") && eq > 0;
        if (isAssign) {
            const key = trimmed.slice(0, eq).trim();
            blocks.push({ keys: [key], lines: buffer });
            buffer = [];
        }
    }
    if (buffer.length > 0) blocks.push({ keys: [], lines: buffer });

    const added: string[] = [];
    const appendChunks: string[] = [];
    for (const blk of blocks) {
        const missing = blk.keys.filter((k) => !(k in current));
        if (blk.keys.length > 0 && missing.length > 0) {
            appendChunks.push(blk.lines.join("\n"));
            added.push(...missing);
        }
    }

    if (appendChunks.length === 0) return { added: [] };

    let body = readFile(envPath);
    if (!body.endsWith("\n")) body += "\n";
    body += "\n" + appendChunks.join("\n") + "\n";
    writeFile(envPath, body);
    return { added };
}

// ─── Steps ────────────────────────────────────────────────────────────────────

async function step0_wranglerLogin(args: Args): Promise<string | null> {
    console.log(`\n${cyan("─── 0. wrangler 로그인 체크 ───────────────────────────────")}`);

    const { loggedIn, accountId: detectedId } = await wranglerWhoami();
    let accountId = detectedId;

    if (!loggedIn) {
        console.log(yellow("  wrangler에 로그인하지 않았습니다."));

        if (args.yes) {
            console.log(red("  DB 생성을 위해 wrangler 로그인이 필요합니다. 종료합니다."));
            closeRL();
            process.exit(1);
        }

        const doLogin = await confirm("로그인하시겠습니까?", false);
        if (!doLogin) {
            console.log(red("  DB 생성을 위해 wrangler 로그인이 필요합니다. 종료합니다."));
            closeRL();
            process.exit(1);
        }

        console.log("  wrangler login 실행 중...");
        const result = runCommand("wrangler", ["login"], { inherit: true });
        if (!result.success) {
            console.error(red("  wrangler 로그인 실패. 종료합니다."));
            closeRL();
            process.exit(1);
        }

        // 로그인 후 재확인
        ({ accountId } = await wranglerWhoami());
    }

    if (accountId) {
        console.log(green(`  ✓ wrangler 로그인 확인됨 (Account ID: ${accountId})`));
    }
    return accountId;
}

/**
 * wrangler 가 빈 문자열 바인딩(`bucket_name: ""`, `database_name: ""` 등) 을 거부하므로
 * step3/4 의 wrangler 호출 전에 합리적 default 로 채워둔다. 사용자가 step3/4b 에서
 * 결정한 실제 값으로 덮어써진다.
 */
function normalizeWranglerPlaceholders() {
    if (!fs.existsSync(WRANGLER_JSONC)) return;
    let content = readFile(WRANGLER_JSONC);
    let changed = false;

    // r2_buckets bucket_name 빈값 → default
    const r2Re = /(\{[^{}]*"binding"\s*:\s*"SKIN_CACHE"[^{}]*\})/g;
    content = content.replace(r2Re, (block) => {
        if (/"bucket_name"\s*:\s*""/.test(block)) {
            changed = true;
            return block.replace(/"bucket_name"\s*:\s*""/, `"bucket_name": "lodestar-skin-cache"`);
        }
        return block;
    });

    // d1_databases database_name 빈값 → default (실제 DB 가 있을 때만 의미 있으므로 placeholder 사용)
    const dbRe = /(\{[^{}]*"binding"\s*:\s*"DB"[^{}]*\})/g;
    content = content.replace(dbRe, (block) => {
        if (/"database_name"\s*:\s*""/.test(block)) {
            changed = true;
            return block.replace(/"database_name"\s*:\s*""/, `"database_name": "lodestar-db"`);
        }
        return block;
    });

    // routes[0].pattern 빈값 → 임시 dev 도메인 (배포 도메인은 IDP_ISSUER_URL 결정 후 갱신)
    if (/"pattern"\s*:\s*""/.test(content)) {
        content = content.replace(/"pattern"\s*:\s*""/, `"pattern": "lodestar.example.com"`);
        changed = true;
    }

    if (changed) {
        writeFile(WRANGLER_JSONC, content);
    }
}

async function step1_createWranglerJsonc(args: Args) {
    console.log(`\n${cyan("─── 1. wrangler.jsonc 생성 ────────────────────────────────")}`);

    if (fs.existsSync(WRANGLER_JSONC)) {
        if (args.yes) {
            // 비대화 모드: 안전하게 유지
            console.log("  wrangler.jsonc 유지 (--yes)");
            return;
        }
        const choice = await select("wrangler.jsonc가 이미 존재합니다. 어떻게 처리할까요?", ["유지 (그대로 둠 — step4 에서 누락된 ID 만 채움)", "덮어쓰기 (example 로 초기화)"]);
        if (choice === 0) {
            console.log("  wrangler.jsonc 유지");
            normalizeWranglerPlaceholders();
            return;
        }
    }

    copyFile(WRANGLER_EXAMPLE, WRANGLER_JSONC);
    normalizeWranglerPlaceholders();
    console.log(green("  ✓ wrangler.jsonc 생성 완료"));
}

async function step2_createEnv(args: Args) {
    console.log(`\n${cyan("─── 2. .env 생성 ──────────────────────────────────────────")}`);

    if (fs.existsSync(ENV_FILE)) {
        if (args.yes) {
            // 비대화 모드: 누락된 키만 자동 병합
            const { added } = mergeEnvFromExample(ENV_FILE, ENV_EXAMPLE);
            if (added.length > 0) console.log(green(`  ✓ .env 병합: ${added.length} 개 누락 키 추가 (${added.join(", ")})`));
            else console.log("  .env 유지 (누락 키 없음)");
            return;
        }
        const choice = await select(".env 가 이미 존재합니다. 어떻게 처리할까요?", ["유지 (그대로 둠)", "병합 (.env.example 의 누락된 키만 추가)", "덮어쓰기 (example 로 초기화)"]);
        if (choice === 0) {
            console.log("  .env 유지");
            return;
        }
        if (choice === 1) {
            const { added } = mergeEnvFromExample(ENV_FILE, ENV_EXAMPLE);
            if (added.length > 0) console.log(green(`  ✓ .env 병합: ${added.length} 개 누락 키 추가 (${added.join(", ")})`));
            else console.log("  .env 유지 (누락 키 없음)");
            return;
        }
    }

    copyFile(ENV_EXAMPLE, ENV_FILE);
    console.log(green("  ✓ .env 생성 완료"));
}

async function setupDb(label: string, nameArg: string | undefined, idArg: string | undefined, defaultName: string, isPreview = false): Promise<{ id: string; name: string } | null> {
    // If ID directly provided
    if (idArg) {
        console.log(green(`  ✓ ${label} ID: ${idArg}`));
        return { id: idArg, name: defaultName };
    }

    const thirdOption = isPreview ? "미사용" : "나중에 직접 설정 (종료)";
    const choice = await select(`${label} 설정`, ["지금 새로 생성", "이미 생성된 DB 사용", thirdOption]);

    if (choice === 3) {
        if (isPreview) {
            console.log("  프리뷰 DB 미사용");
            return null;
        }
        console.log(yellow("  wrangler.jsonc와 .env의 YOUR_D1_DATABASE_ID 를 직접 입력하세요."));
        closeRL();
        process.exit(0);
    }

    if (choice === 1) {
        // Create new
        const name = nameArg ?? (await ask(`${label} 이름을 입력하세요`, defaultName));
        const id = await createD1Database(name);
        if (!id) {
            console.error(red(`  ${label} 생성 실패. 종료합니다.`));
            closeRL();
            process.exit(1);
        }
        return { id, name };
    }

    // Use existing DB
    const dbs = await listD1Databases();
    if (!dbs || dbs.length === 0) {
        console.error(red("  D1 데이터베이스 목록을 가져올 수 없거나 비어있습니다. 종료합니다."));
        closeRL();
        process.exit(1);
    }

    const options = dbs!.map((db) => `${db.name} (id: ${db.uuid})`);
    const dbChoice = await select(`사용할 ${label}를 선택하세요`, options);
    const selected = dbs![dbChoice - 1];
    console.log(green(`  ✓ ${selected.name} (id: ${selected.uuid}) 선택됨`));
    return { id: selected.uuid, name: selected.name };
}

/**
 * 기존 .env / wrangler.jsonc 에서 이미 설정된 D1 ID 를 탐지한다.
 * UUID 형식의 값만 유효 — placeholder("YOUR_D1_*") 는 무시.
 */
function detectExistingD1(): { dbId: string | null; previewDbId: string | null; dbName: string | null; previewDbName: string | null } {
    const env = loadEnvFile(ENV_FILE);
    const isUuid = (s?: string): s is string => !!s && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);

    let dbId: string | null = isUuid(env.CLOUDFLARE_D1_DATABASE_ID) ? env.CLOUDFLARE_D1_DATABASE_ID : null;
    let previewDbId: string | null = isUuid(env.CLOUDFLARE_D1_PREVIEW_DATABASE_ID) ? env.CLOUDFLARE_D1_PREVIEW_DATABASE_ID : null;
    let dbName: string | null = null;
    let previewDbName: string | null = null;

    // wrangler.jsonc 에서 database_name + database_id 매칭
    if (fs.existsSync(WRANGLER_JSONC)) {
        const wc = readFile(WRANGLER_JSONC);
        // strip line comments
        const stripped = wc.replace(/\/\/[^\n]*/g, "");
        const blocks = [...stripped.matchAll(/\{[^{}]*"binding"\s*:\s*"DB"[^{}]*\}/g)].map((m) => m[0]);
        for (const blk of blocks) {
            const idMatch = blk.match(/"database_id"\s*:\s*"([0-9a-f-]{36})"/i);
            const nameMatch = blk.match(/"database_name"\s*:\s*"([^"]+)"/);
            const previewMatch = blk.match(/"preview_database_id"\s*:\s*"([0-9a-f-]{36})"/i);
            if (idMatch && isUuid(idMatch[1])) dbId = dbId ?? idMatch[1];
            if (nameMatch) dbName = dbName ?? nameMatch[1];
            if (previewMatch && isUuid(previewMatch[1])) previewDbId = previewDbId ?? previewMatch[1];
        }
    }
    if (dbId && !dbName) dbName = "lodestar-db";
    if (previewDbId && !previewDbName && dbName) previewDbName = `${dbName}-preview`;

    return { dbId, previewDbId, dbName, previewDbName };
}

async function step3_dbSetup(args: Args): Promise<{
    dbId: string;
    dbName: string;
    previewDbId: string | null;
    previewDbName: string | null;
}> {
    console.log(`\n${cyan("─── 3. D1 데이터베이스 설정 ────────────────────────────────")}`);

    // CLI 로 명시 지정한 경우는 그대로 사용
    if (!args.dbId && !args.dbName) {
        const existing = detectExistingD1();
        if (existing.dbId) {
            console.log(green(`  기존 D1 설정 발견:`));
            console.log(`    DB:         ${existing.dbName ?? "?"}  (id: ${existing.dbId})`);
            if (existing.previewDbId) console.log(`    Preview DB: ${existing.previewDbName ?? "?"}  (id: ${existing.previewDbId})`);

            const keep = args.yes || (await confirm("기존 D1 설정을 유지하시겠습니까?", true));
            if (keep) {
                return {
                    dbId: existing.dbId,
                    dbName: existing.dbName ?? "lodestar-db",
                    previewDbId: args.noPreview ? null : existing.previewDbId,
                    previewDbName: args.noPreview ? null : existing.previewDbName,
                };
            }
        }
    }

    const db = await setupDb("D1 데이터베이스", args.dbName, args.dbId, "lodestar-db");
    if (!db) {
        closeRL();
        throw new Error("DB 설정에 실패했습니다.");
    }

    let previewDbId: string | null = null;
    let previewDbName: string | null = null;

    if (!args.noPreview) {
        if (args.previewDbId) {
            previewDbId = args.previewDbId;
            previewDbName = args.previewDbName ?? `${db.name}-preview`;
            console.log(green(`  ✓ 프리뷰 DB ID: ${previewDbId}`));
        } else {
            const previewDb = await setupDb("프리뷰 D1 데이터베이스", args.previewDbName, undefined, `${db.name}-preview`, true);
            previewDbId = previewDb?.id ?? null;
            previewDbName = previewDb?.name ?? null;
        }
    }

    return { dbId: db.id, dbName: db.name, previewDbId, previewDbName };
}

async function step4_updateFiles(dbId: string, previewDbId: string | null, accountId: string | null, dbName: string) {
    console.log(`\n${cyan("─── 4. 파일 업데이트 ──────────────────────────────────────")}`);

    // Update wrangler.jsonc — placeholder 치환 + 기존 UUID 도 새 값으로 교체.
    let wranglerContent = readFile(WRANGLER_JSONC);

    // 1) example placeholder 치환
    wranglerContent = replaceAll(wranglerContent, "YOUR_D1_DATABASE_ID", dbId);
    if (previewDbId) {
        wranglerContent = replaceAll(wranglerContent, "YOUR_D1_PREVIEW_DATABASE_ID", previewDbId);
        // 주석 처리된 preview_database_id 라인을 활성화 (값 유무 무관)
        wranglerContent = wranglerContent.replace(/\/\/\s*"preview_database_id":\s*"([^"]*)"/g, `"preview_database_id": "$1"`);
    }

    // 2) "binding": "DB" 블록 안의 database_name / database_id / preview_database_id 갱신.
    //    빈 값("") 도 채울 수 있도록 [^"]* 사용.
    wranglerContent = wranglerContent.replace(/(\{[^{}]*"binding"\s*:\s*"DB"[^{}]*\})/g, (block) => {
        let updated = block;

        const nameRe = /"database_name"\s*:\s*"[^"]*"/;
        if (nameRe.test(updated)) updated = updated.replace(nameRe, `"database_name": "${dbName}"`);

        const idRe = /"database_id"\s*:\s*"[^"]*"/;
        if (idRe.test(updated)) updated = updated.replace(idRe, `"database_id": "${dbId}"`);
        else updated = updated.replace(/("database_name"\s*:\s*"[^"]*",?)/, `$1\n\t\t\t"database_id": "${dbId}",`);

        if (previewDbId) {
            const previewRe = /"preview_database_id"\s*:\s*"[^"]*"/;
            if (previewRe.test(updated)) updated = updated.replace(previewRe, `"preview_database_id": "${previewDbId}"`);
            else updated = updated.replace(/("database_id"\s*:\s*"[^"]*",?)/, `$1\n\t\t\t"preview_database_id": "${previewDbId}",`);
        }
        return updated;
    });

    writeFile(WRANGLER_JSONC, wranglerContent);
    console.log(green("  ✓ wrangler.jsonc 업데이트 완료"));

    // Update .env — 누락된 키는 그대로 추가, 기존 빈 값/플레이스홀더만 갱신.
    let envContent = readFile(ENV_FILE);
    const setOrAppend = (key: string, value: string) => {
        const re = new RegExp(`^${key}=.*$`, "m");
        if (re.test(envContent)) {
            envContent = envContent.replace(re, `${key}="${value}"`);
        } else {
            if (!envContent.endsWith("\n")) envContent += "\n";
            envContent += `${key}="${value}"\n`;
        }
    };
    if (accountId) setOrAppend("CLOUDFLARE_ACCOUNT_ID", accountId);
    setOrAppend("CLOUDFLARE_D1_DATABASE_ID", dbId);
    if (previewDbId) setOrAppend("CLOUDFLARE_D1_PREVIEW_DATABASE_ID", previewDbId);

    writeFile(ENV_FILE, envContent);
    console.log(green("  ✓ .env 업데이트 완료"));

    // wrangler.jsonc 의 vars 블록을 .env 와 동기화 (secret/token 제외).
    syncWranglerVarsFromEnv();
}

/**
 * `.env` 의 비-시크릿 키를 `wrangler.jsonc` 의 vars 블록과 동기화한다.
 * secret/token 류는 제외 — `wrangler secret put` 으로 별도 배포.
 */
const SECRET_KEYS = new Set(["IDP_SIGNING_KEY_SECRET", "SMTP_PASSWORD", "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_D1_TOKEN"]);

function syncWranglerVarsFromEnv() {
    if (!fs.existsSync(WRANGLER_JSONC) || !fs.existsSync(ENV_FILE)) return;
    const env = loadEnvFile(ENV_FILE);
    let envContent = readFile(ENV_FILE);
    let wranglerContent = readFile(WRANGLER_JSONC);

    const synced: string[] = [];
    for (const [key, value] of Object.entries(env)) {
        if (SECRET_KEYS.has(key)) continue;
        if (value === "") continue;
        const r = applyVar(envContent, wranglerContent, key, value);
        envContent = r.env;
        wranglerContent = r.wrangler;
        synced.push(key);
    }

    // routes[0].pattern 자동 채움 — IDP_ISSUER_URL 의 host 사용 (localhost 제외).
    const issuer = env.IDP_ISSUER_URL ?? "";
    if (issuer) {
        try {
            const host = new URL(issuer).host;
            const isLocal = /^(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?$/.test(host);
            if (!isLocal) {
                const before = wranglerContent;
                wranglerContent = wranglerContent.replace(/("pattern"\s*:\s*)"[^"]*"/, `$1"${host.split(":")[0]}"`);
                if (wranglerContent !== before) synced.push("routes.pattern");
            }
        } catch {
            /* invalid URL — skip */
        }
    }

    writeFile(ENV_FILE, envContent);
    writeFile(WRANGLER_JSONC, wranglerContent);
    if (synced.length > 0) console.log(green(`  ✓ wrangler.jsonc vars 동기화 (${synced.length}개): ${synced.join(", ")}`));
}

/** wrangler.jsonc 의 SKIN_CACHE 바인딩에서 bucket_name 추출. */
function detectExistingR2BucketName(): string | null {
    if (!fs.existsSync(WRANGLER_JSONC)) return null;
    const wc = readFile(WRANGLER_JSONC).replace(/\/\/[^\n]*/g, "");
    const block = wc.match(/\{[^{}]*"binding"\s*:\s*"SKIN_CACHE"[^{}]*\}/);
    if (!block) return null;
    const m = block[0].match(/"bucket_name"\s*:\s*"([^"]+)"/);
    return m?.[1] ?? null;
}

/** Cloudflare 에 해당 R2 버킷이 실제로 존재하는지 확인. */
async function r2BucketExists(name: string): Promise<boolean> {
    const result = runCommand("wrangler", ["r2", "bucket", "list"], { inherit: false });
    if (!result.success) return false;
    return result.stdout.includes(name);
}

async function step4b_r2Setup(args: Args) {
    console.log(`\n${cyan("─── 4b. R2 버킷 설정 (스킨 캐시) ─────────────────────────────")}`);

    if (args.noR2) {
        console.log("  R2 버킷 생성 건너뜀");
        return;
    }

    // 기존 설정 감지: wrangler.jsonc 에 bucket_name 이 있고 실제 Cloudflare 에 존재하면 유지 옵션 제공.
    if (!args.r2BucketName) {
        const existingName = detectExistingR2BucketName();
        if (existingName) {
            const exists = await r2BucketExists(existingName);
            if (exists) {
                console.log(green(`  기존 R2 버킷 발견: ${existingName}`));
                const keep = args.yes || (await confirm("기존 R2 버킷을 그대로 사용하시겠습니까?", true));
                if (keep) {
                    console.log("  R2 버킷 유지");
                    return;
                }
            } else {
                console.log(yellow(`  wrangler.jsonc 에 '${existingName}' 으로 설정돼 있으나 Cloudflare 에 존재하지 않습니다.`));
            }
        }
    }

    const doCreate = args.yes || (await confirm("커스텀 스킨 캐시용 R2 버킷을 생성하시겠습니까?", true));
    if (!doCreate) {
        console.log("  R2 버킷 생성 건너뜀");
        return;
    }

    const bucketName = args.r2BucketName ?? (await ask("R2 버킷 이름", "lodestar-skin-cache"));

    const result = await runWithSpinner(`R2 버킷 생성 중: ${bucketName}`, "wrangler", ["r2", "bucket", "create", bucketName]);
    if (!result.success) {
        const combined = result.stdout + result.stderr;
        if (combined.includes("already exists")) {
            console.log(yellow(`  버킷 '${bucketName}'이 이미 존재합니다. 기존 버킷을 사용합니다.`));
        } else {
            console.error(red(`  R2 버킷 생성 실패:\n${result.stderr}`));
            return;
        }
    } else {
        console.log(green(`  ✓ R2 버킷 '${bucketName}' 생성 완료`));
    }

    // wrangler.jsonc의 bucket_name 업데이트
    if (fs.existsSync(WRANGLER_JSONC)) {
        let content = readFile(WRANGLER_JSONC);
        content = replaceAll(content, "lodestar-skin-cache", bucketName);
        writeFile(WRANGLER_JSONC, content);
        console.log(green(`  ✓ wrangler.jsonc bucket_name 업데이트 완료`));
    }
}

// ─── Migration Conflict Detection ────────────────────────────────────────────

async function getExistingTables(dbName: string, env: Record<string, string>): Promise<string[] | null> {
    const result = await runWithSpinner(
        `기존 테이블 조회 중 (${dbName})...`,
        "wrangler",
        ["d1", "execute", dbName, "--remote", "--json", "--command", "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"],
        { env },
    );
    if (!result.success) {
        console.warn(yellow(`  테이블 조회 실패 (건너뜀): ${result.stderr.slice(0, 120)}`));
        return null;
    }
    try {
        const parsed = JSON.parse(result.stdout) as Array<{ results: Array<{ name: string }> }>;
        return (parsed[0]?.results ?? []).map((r) => r.name);
    } catch {
        return null;
    }
}

function extractTablesFromMigrations(): string[] {
    const drizzleDir = path.join(ROOT, "drizzle");
    if (!fs.existsSync(drizzleDir)) return [];
    const tables = new Set<string>();
    for (const file of fs
        .readdirSync(drizzleDir)
        .filter((f) => f.endsWith(".sql"))
        .sort()) {
        const content = readFile(path.join(drizzleDir, file));
        for (const m of content.matchAll(/CREATE TABLE [`"]?(\w+)[`"]?\s*\(/gi)) {
            tables.add(m[1]);
        }
    }
    return [...tables];
}

function buildFilteredMigrationSQL(conflicting: Set<string>): string {
    const drizzleDir = path.join(ROOT, "drizzle");
    const stmts: string[] = [];
    for (const file of fs
        .readdirSync(drizzleDir)
        .filter((f) => f.endsWith(".sql"))
        .sort()) {
        const content = readFile(path.join(drizzleDir, file));
        for (const stmt of content.split("--> statement-breakpoint")) {
            const s = stmt.trim();
            if (!s) continue;
            const tblMatch = s.match(/^CREATE TABLE [`"]?(\w+)[`"]?\s*\(/i);
            if (tblMatch && conflicting.has(tblMatch[1])) continue;
            const idxMatch = s.match(/^CREATE (?:UNIQUE )?INDEX \S+ ON [`"]?(\w+)[`"]?/i);
            if (idxMatch && conflicting.has(idxMatch[1])) continue;
            stmts.push(s);
        }
    }
    return stmts.join(";\n");
}

function buildDrizzleTrackingSQL(): string {
    const drizzleDir = path.join(ROOT, "drizzle");
    const now = Date.now();
    const lines = [`CREATE TABLE IF NOT EXISTS "__drizzle_migrations" (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, hash TEXT NOT NULL, created_at NUMERIC);`];
    for (const file of fs
        .readdirSync(drizzleDir)
        .filter((f) => f.endsWith(".sql"))
        .sort()) {
        const content = readFile(path.join(drizzleDir, file));
        const hash = createHash("sha256").update(content).digest("hex");
        lines.push(`INSERT INTO "__drizzle_migrations" (hash, created_at) SELECT '${hash}', ${now} WHERE NOT EXISTS (SELECT 1 FROM "__drizzle_migrations" WHERE hash = '${hash}');`);
    }
    return lines.join("\n");
}

async function handleMigrationConflicts(dbName: string, env: Record<string, string>, args: Args): Promise<"proceed" | "done"> {
    const existing = await getExistingTables(dbName, env);
    if (!existing) return "proceed";

    const migrationTables = extractTablesFromMigrations();

    // Stale `__drizzle_migrations` 감지: 추적 테이블에 레코드는 있는데 실제 사용자 테이블은 없으면
    // drizzle 이 "이미 적용됨"으로 오판해 silent-skip 한다. 이런 상태를 정리한 뒤 재적용.
    const hasTracking = existing.includes("__drizzle_migrations");
    const userTablesPresent = migrationTables.some((t) => existing.includes(t));
    if (hasTracking && !userTablesPresent) {
        console.log(yellow(`  ⚠  __drizzle_migrations 추적은 있으나 사용자 테이블이 없어 stale 상태입니다 (${dbName}).`));
        const cleanupSql = [`DROP TABLE IF EXISTS "__drizzle_migrations";`, `DROP TABLE IF EXISTS "_seed_migrations";`].join("\n");
        const { filePath: tmp, cleanup } = createTempFile("idp-stale-", cleanupSql);
        try {
            const r = await runWithSpinner(`stale 추적 테이블 삭제 중 (${dbName})...`, "wrangler", ["d1", "execute", dbName, "--remote", "--file", tmp], { env });
            if (!r.success) {
                console.error(red(`  추적 테이블 삭제 실패:\n${r.stderr}`));
                closeRL();
                process.exit(1);
            }
        } finally {
            cleanup();
        }
        console.log(green(`  ✓ stale 추적 테이블 정리 완료 → 전체 마이그레이션 재적용`));
        return "proceed";
    }

    if (existing.length === 0) return "proceed";

    const conflicts = migrationTables.filter((t) => existing.includes(t));
    if (conflicts.length === 0) return "proceed";

    console.log(yellow(`\n  ⚠  이미 존재하는 테이블 발견 (${dbName}):`));
    conflicts.forEach((t) => console.log(`     - ${t}`));

    let choice: number;
    if (args.yes) {
        choice = 2;
        console.log(yellow("  (--yes 모드) 겹치는 테이블은 건너뜀으로 자동 선택"));
    } else {
        choice = await select("마이그레이션 방식을 선택하세요", ["겹치는 테이블 삭제 후 전체 마이그레이션 (데이터 손실 주의)", "겹치는 테이블은 건너뛰고 나머지만 마이그레이션"]);
    }

    if (choice === 1) {
        // 핵심: 사용자 테이블과 함께 `__drizzle_migrations` 도 삭제해야 한다.
        // 안 그러면 drizzle 이 "이미 적용됨" 으로 오판하고 마이그레이션을 silent-skip 한다.
        const dropSQL = [
            "PRAGMA foreign_keys = OFF;",
            ...conflicts.map((t) => `DROP TABLE IF EXISTS \`${t}\`;`),
            `DROP TABLE IF EXISTS "__drizzle_migrations";`,
            `DROP TABLE IF EXISTS "_seed_migrations";`,
            "PRAGMA foreign_keys = ON;",
        ].join("\n");

        const { filePath: dropTmpFile, cleanup: dropCleanup } = createTempFile("idp-drop-", dropSQL);
        try {
            const dropResult = await runWithSpinner(`겹치는 테이블 삭제 중 (${dbName})...`, "wrangler", ["d1", "execute", dbName, "--remote", "--file", dropTmpFile], { env });
            if (!dropResult.success) {
                console.error(red(`  테이블 삭제 실패:\n${dropResult.stderr}`));
                closeRL();
                process.exit(1);
            }
        } finally {
            dropCleanup();
        }
        console.log(green(`  ✓ ${conflicts.length}개 테이블 삭제 완료 → 전체 마이그레이션 진행`));
        return "proceed";
    }

    // Option 2: 필터링된 SQL + drizzle tracking
    const combinedSQL = buildFilteredMigrationSQL(new Set(conflicts)) + "\n" + buildDrizzleTrackingSQL();
    const { filePath: filteredTmpFile, cleanup: filteredCleanup } = createTempFile("idp-migrate-", combinedSQL);
    try {
        const runResult = await runWithSpinner(`필터링된 마이그레이션 실행 중 (${dbName})...`, "wrangler", ["d1", "execute", dbName, "--remote", "--file", filteredTmpFile], { env });
        if (!runResult.success) {
            console.error(red(`  필터링된 마이그레이션 실패:\n${runResult.stderr}`));
            closeRL();
            process.exit(1);
        }
    } finally {
        filteredCleanup();
    }
    console.log(green(`  ✓ 필터링된 마이그레이션 완료 (drizzle tracking 업데이트됨)`));
    return "done";
}

// ─────────────────────────────────────────────────────────────────────────────

async function step5_migrate(args: Args, hasPreviewDb: boolean, dbName: string, previewDbName: string | null) {
    console.log(`\n${cyan("─── 5. 마이그레이션 ────────────────────────────────────────")}`);

    let doMigrate = args.migrate;
    if (doMigrate === undefined) {
        doMigrate = await confirm("마이그레이션을 지금 진행하시겠습니까?", true);
    }

    if (!doMigrate) {
        console.log("  마이그레이션 건너뜀");
        return;
    }

    // .env 로드 후 Cloudflare 자격증명 확인
    const envVars = loadEnvFile(ENV_FILE);

    if (!envVars.CLOUDFLARE_ACCOUNT_ID) {
        console.log(yellow("\n  Cloudflare 계정 ID를 감지할 수 없습니다."));
        const id = await ask("CLOUDFLARE_ACCOUNT_ID 직접 입력", "");
        if (!id) {
            console.error(red("  계정 ID가 없으면 마이그레이션을 실행할 수 없습니다."));
            closeRL();
            process.exit(1);
        }
        envVars.CLOUDFLARE_ACCOUNT_ID = id;
        let envContent = readFile(ENV_FILE);
        envContent = envContent.replace(/^CLOUDFLARE_ACCOUNT_ID=".*"$/m, `CLOUDFLARE_ACCOUNT_ID="${id}"`);
        writeFile(ENV_FILE, envContent);
    }

    // 토큰 확인 — CLOUDFLARE_D1_TOKEN 또는 CLOUDFLARE_API_TOKEN 중 하나
    const hasToken = (v: string | undefined) => !!v && v.length > 0;
    if (!hasToken(envVars.CLOUDFLARE_D1_TOKEN) && !hasToken(envVars.CLOUDFLARE_API_TOKEN)) {
        console.log(`
  ${cyan("Cloudflare API 토큰이 필요합니다.")}
  아래 URL에서 토큰을 생성하세요:

  ${yellow("https://dash.cloudflare.com/?to=/:account/api-tokens/create")}

  토큰 생성 방법:
    1. [사용자 정의 토큰 만들기] 선택
    2. 권한 추가: [계정] > [D1] > [편집]
    3. 토큰 생성 후 아래에 붙여넣기
`);
        const token = await ask("CLOUDFLARE_D1_TOKEN 입력", "");
        if (!token) {
            console.error(red("  토큰이 없으면 마이그레이션을 실행할 수 없습니다."));
            closeRL();
            process.exit(1);
        }
        let envContent = readFile(ENV_FILE);
        if (/^CLOUDFLARE_D1_TOKEN=/m.test(envContent)) {
            envContent = envContent.replace(/^CLOUDFLARE_D1_TOKEN=".*"$/m, `CLOUDFLARE_D1_TOKEN="${token}"`);
        } else {
            if (!envContent.endsWith("\n")) envContent += "\n";
            envContent += `CLOUDFLARE_D1_TOKEN="${token}"\n`;
        }
        writeFile(ENV_FILE, envContent);
    }

    // 파일 재로드로 최신 값 보장
    const freshEnv = loadEnvFile(ENV_FILE);
    const migrateEnv: Record<string, string> = {
        CLOUDFLARE_ACCOUNT_ID: freshEnv.CLOUDFLARE_ACCOUNT_ID ?? "",
        CLOUDFLARE_D1_DATABASE_ID: freshEnv.CLOUDFLARE_D1_DATABASE_ID ?? "",
        CLOUDFLARE_D1_PREVIEW_DATABASE_ID: freshEnv.CLOUDFLARE_D1_PREVIEW_DATABASE_ID ?? "",
        ...(hasToken(freshEnv.CLOUDFLARE_D1_TOKEN) ? { CLOUDFLARE_D1_TOKEN: freshEnv.CLOUDFLARE_D1_TOKEN! } : {}),
        ...(hasToken(freshEnv.CLOUDFLARE_API_TOKEN) ? { CLOUDFLARE_API_TOKEN: freshEnv.CLOUDFLARE_API_TOKEN! } : {}),
    };

    // Generate migrations
    console.log("\n  bun run db:generate 실행 중...");
    const generateResult = runCommand("bun", ["run", "db:generate"], {
        inherit: true,
        env: migrateEnv,
    });
    if (!generateResult.success) {
        console.error(red("  db:generate 실패"));
        closeRL();
        process.exit(1);
    }
    console.log(green("  ✓ db:generate 완료"));

    // 프로덕션 DB 충돌 확인 후 마이그레이션
    const prodConflict = await handleMigrationConflicts(dbName, migrateEnv, args);
    if (prodConflict !== "done") {
        console.log("  bun run db:migrate 실행 중...");
        const migrateResult = runCommand("bun", ["run", "db:migrate"], {
            inherit: true,
            env: migrateEnv,
        });
        if (!migrateResult.success) {
            console.error(red("  db:migrate 실패"));
            closeRL();
            process.exit(1);
        }
        console.log(green("  ✓ db:migrate 완료"));
    }

    // 프리뷰 DB 마이그레이션
    if (hasPreviewDb && previewDbName) {
        let doMigratePreview = args.migratePreview;
        if (doMigratePreview === undefined) {
            doMigratePreview = await confirm("프리뷰 DB에도 마이그레이션을 진행하시겠습니까?", true);
        }

        if (doMigratePreview) {
            const previewEnv = { ...migrateEnv, CLOUDFLARE_IS_PREVIEW: "true" };
            const previewConflict = await handleMigrationConflicts(previewDbName, previewEnv, args);
            if (previewConflict !== "done") {
                console.log("  bun run db:migrate:preview 실행 중...");
                const previewResult = runCommand("bun", ["run", "db:migrate:preview"], {
                    inherit: true,
                    env: previewEnv,
                });
                if (!previewResult.success) {
                    console.error(red("  db:migrate:preview 실패"));
                    closeRL();
                    process.exit(1);
                }
                console.log(green("  ✓ db:migrate:preview 완료"));
            }
        } else {
            console.log("  프리뷰 DB 마이그레이션 건너뜀");
        }
    }
}

// ─── Password Hashing ─────────────────────────────────────────────────────────
// 앱의 정규 해시(scrypt — `hashPassword`, node:crypto 네이티브라 Workers/Node/Bun 공통)를
// 그대로 재사용한다. 과거 PBKDF2 직접 구현은 Workers WebCrypto 의 반복 상한(100k)과 얽혀
// 검증 불가/OWASP 미달 문제가 있었으므로 제거했다.

function generateRandomPassword(length = 20): string {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%";
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    return Array.from(bytes, (b) => chars[b % chars.length]).join("");
}

// ─── Admin Seeding ────────────────────────────────────────────────────────────

interface AdminSeedData {
    tenantName: string;
    email: string;
    username: string;
    displayName: string;
    hashedPassword: string;
}

async function seedAdminToDb(dbName: string, data: AdminSeedData, env: Record<string, string>, isPreview = false): Promise<boolean> {
    const now = Date.now();
    const tenantId = crypto.randomUUID();
    const userId = crypto.randomUUID();
    const credId = crypto.randomUUID();
    const identityId = crypto.randomUUID();

    const esc = (s: string) => s.replace(/'/g, "''");

    const sql = [
        // 테넌트 생성 (이미 존재하면 이름만 업데이트)
        `INSERT INTO tenants (id, slug, name, status, created_at, updated_at) VALUES ('${tenantId}', 'default', '${esc(data.tenantName)}', 'active', ${now}, ${now}) ON CONFLICT(slug) DO UPDATE SET name = excluded.name;`,
        // 동일 이메일 admin이 없을 때만 삽입
        `INSERT INTO users (id, tenant_id, email, username, display_name, role, status, created_at, updated_at) SELECT '${userId}', t.id, '${esc(data.email)}', '${esc(data.username)}', '${esc(data.displayName)}', 'admin', 'active', ${now}, ${now} FROM tenants t WHERE t.slug = 'default' AND NOT EXISTS (SELECT 1 FROM users WHERE email = '${esc(data.email)}' AND tenant_id = t.id);`,
        // 비밀번호 credential (user INSERT가 성공한 경우에만)
        `INSERT INTO credentials (id, user_id, type, secret, label, created_at) SELECT '${credId}', '${userId}', 'password', '${esc(data.hashedPassword)}', '비밀번호', ${now} WHERE EXISTS (SELECT 1 FROM users WHERE id = '${userId}') AND NOT EXISTS (SELECT 1 FROM credentials WHERE user_id = '${userId}' AND type = 'password');`,
        // local identity
        `INSERT INTO identities (id, tenant_id, user_id, provider, subject, email, linked_at) SELECT '${identityId}', t.id, '${userId}', 'local', '${esc(data.email)}', '${esc(data.email)}', ${now} FROM tenants t WHERE t.slug = 'default' AND NOT EXISTS (SELECT 1 FROM identities WHERE user_id = '${userId}' AND provider = 'local');`,
    ].join("\n");

    const { filePath: seedTmpFile, cleanup: seedCleanup } = createTempFile("idp-seed-", sql);
    const actualEnv = isPreview ? { ...env, CLOUDFLARE_IS_PREVIEW: "true" } : env;
    const label = `관리자 계정 생성 중 (${dbName}${isPreview ? " preview" : ""})...`;

    try {
        const result = await runWithSpinner(label, "wrangler", ["d1", "execute", dbName, "--remote", "--file", seedTmpFile], { env: actualEnv });

        if (!result.success) {
            console.error(red(`  관리자 계정 생성 실패:\n${result.stderr}`));
            return false;
        }
        return true;
    } finally {
        seedCleanup();
    }
}

async function step5b_bootstrapConfig(args: Args, dbName: string, previewDbName: string | null): Promise<{ email: string; password: string; generated: boolean } | null> {
    console.log(`\n${cyan("─── 5b. 초기 관리자 계정 생성 ─────────────────────────────────")}`);

    const tenantName = args.tenantName ?? (await ask("조직(테넌트) 이름", "My Organization"));
    const username = args.adminUsername ?? (await ask("초기 관리자 아이디", "admin"));
    const email = args.adminEmail ?? (await ask("초기 관리자 이메일", "admin@example.com"));
    const displayName = args.adminName ?? (await ask("초기 관리자 표시 이름", "관리자"));
    const issuerUrl = args.issuerUrl ?? (await ask("IDP Issuer URL", "http://localhost:5173"));

    let password: string;
    let generated = false;
    if (args.adminPassword) {
        password = args.adminPassword;
    } else {
        const input = await ask("초기 관리자 비밀번호 (엔터: 자동 생성)", "");
        if (input === "") {
            password = generateRandomPassword(20);
            generated = true;
        } else {
            password = input;
        }
    }

    console.log("  비밀번호 해싱 중...");
    const hashedPassword = await hashPassword(password);

    // .env에 민감하지 않은 값만 저장
    if (fs.existsSync(ENV_FILE)) {
        let envContent = readFile(ENV_FILE);
        envContent = envContent.replace(/^IDP_DEFAULT_TENANT_NAME=".*"$/m, `IDP_DEFAULT_TENANT_NAME="${tenantName}"`);
        envContent = envContent.replace(/^IDP_ISSUER_URL=".*"$/m, `IDP_ISSUER_URL="${issuerUrl}"`);
        writeFile(ENV_FILE, envContent);
        console.log(green("  ✓ .env 업데이트 완료 (테넌트 이름, Issuer URL)"));
    }

    const envVars = loadEnvFile(ENV_FILE);
    const wranglerEnv: Record<string, string> = {
        CLOUDFLARE_ACCOUNT_ID: envVars.CLOUDFLARE_ACCOUNT_ID ?? "",
        ...(envVars.CLOUDFLARE_D1_TOKEN ? { CLOUDFLARE_D1_TOKEN: envVars.CLOUDFLARE_D1_TOKEN } : {}),
        ...(envVars.CLOUDFLARE_API_TOKEN ? { CLOUDFLARE_API_TOKEN: envVars.CLOUDFLARE_API_TOKEN } : {}),
    };

    const data: AdminSeedData = { tenantName, email, username, displayName, hashedPassword };
    const ok = await seedAdminToDb(dbName, data, wranglerEnv, false);
    if (!ok) return null;

    if (previewDbName) {
        const doPreview = args.yes || (await confirm("프리뷰 DB에도 관리자 계정을 생성하시겠습니까?", true));
        if (doPreview) {
            // 프리뷰 DB 에 스키마가 없으면 admin 시드가 'no such table' 로 실패한다.
            // 방어적으로 마이그레이션을 먼저 실행한다. drizzle.config.ts 가 D1 ID 를
            // 환경변수로 읽으므로 .env 의 ID 들을 모두 함께 전달해야 한다.
            const previewMigrateEnv = {
                ...wranglerEnv,
                CLOUDFLARE_D1_DATABASE_ID: envVars.CLOUDFLARE_D1_DATABASE_ID ?? "",
                CLOUDFLARE_D1_PREVIEW_DATABASE_ID: envVars.CLOUDFLARE_D1_PREVIEW_DATABASE_ID ?? "",
                CLOUDFLARE_IS_PREVIEW: "true",
            };
            console.log("  프리뷰 DB 스키마 확인 중 (db:migrate:preview)...");
            const previewMigrate = runCommand("bun", ["run", "db:migrate:preview"], {
                inherit: true,
                env: previewMigrateEnv,
            });
            if (!previewMigrate.success) {
                console.error(red("  db:migrate:preview 실패 — 프리뷰 admin 시드 건너뜀"));
            } else {
                await seedAdminToDb(previewDbName, data, wranglerEnv, true);
            }
        }
    }

    return { email, password, generated };
}

/**
 * .env 의 일반 KEY 와 wrangler.jsonc `vars` 블록을 동시에 갱신.
 * vars 키가 없으면 마지막 } 직전에 추가.
 */
function applyVar(envContent: string, wranglerContent: string, key: string, value: string): { env: string; wrangler: string } {
    // .env
    const envRe = new RegExp(`^${key}=.*$`, "m");
    if (envRe.test(envContent)) {
        envContent = envContent.replace(envRe, `${key}="${value}"`);
    } else {
        if (!envContent.endsWith("\n")) envContent += "\n";
        envContent += `${key}="${value}"\n`;
    }

    // wrangler.jsonc vars 블록
    const safeValue = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    const escKey = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const inVarsRe = new RegExp(`("${escKey}"\\s*:\\s*)"[^"]*"`);
    if (inVarsRe.test(wranglerContent)) {
        wranglerContent = wranglerContent.replace(inVarsRe, `$1"${safeValue}"`);
    } else {
        // vars 블록 안에 추가 — `"vars": {` 다음 줄에 삽입
        const insertRe = /("vars"\s*:\s*\{\s*)/;
        if (insertRe.test(wranglerContent)) {
            wranglerContent = wranglerContent.replace(insertRe, `$1\n        "${key}": "${safeValue}",`);
        }
    }

    return { env: envContent, wrangler: wranglerContent };
}

async function step5c_smtpConfig(args: Args) {
    console.log(`\n${cyan("─── 5c. SMTP 설정 ────────────────────────────────────────")}`);

    if (args.yes) {
        console.log("  (--yes 모드) SMTP 설정 건너뜀");
        return;
    }

    const doConfig = await confirm("SMTP 메일 발송을 설정하시겠습니까? (비밀번호 재설정 등에 사용)", false);
    if (!doConfig) {
        console.log("  SMTP 설정 건너뜀");
        return;
    }

    const current = loadEnvFile(ENV_FILE);
    const hostname = await ask("SMTP_HOSTNAME (예: smtp.gmail.com)", current.SMTP_HOSTNAME ?? "");
    if (!hostname) {
        console.log(yellow("  hostname 미입력 — SMTP 설정 취소"));
        return;
    }
    const portStr = await ask("SMTP_PORTNUMB (587/465/25)", current.SMTP_PORTNUMB ?? "587");
    const port = parseInt(portStr, 10);
    if (!Number.isFinite(port) || port <= 0) {
        console.log(yellow("  포트가 유효하지 않음 — SMTP 설정 취소"));
        return;
    }
    const username = await ask("SMTP_USERNAME", current.SMTP_USERNAME ?? "");
    const sendmail = await ask("SMTP_SENDMAIL (발신자 이메일)", current.SMTP_SENDMAIL ?? username);
    const encType = await ask("SMTP_ENC_TYPE (starttls / tls / none)", current.SMTP_ENC_TYPE ?? "starttls");
    const password = await ask("SMTP_PASSWORD (입력값은 wrangler secret 으로 배포되며 .env/wrangler.jsonc 에 저장되지 않습니다)", "");

    // .env + wrangler.jsonc 업데이트
    let envContent = readFile(ENV_FILE);
    let wranglerContent = readFile(WRANGLER_JSONC);
    const apply = (k: string, v: string) => {
        const r = applyVar(envContent, wranglerContent, k, v);
        envContent = r.env;
        wranglerContent = r.wrangler;
    };
    apply("SMTP_HOSTNAME", hostname);
    apply("SMTP_PORTNUMB", String(port));
    apply("SMTP_USERNAME", username);
    apply("SMTP_SENDMAIL", sendmail);
    apply("SMTP_ENC_TYPE", encType);
    writeFile(ENV_FILE, envContent);
    writeFile(WRANGLER_JSONC, wranglerContent);
    console.log(green("  ✓ .env / wrangler.jsonc 업데이트 완료"));

    // .env 에 SMTP_PASSWORD 저장 (로컬 개발용). 운영 secret 은 사용자가 수동 배포.
    let envAfter = readFile(ENV_FILE);
    if (/^SMTP_PASSWORD=.*$/m.test(envAfter)) {
        envAfter = envAfter.replace(/^SMTP_PASSWORD=.*$/m, `SMTP_PASSWORD="${password}"`);
    } else {
        if (!envAfter.endsWith("\n")) envAfter += "\n";
        envAfter += `SMTP_PASSWORD="${password}"\n`;
    }
    writeFile(ENV_FILE, envAfter);

    if (password) {
        console.log(green("  ✓ SMTP_PASSWORD .env 저장 (로컬 개발용)"));
    }
    console.log(yellow(`  ⚠ 운영 배포 전 ${cyan("wrangler secret put SMTP_PASSWORD")} 명령으로 직접 등록하세요.`));
}

async function step6_signingKey(args: Args) {
    console.log(`\n${cyan("─── 6. 시크릿 설정 ────────────────────────────────────────")}`);

    let signingKey = args.signingKey;

    if (!signingKey) {
        console.log(`  ${cyan("IDP_SIGNING_KEY_SECRET")} 을 설정합니다.`);
        const input = await ask("직접 입력하거나 엔터를 누르면 자동 생성합니다 (openssl rand -base64 32)", "");

        if (input === "") {
            const result = runCommand("openssl", ["rand", "-base64", "32"]);
            if (!result.success) {
                console.error(red("  openssl 실행 실패. 시크릿을 직접 설정하세요."));
                return;
            }
            signingKey = result.stdout.trim();
            console.log(green(`  ✓ 자동 생성된 시크릿: ${signingKey}`));
        } else {
            signingKey = input;
        }
    }

    // Update .env
    let envContent = readFile(ENV_FILE);
    envContent = envContent.replace(/^IDP_SIGNING_KEY_SECRET=".*"$/m, `IDP_SIGNING_KEY_SECRET="${signingKey}"`);
    writeFile(ENV_FILE, envContent);
    console.log(green("  ✓ IDP_SIGNING_KEY_SECRET .env 업데이트 완료"));
}

function printComplete(adminResult?: { email: string; password: string; generated: boolean } | null) {
    console.log(`\n${green("✓ 셋업 완료!")}`);

    if (adminResult) {
        console.log(`
${cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")}
  초기 관리자 계정 정보${adminResult.generated ? " (자동 생성됨)" : ""}

  이메일  : ${yellow(adminResult.email)}
  비밀번호: ${yellow(adminResult.password)}
${
    adminResult.generated
        ? `
  ${red("⚠️  이 비밀번호는 다시 표시되지 않습니다. 반드시 저장하세요.")}`
        : ""
}
${cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")}
`);
    }

    console.log(`로컬 개발 서버 시작:
  ${cyan("bun run dev")}

프로덕션 배포:
  ${cyan("bun run deploy")}
  (배포 전 시크릿을 직접 설정하세요:
    ${yellow("wrangler secret put IDP_SIGNING_KEY_SECRET")}
    ${yellow("wrangler secret put SMTP_PASSWORD")}  (SMTP 사용 시))
`);
}

// ─── Direct-connection path (postgres / mysql / sqlite) ────────────────────────

type DirectDialect = "postgres" | "mysql" | "sqlite";
const GEN_SCRIPT_BY_DIALECT: Record<DirectDialect, string> = {
    postgres: "db:generate:pg",
    mysql: "db:generate:mysql",
    sqlite: "db:generate:sqlite",
};
const MIGRATE_SCRIPT_BY_DIALECT: Record<DirectDialect, string> = {
    postgres: "db:migrate:pg",
    mysql: "db:migrate:mysql",
    sqlite: "db:migrate:sqlite",
};

/** 활성 방언 결정: --dialect > process.env.DB_DIALECT > .env DB_DIALECT > 프롬프트(기본 d1). */
async function resolveSetupDialect(args: Args): Promise<string> {
    const explicit = (args.dialect ?? process.env.DB_DIALECT ?? "").toLowerCase();
    if (explicit) return explicit;
    const fromEnvFile = (loadEnvFile(ENV_FILE).DB_DIALECT ?? "").toLowerCase();
    if (fromEnvFile) return fromEnvFile;
    if (args.yes) return "d1";
    const choice = await select("사용할 DB 방언을 선택하세요", ["d1 (Cloudflare D1 — 기본)", "postgres", "mysql", "sqlite (libSQL/Turso)"]);
    return ["d1", "postgres", "mysql", "sqlite"][choice - 1];
}

/** wrangler.jsonc 에 Hyperdrive 바인딩(HYPERDRIVE) 을 설정/갱신한다. */
function setHyperdriveBinding(id: string) {
    if (!fs.existsSync(WRANGLER_JSONC)) return;
    let content = readFile(WRANGLER_JSONC);
    const activeArr = content.match(/(?<!\/\/\s*)"hyperdrive"\s*:\s*\[[\s\S]*?\]/);
    if (activeArr && /"binding"\s*:\s*"HYPERDRIVE"/.test(activeArr[0])) {
        // 기존 활성 바인딩 — id 만 교체
        content = content.replace(/("binding"\s*:\s*"HYPERDRIVE"[\s\S]*?"id"\s*:\s*)"[^"]*"/, `$1"${id}"`);
    } else {
        // 마지막 } 앞에 새 배열 추가
        content = content.replace(/\}\s*$/, `    "hyperdrive": [\n        {\n            "binding": "HYPERDRIVE",\n            "id": "${id}",\n        },\n    ],\n}\n`);
    }
    writeFile(WRANGLER_JSONC, content);
}

async function step3_directDbSetup(args: Args, dialect: DirectDialect): Promise<{ databaseUrl: string }> {
    console.log(`\n${cyan(`─── 3. ${dialect} 연결 설정 ───────────────────────────────`)}`);
    const env = loadEnvFile(ENV_FILE);

    let databaseUrl = args.databaseUrl ?? env.DATABASE_URL ?? "";
    if (databaseUrl && !args.databaseUrl) {
        const masked = databaseUrl.replace(/:\/\/([^:]+):[^@]*@/, "://$1:***@");
        const keep = args.yes || (await confirm(`기존 DATABASE_URL 을 사용하시겠습니까? (${masked})`, true));
        if (!keep) databaseUrl = "";
    }
    if (!databaseUrl) {
        const example = dialect === "sqlite" ? "file:./lodestar.db" : dialect === "postgres" ? "postgres://user:pass@host:5432/db" : "mysql://user:pass@host:3306/db";
        databaseUrl = await ask(`DATABASE_URL 입력 (예: ${example})`);
        if (!databaseUrl) {
            console.error(red("  DATABASE_URL 이 필요합니다. 종료합니다."));
            closeRL();
            process.exit(1);
        }
    }

    // Hyperdrive (postgres/mysql 만 — Workers 배포용)
    let hyperdriveId = args.hyperdriveId ?? "";
    if (dialect !== "sqlite") {
        if (!hyperdriveId && !args.yes) {
            const wantHd = await confirm("Cloudflare Workers 배포용 Hyperdrive 바인딩을 설정하시겠습니까?", true);
            if (wantHd) hyperdriveId = await ask("Hyperdrive 구성 ID (엔터: 건너뜀)", "");
        }
        if (hyperdriveId) {
            setHyperdriveBinding(hyperdriveId);
            console.log(green(`  ✓ wrangler.jsonc HYPERDRIVE 바인딩 설정 (id: ${hyperdriveId})`));
        }
    }

    // .env: DB_DIALECT + DATABASE_URL, wrangler vars: DB_DIALECT (DATABASE_URL 은 민감정보라 .env 전용)
    let envContent = readFile(ENV_FILE);
    let wranglerContent = readFile(WRANGLER_JSONC);
    ({ env: envContent, wrangler: wranglerContent } = applyVar(envContent, wranglerContent, "DB_DIALECT", dialect));
    const dbUrlRe = /^DATABASE_URL=.*$/m;
    if (dbUrlRe.test(envContent)) envContent = envContent.replace(dbUrlRe, `DATABASE_URL="${databaseUrl}"`);
    else envContent += `${envContent.endsWith("\n") ? "" : "\n"}DATABASE_URL="${databaseUrl}"\n`;
    writeFile(ENV_FILE, envContent);
    writeFile(WRANGLER_JSONC, wranglerContent);
    console.log(green("  ✓ .env / wrangler.jsonc 업데이트 (DB_DIALECT, DATABASE_URL)"));

    return { databaseUrl };
}

async function step5_directMigrate(args: Args, dialect: DirectDialect, databaseUrl: string) {
    console.log(`\n${cyan("─── 5. 마이그레이션 ────────────────────────────────────────")}`);
    let doMigrate = args.migrate;
    if (doMigrate === undefined) doMigrate = await confirm("스키마 마이그레이션을 지금 진행하시겠습니까?", true);
    if (!doMigrate) {
        console.log("  마이그레이션 건너뜀");
        return;
    }
    const migrateEnv = { DB_DIALECT: dialect, DATABASE_URL: databaseUrl };
    console.log(`\n  bun run ${GEN_SCRIPT_BY_DIALECT[dialect]} 실행 중...`);
    const gen = runCommand("bun", ["run", GEN_SCRIPT_BY_DIALECT[dialect]], { inherit: true, env: migrateEnv });
    if (!gen.success) {
        console.error(red("  마이그레이션 생성 실패"));
        closeRL();
        process.exit(1);
    }
    console.log(`  bun run ${MIGRATE_SCRIPT_BY_DIALECT[dialect]} 실행 중...`);
    const mig = runCommand("bun", ["run", MIGRATE_SCRIPT_BY_DIALECT[dialect]], { inherit: true, env: migrateEnv });
    if (!mig.success) {
        console.error(red("  마이그레이션 적용 실패"));
        closeRL();
        process.exit(1);
    }
    console.log(green("  ✓ 마이그레이션 완료"));
}

async function step5b_directBootstrap(args: Args, dialect: DirectDialect, databaseUrl: string): Promise<{ email: string; password: string; generated: boolean } | null> {
    console.log(`\n${cyan("─── 5b. 초기 관리자 계정 생성 ─────────────────────────────────")}`);
    const tenantName = args.tenantName ?? (await ask("조직(테넌트) 이름", "My Organization"));
    const username = args.adminUsername ?? (await ask("초기 관리자 아이디", "admin"));
    const email = args.adminEmail ?? (await ask("초기 관리자 이메일", "admin@example.com"));
    const displayName = args.adminName ?? (await ask("초기 관리자 표시 이름", "관리자"));
    const issuerUrl = args.issuerUrl ?? (await ask("IDP Issuer URL", "http://localhost:5173"));

    let password: string;
    let generated = false;
    if (args.adminPassword) {
        password = args.adminPassword;
    } else {
        const input = await ask("초기 관리자 비밀번호 (엔터: 자동 생성)", "");
        if (input === "") {
            password = generateRandomPassword(20);
            generated = true;
        } else {
            password = input;
        }
    }

    if (fs.existsSync(ENV_FILE)) {
        let envContent = readFile(ENV_FILE);
        envContent = envContent.replace(/^IDP_DEFAULT_TENANT_NAME=".*"$/m, `IDP_DEFAULT_TENANT_NAME="${tenantName}"`);
        envContent = envContent.replace(/^IDP_ISSUER_URL=".*"$/m, `IDP_ISSUER_URL="${issuerUrl}"`);
        writeFile(ENV_FILE, envContent);
        console.log(green("  ✓ .env 업데이트 완료 (테넌트 이름, Issuer URL)"));
    }

    // 검증된 scripts/seed.ts 재사용 — 비밀번호는 env 로 전달, SEED_RESET=0 으로 프롬프트 없이 실행.
    console.log("  scripts/seed.ts 로 관리자 시드 중...");
    const seed = runCommand("bun", ["scripts/seed.ts"], {
        inherit: true,
        env: {
            DB_DIALECT: dialect,
            DATABASE_URL: databaseUrl,
            SEED_RESET: "0",
            IDP_BOOTSTRAP_ADMIN_USERNAME: username,
            IDP_BOOTSTRAP_ADMIN_EMAIL: email,
            IDP_BOOTSTRAP_ADMIN_PASSWORD: password,
            IDP_BOOTSTRAP_ADMIN_NAME: displayName,
        },
    });
    if (!seed.success) {
        console.error(red("  관리자 시드 실패"));
        return null;
    }
    return { email, password, generated };
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
    const argv = process.argv.slice(2);
    const args = parseArgs(argv);

    if (args.help) {
        printHelp();
        process.exit(0);
    }

    console.log(`${C.bold}${cyan("=== Lodestar 프로젝트 셋업 ===")}${C.reset}`);

    // wrangler.jsonc / .env 생성 (방언 무관)
    await step1_createWranglerJsonc(args);
    await step2_createEnv(args);

    // 활성 DB 방언 결정
    const dialect = await resolveSetupDialect(args);
    console.log(`\n${cyan(`DB 방언: ${dialect}`)}`);

    let adminResult: { email: string; password: string; generated: boolean } | null = null;

    if (dialect === "d1") {
        // Cloudflare D1 경로
        const accountId = await step0_wranglerLogin(args);
        const { dbId, dbName, previewDbId, previewDbName } = await step3_dbSetup(args);
        await step4_updateFiles(dbId, previewDbId, accountId, dbName);
        await step4b_r2Setup(args);
        await step5_migrate(args, previewDbId !== null, dbName, previewDbName);
        adminResult = await step5b_bootstrapConfig(args, dbName, previewDbName);
    } else if (dialect === "postgres" || dialect === "mysql" || dialect === "sqlite") {
        // 직결(DATABASE_URL) 경로 — postgres / mysql / sqlite
        const { databaseUrl } = await step3_directDbSetup(args, dialect);
        await step4b_r2Setup(args);
        await step5_directMigrate(args, dialect, databaseUrl);
        adminResult = await step5b_directBootstrap(args, dialect, databaseUrl);
    } else {
        console.error(red(`알 수 없는 DB_DIALECT: ${dialect} (d1 | postgres | mysql | sqlite)`));
        closeRL();
        process.exit(1);
    }

    await step5c_smtpConfig(args);

    // step5b/5c 가 .env 에 추가한 값들 (테넌트 이름, Issuer URL, SMTP_*) 을 wrangler.jsonc 와 다시 동기화.
    syncWranglerVarsFromEnv();

    // Step 6: Signing key
    await step6_signingKey(args);

    // Done
    closeRL();
    printComplete(adminResult);
}

main().catch((err) => {
    console.error(red(`\n오류: ${err instanceof Error ? err.message : String(err)}`));
    closeRL();
    process.exit(1);
});
