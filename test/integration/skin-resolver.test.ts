import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import { invalidateSkinCache, parseSkinHint, resolveSkinByHint, resolveSkinHtml, TENANT_DEFAULT_CLIENT_REF, TENANT_DEFAULT_CLIENT_TYPE, type SkinType } from "../../src/lib/server/skin/resolver";
import { clientSkins } from "../../src/lib/server/db/schema";
import { openMemoryDb, seedTenantAndSigningKey, TEST_ISSUER_URL, type MemoryDb } from "./harness";
import type { Tenant } from "../../src/lib/server/db/schema";

// 커스텀 스킨 해석기. 관리자가 등록한 **외부 호스트**의 HTML 을 서버가 가져와 로그인 화면으로
// 내보내는 경로라, 이 파일이 검증하는 것은 사실상 SSRF 게이트와 응답 검증이다.
//
// `sanitizeSkinHtml` 은 Cloudflare/Bun 의 HTMLRewriter 전역을 쓰는데 vitest 는 node 에서 돌아
// 그 전역이 없다. 여기서는 sanitize 를 **표식만 남기는 스텁**으로 바꿔, 해석기가 "가져온 HTML 을
// 그대로 내보내지 않고 반드시 sanitize 를 통과시킨다"는 성질만 확인한다. sanitize 자체의 동작은
// test/workers/skin-sanitize.test.ts 가 실제 HTMLRewriter 로 검증한다.

const SANITIZE_MARK = "SANITIZED:";

let mem: MemoryDb;
let tenant: Tenant;
let fetchCalls: Array<{ url: string; init: RequestInit | undefined }>;
let nextResponse: () => Response;
const originalFetch = globalThis.fetch;
const originalRewriter = (globalThis as Record<string, unknown>).HTMLRewriter;

/** sanitizeSkinHtml 이 기대하는 최소 인터페이스만 흉내내는 스텁. 입력에 표식을 붙여 돌려준다. */
class MarkingRewriterStub {
    on() {
        return this;
    }
    transform(response: Response) {
        return { text: async () => `${SANITIZE_MARK}${await response.text()}` } as unknown as Response;
    }
}

function htmlResponse(body: string, extraHeaders: Record<string, string> = {}): Response {
    return new Response(body, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8", ...extraHeaders } });
}

beforeEach(async () => {
    mem = await openMemoryDb();
    tenant = await seedTenantAndSigningKey(mem);
    fetchCalls = [];
    nextResponse = () => htmlResponse("<p>skin</p>");
    globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
        fetchCalls.push({ url: String(url), init });
        return Promise.resolve(nextResponse());
    }) as typeof fetch;
    (globalThis as Record<string, unknown>).HTMLRewriter = MarkingRewriterStub;
});

afterEach(() => {
    globalThis.fetch = originalFetch;
    (globalThis as Record<string, unknown>).HTMLRewriter = originalRewriter;
    mem.close();
});

const CLIENT_REF = "11111111-1111-4111-8111-111111111111";

async function seedSkin(overrides: Partial<typeof clientSkins.$inferInsert> = {}) {
    await mem.db.insert(clientSkins).values({
        tenantId: tenant.id,
        clientType: "oidc",
        clientRefId: CLIENT_REF,
        skinType: "login",
        fetchUrl: "https://skin.test.example/login.html",
        cacheTtlSeconds: 3600,
        enabled: true,
        ...overrides,
    });
}

/** 기본 인자로 해석기를 호출한다. platform 이 없으면 캐시 스토어도 없다(원본 fetch 경로). */
function resolve(args: Partial<{ tenantId: string; clientType: "oidc" | "saml" | null; clientRefId: string | null; skinType: SkinType; platform: App.Platform }> = {}) {
    return resolveSkinHtml(
        mem.db,
        args.platform,
        args.tenantId ?? tenant.id,
        args.clientType === null ? null : (args.clientType ?? "oidc"),
        args.clientRefId === null ? null : (args.clientRefId ?? CLIENT_REF),
        args.skinType ?? "login",
    );
}

describe("resolveSkinHtml: DB 스코프", () => {
    it("설정이 없으면 null 이고 외부 호출도 하지 않는다", async () => {
        expect(await resolve()).toBeNull();
        expect(fetchCalls).toHaveLength(0);
    });

    it("가져온 HTML 을 sanitize 를 통과시킨 뒤 내보낸다", async () => {
        await seedSkin();
        nextResponse = () => htmlResponse("<p>skin</p>");

        expect(await resolve()).toBe(`${SANITIZE_MARK}<p>skin</p>`);
        expect(fetchCalls).toHaveLength(1);
    });

    it("enabled=false 인 설정은 무시한다", async () => {
        await seedSkin({ enabled: false });
        expect(await resolve()).toBeNull();
        expect(fetchCalls).toHaveLength(0);
    });

    it("다른 테넌트의 설정은 보이지 않는다", async () => {
        await seedSkin();
        expect(await resolve({ tenantId: "00000000-0000-4000-8000-000000000000" })).toBeNull();
        expect(fetchCalls).toHaveLength(0);
    });

    it("clientType 이 다르면 매칭되지 않는다", async () => {
        await seedSkin();
        expect(await resolve({ clientType: "saml" })).toBeNull();
    });

    it("clientRefId 가 다르면 매칭되지 않는다", async () => {
        await seedSkin();
        expect(await resolve({ clientRefId: "22222222-2222-4222-8222-222222222222" })).toBeNull();
    });

    it("skinType 이 다르면 매칭되지 않는다 (페이지별로 독립)", async () => {
        await seedSkin({ skinType: "login" });
        expect(await resolve({ skinType: "signup" })).toBeNull();
    });

    it("verify_email 스킨도 해석한다 (이메일 인증 화면)", async () => {
        await seedSkin({ skinType: "verify_email", fetchUrl: "https://skin.test.example/verify.html" });

        expect(await resolve({ skinType: "verify_email" })).toBe(`${SANITIZE_MARK}<p>skin</p>`);
        expect(fetchCalls[0].url).toBe("https://skin.test.example/verify.html");
        // login 으로는 매칭되지 않는다.
        expect(await resolve({ skinType: "login" })).toBeNull();
    });
});

describe("resolveSkinHtml: fetch URL 게이트 (SSRF)", () => {
    // 리터럴 IP 는 assertResolvedHostAllowed 가 DNS 재해석 없이 통과시키므로,
    // 아래 목록은 전부 isFetchUrlAllowed 의 문자열 검사에서 걸러져야 한다.
    const blockedUrls = [
        ["http (https 아님)", "http://skin.test.example/login.html"],
        ["localhost", "https://localhost/login.html"],
        ["127.0.0.1", "https://127.0.0.1/login.html"],
        ["127.x 대역", "https://127.9.9.9/login.html"],
        ["0.0.0.0", "https://0.0.0.0/login.html"],
        ["0.x 대역", "https://0.1.2.3/login.html"],
        ["10.x 사설", "https://10.0.0.1/login.html"],
        ["192.168.x 사설", "https://192.168.1.1/login.html"],
        ["172.16.x 사설", "https://172.16.0.1/login.html"],
        ["172.31.x 사설", "https://172.31.255.255/login.html"],
        ["169.254.x 링크로컬", "https://169.254.169.254/latest/meta-data/"],
        ["GCP 메타데이터", "https://metadata.google.internal/x"],
        ["Alibaba 메타데이터", "https://100.100.100.200/x"],
        ["EC2 instance-data", "https://instance-data.ec2.internal/x"],
        [".local", "https://printer.local/login.html"],
        [".internal", "https://svc.internal/login.html"],
        ["점 없는 단일 라벨", "https://intranet/login.html"],
        ["IPv6 리터럴", "https://[::1]/login.html"],
        ["URL 파싱 불가", "not-a-url"],
    ] as const;

    for (const [label, fetchUrl] of blockedUrls) {
        it(`${label} 은 거부하고 외부 호출도 하지 않는다`, async () => {
            await seedSkin({ fetchUrl });
            expect(await resolve()).toBeNull();
            expect(fetchCalls).toHaveLength(0);
        });
    }

    it("172.15.x / 172.32.x 는 사설 대역이 아니므로 통과시킨다 (경계 확인)", async () => {
        await seedSkin({ fetchUrl: "https://172.15.0.1/login.html" });
        expect(await resolve()).toBe(`${SANITIZE_MARK}<p>skin</p>`);
        expect(fetchCalls).toHaveLength(1);
    });
});

describe("resolveSkinHtml: 응답 검증", () => {
    it("3xx 는 거부한다 (Location 으로 secret 이 새는 것을 막는다)", async () => {
        await seedSkin();
        nextResponse = () => new Response(null, { status: 302, headers: { Location: "https://evil.example/" } });
        expect(await resolve()).toBeNull();
    });

    it("2xx 가 아니면 거부한다", async () => {
        await seedSkin();
        nextResponse = () => new Response("nope", { status: 404, headers: { "Content-Type": "text/html" } });
        expect(await resolve()).toBeNull();
    });

    it("Content-Type 이 text/html 이 아니면 거부한다", async () => {
        await seedSkin();
        nextResponse = () => new Response(`{"a":1}`, { status: 200, headers: { "Content-Type": "application/json" } });
        expect(await resolve()).toBeNull();
    });

    it("Content-Length 가 한도를 넘으면 본문을 읽기 전에 거부한다", async () => {
        await seedSkin();
        nextResponse = () => htmlResponse("<p>small</p>", { "Content-Length": String(512 * 1024 + 1) });
        expect(await resolve()).toBeNull();
    });

    it("Content-Length 가 거짓이어도 본문 길이로 다시 막는다", async () => {
        await seedSkin();
        nextResponse = () => htmlResponse("x".repeat(512 * 1024 + 1), { "Content-Length": "10" });
        expect(await resolve()).toBeNull();
    });

    it("한도 이하 본문은 통과한다 (경계 확인)", async () => {
        await seedSkin();
        const body = "y".repeat(512 * 1024);
        nextResponse = () => htmlResponse(body);
        expect(await resolve()).toBe(`${SANITIZE_MARK}${body}`);
    });

    it("fetch 가 던지면 null 로 떨어진다 (로그인 화면은 기본 UI 로 폴백)", async () => {
        await seedSkin();
        globalThis.fetch = (() => Promise.reject(new Error("network down"))) as typeof fetch;
        expect(await resolve()).toBeNull();
    });
});

describe("resolveSkinHtml: 요청 형태", () => {
    it("Accept: text/html 과 redirect: manual 로 요청한다", async () => {
        await seedSkin();
        await resolve();

        const [call] = fetchCalls;
        expect(call.url).toBe("https://skin.test.example/login.html");
        expect((call.init?.headers as Record<string, string>).Accept).toBe("text/html");
        expect(call.init?.redirect).toBe("manual");
        expect(call.init?.signal).toBeDefined(); // 타임아웃 AbortController
    });

    it("fetchSecret 이 있으면 X-IDP-Token 헤더로 보낸다", async () => {
        await seedSkin({ fetchSecret: "s3cr3t-skin-token" });
        await resolve();

        expect((fetchCalls[0].init?.headers as Record<string, string>)["X-IDP-Token"]).toBe("s3cr3t-skin-token");
    });

    it("fetchSecret 이 없으면 X-IDP-Token 헤더를 보내지 않는다", async () => {
        await seedSkin();
        await resolve();

        expect((fetchCalls[0].init?.headers as Record<string, string>)["X-IDP-Token"]).toBeUndefined();
    });
});

// ── 캐시 ────────────────────────────────────────────────────────────────────────
// R2 바인딩이 없으면 캐시 스토어가 null 이라 매번 원본을 가져온다(위 테스트들이 그 경로).
// 여기서는 최소 R2 스텁을 넣어 캐시 경로를 확인한다.
describe("resolveSkinHtml: 캐시", () => {
    interface StubObject {
        body: string;
        fetchedAt: string;
    }

    function makeR2Platform() {
        const store = new Map<string, StubObject>();
        const deleted: string[] = [];
        const bucket = {
            get: async (key: string) => {
                const hit = store.get(key);
                return hit ? { text: async () => hit.body, customMetadata: { fetchedAt: hit.fetchedAt } } : null;
            },
            put: async (key: string, value: string, opts: { customMetadata?: Record<string, string> }) => {
                store.set(key, { body: value, fetchedAt: opts.customMetadata?.fetchedAt ?? "0" });
            },
            delete: async (key: string) => {
                deleted.push(key);
                store.delete(key);
            },
        };
        return { platform: { env: { ...mem.env, SKIN_CACHE: bucket } } as unknown as App.Platform, store, deleted };
    }

    it("sanitize 된 결과만 캐시에 저장한다 (원본이 캐시에 남지 않는다)", async () => {
        await seedSkin();
        const { platform, store } = makeR2Platform();

        await resolve({ platform });

        const cached = [...store.values()];
        expect(cached).toHaveLength(1);
        expect(cached[0].body).toBe(`${SANITIZE_MARK}<p>skin</p>`);
        expect(cached[0].body).not.toBe("<p>skin</p>");
    });

    it("TTL 안에서는 캐시를 쓰고 외부 호출을 다시 하지 않는다", async () => {
        await seedSkin();
        const { platform } = makeR2Platform();

        const first = await resolve({ platform });
        const second = await resolve({ platform });

        expect(fetchCalls).toHaveLength(1);
        // 캐시 히트 경로도 읽는 시점에 한 번 더 sanitize 한다(아래 legacy 캐시 테스트 참고).
        // 스텁이 표식을 덧붙이므로 두 번째 결과에는 표식이 하나 더 붙는다.
        expect(first).toBe(`${SANITIZE_MARK}<p>skin</p>`);
        expect(second).toBe(`${SANITIZE_MARK}${first}`);
    });

    it("TTL 이 지나면 다시 가져온다", async () => {
        await seedSkin({ cacheTtlSeconds: 0 });
        const { platform } = makeR2Platform();

        await resolve({ platform });
        await resolve({ platform });

        expect(fetchCalls).toHaveLength(2);
    });

    it("캐시에서 읽은 값도 다시 sanitize 한다 (sanitize 도입 전 캐시 대비)", async () => {
        await seedSkin();
        const { platform, store } = makeR2Platform();
        await resolve({ platform });
        // sanitize 되지 않은 legacy 캐시를 흉내낸다.
        const key = [...store.keys()][0];
        store.set(key, { body: "<script>legacy</script>", fetchedAt: String(Date.now()) });

        expect(await resolve({ platform })).toBe(`${SANITIZE_MARK}<script>legacy</script>`);
    });

    it("invalidateSkinCache 는 해당 스킨의 캐시 키만 지운다", async () => {
        await seedSkin();
        const { platform, deleted, store } = makeR2Platform();
        await resolve({ platform });
        expect(store.size).toBe(1);

        await invalidateSkinCache(platform, tenant.id, "oidc", CLIENT_REF, "login");

        expect(deleted).toHaveLength(1);
        expect(store.size).toBe(0);
    });

    it("캐시 키에 clientRefId 원문이 들어가지 않는다 (해시로 감춘다)", async () => {
        await seedSkin();
        const { platform, store } = makeR2Platform();
        await resolve({ platform });

        const key = [...store.keys()][0];
        expect(key).toContain(`skins/${tenant.id}/oidc/`);
        expect(key).toContain("/login");
        expect(key).not.toContain(CLIENT_REF);
    });

    it("캐시 스토어가 없으면 매번 원본을 가져온다", async () => {
        await seedSkin();
        await resolve();
        await resolve();
        expect(fetchCalls).toHaveLength(2);
    });
});

describe("resolveSkinHtml: 기본 인자", () => {
    it("skinType 을 생략하면 login 을 본다", async () => {
        await seedSkin({ skinType: "login" });
        const html = await resolveSkinHtml(mem.db, undefined, tenant.id, "oidc", CLIENT_REF);
        expect(html).toBe(`${SANITIZE_MARK}<p>skin</p>`);
    });

    it("테스트 격리 확인: 시드한 행이 실제로 이 테넌트에 있다", async () => {
        await seedSkin();
        const rows = await mem.db.select().from(clientSkins).where(eq(clientSkins.tenantId, tenant.id));
        expect(rows).toHaveLength(1);
        expect(rows[0].fetchUrl).toBe("https://skin.test.example/login.html");
        expect(TEST_ISSUER_URL).toContain("https://");
    });
});

// 3-A: 클라이언트가 특정되지 않는 흐름(초대 수락·이메일 변경 확인)과 전용 스킨이 없는
// 클라이언트를 위해 테넌트 단위 기본 스킨 슬롯을 둔다. clientType/skin_type 은 드리즐의 TS 전용
// enum(컬럼은 text)이라 값을 늘려도 마이그레이션이 없고, 기존 유니크 인덱스가 중복을 막는다.
describe("resolveSkinHtml: 테넌트 기본 스킨 폴백", () => {
    async function seedTenantDefault(overrides: Partial<typeof clientSkins.$inferInsert> = {}) {
        await mem.db.insert(clientSkins).values({
            tenantId: tenant.id,
            clientType: TENANT_DEFAULT_CLIENT_TYPE,
            clientRefId: TENANT_DEFAULT_CLIENT_REF,
            skinType: "login",
            fetchUrl: "https://skin.test.example/default.html",
            cacheTtlSeconds: 3600,
            enabled: true,
            ...overrides,
        });
    }

    it("전용 스킨이 없으면 테넌트 기본 스킨을 쓴다", async () => {
        await seedTenantDefault();

        expect(await resolve()).toBe(`${SANITIZE_MARK}<p>skin</p>`);
        expect(fetchCalls[0].url).toBe("https://skin.test.example/default.html");
    });

    it("전용 스킨이 있으면 그것이 기본 스킨보다 우선한다", async () => {
        await seedTenantDefault();
        await seedSkin({ fetchUrl: "https://skin.test.example/own.html" });

        await resolve();
        expect(fetchCalls[0].url).toBe("https://skin.test.example/own.html");
    });

    it("클라이언트 컨텍스트가 없어도(null) 기본 스킨을 쓴다", async () => {
        await seedTenantDefault({ skinType: "accept_invite" });

        expect(await resolve({ clientType: null, clientRefId: null, skinType: "accept_invite" })).toBe(`${SANITIZE_MARK}<p>skin</p>`);
    });

    it("기본 스킨이 비활성이면 폴백하지 않는다", async () => {
        await seedTenantDefault({ enabled: false });

        expect(await resolve()).toBeNull();
        expect(fetchCalls).toHaveLength(0);
    });

    it("스킨 타입이 다른 기본 스킨으로는 폴백하지 않는다", async () => {
        await seedTenantDefault({ skinType: "signup" });

        expect(await resolve({ skinType: "login" })).toBeNull();
    });

    it("다른 테넌트의 기본 스킨은 보이지 않는다", async () => {
        await seedTenantDefault();

        expect(await resolve({ tenantId: "00000000-0000-4000-8000-000000000000" })).toBeNull();
        expect(fetchCalls).toHaveLength(0);
    });

    it("기본 스킨으로 폴백한 여러 클라이언트가 캐시를 공유한다 (키는 매칭된 행 기준)", async () => {
        await seedTenantDefault();
        const store = new Map<string, { body: string; fetchedAt: string }>();
        const bucket = {
            get: async (key: string) => {
                const hit = store.get(key);
                return hit ? { text: async () => hit.body, customMetadata: { fetchedAt: hit.fetchedAt } } : null;
            },
            put: async (key: string, value: string, opts: { customMetadata?: Record<string, string> }) => {
                store.set(key, { body: value, fetchedAt: opts.customMetadata?.fetchedAt ?? "0" });
            },
            delete: async (key: string) => void store.delete(key),
        };
        const platform = { env: { ...mem.env, SKIN_CACHE: bucket } } as unknown as App.Platform;

        await resolve({ platform });
        await resolve({ platform, clientRefId: "99999999-9999-4999-8999-999999999999" });

        expect(store.size).toBe(1); // 클라이언트별로 따로 캐시되지 않는다
        expect(fetchCalls).toHaveLength(1); // 두 번째 클라이언트는 캐시 히트
    });
});

describe("parseSkinHint / resolveSkinByHint", () => {
    it("oidc/saml 힌트를 분해한다", () => {
        expect(parseSkinHint("oidc:abc")).toEqual({ clientType: "oidc", clientRefId: "abc" });
        expect(parseSkinHint("saml:sp-1")).toEqual({ clientType: "saml", clientRefId: "sp-1" });
    });

    it("형식이 어긋나면 둘 다 null 이라 기본 스킨으로 폴백된다", () => {
        for (const bad of [null, undefined, "", "oidc", ":abc", "ldap:abc", "oidc:"]) {
            expect(parseSkinHint(bad)).toEqual({ clientType: null, clientRefId: null });
        }
    });

    it("힌트가 없으면 테넌트 기본 스킨을 해석한다", async () => {
        await mem.db.insert(clientSkins).values({
            tenantId: tenant.id,
            clientType: TENANT_DEFAULT_CLIENT_TYPE,
            clientRefId: TENANT_DEFAULT_CLIENT_REF,
            skinType: "logout",
            fetchUrl: "https://skin.test.example/logout.html",
        });

        expect(await resolveSkinByHint(mem.db, undefined, tenant.id, null, "logout")).toBe(`${SANITIZE_MARK}<p>skin</p>`);
    });
});
