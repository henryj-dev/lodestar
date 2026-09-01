/**
 * admin 정형 CRUD 라우트(teams/parts/positions/departments)용 zod 폼 스키마.
 *
 * 런타임 폼 검증 표준화 전용 — DB 스키마와는 무관하다.
 * 공통 필드 규칙:
 *   - 필수 텍스트(name): trim 후 빈값이면 실패.
 *   - 선택 텍스트(code/description/FK id): trim 후 빈값이면 null.
 *   - status: "active" | "inactive" (기본 active).
 *   - 정수(level): coerce 후 int. 실패 시 에러.
 *   - displayOrder: coerce 후 int, 실패/빈값이면 0 (기존 isNaN→0 동작 보존).
 */
import { z } from "zod";

/**
 * 서비스 role / entitlement 의 `key` 형식.
 *
 * 클라이언트 상세와 SP 상세 두 화면이 같은 규칙을 쓴다 — 예전에는 두 파일에 같은 정규식이
 * 복제돼 있었고, entitlement 가 추가되면서 네 곳이 될 참이라 여기로 올렸다.
 *
 * 점·밑줄을 허용하므로 `site.read` · `plan.approve_own` 같은 네임스페이스 키가 통과한다.
 * 이 값이 OIDC 클레임(`roles` / `entitlements`)에 그대로 실리므로 형식을 좁히면 RP 가 깨진다.
 */
export const SERVICE_KEY_RE = /^[A-Za-z0-9_.-]{1,64}$/;

/**
 * entitlement key 정규화 — 소문자로 낮춘다.
 *
 * 유니크 인덱스에 collation 을 지정하지 않아 방언마다 대소문자 취급이 다르다: MySQL 기본
 * collation 은 대소문자를 구분하지 않아 `Site.Read` 가 `site.read` 와 충돌(409)하지만,
 * PostgreSQL·SQLite 는 서로 다른 행으로 받아들이고 **둘 다 클레임 배열에 실린다.**
 * 인가에 쓰이는 값이 방언에 따라 달라지면 안 되므로 입력 시점에 하나로 모은다.
 * (role key 는 기존 데이터가 있을 수 있어 건드리지 않는다 — 클레임 의미가 이미 표시용이다.)
 */
export function normalizeEntitlementKey(raw: string): string {
    return raw.trim().toLowerCase();
}

/**
 * SAML SP 의 `allowedAttributes` 에 넣을 수 있는 속성 키 화이트리스트.
 *
 * **SSO 라우트가 실제로 발행할 수 있는 속성의 상위집합이어야 한다.** `saml/sso` 는 모든 속성을
 * `allowedSet.has(key)` 로 게이트하는데, 그 allowedSet 은 이 목록을 통과한 값만 담긴다. 여기에
 * 키가 빠지면 관리자가 저장해도 조용히 버려지고 → SP 는 그 속성을 영원히 받지 못한다.
 * 실제로 `Entitlements` 가 이 목록에서 누락돼, 발행 로직·정의 UI·안내 문구가 모두 있는데도
 * 속성이 나갈 수 없는 상태였다(무동작). 발행 경로에 속성을 추가하면 여기도 같이 늘려야 한다.
 *
 * 라우트 파일이 아니라 이 모듈에 두는 이유: `+page.server.ts` 는 SvelteKit 이 허용하는 export
 * 만 내보낼 수 있어 테스트가 직접 import 할 수 없다. 위 불변식을 테스트로 고정하려면 공유
 * 모듈이어야 한다(`SERVICE_KEY_RE` 를 여기로 올린 것과 같은 이유).
 */
export const SAML_ATTRIBUTE_KEYS = [
    "email",
    "username",
    "displayName",
    "givenName",
    "familyName",
    "surName",
    "phoneNumber",
    "department",
    "team",
    "jobTitle",
    "position",
    "Role",
    "RoleLabel",
    "Entitlements",
] as const;

export type SamlAttributeKey = (typeof SAML_ATTRIBUTE_KEYS)[number];

/** 필수 텍스트: trim 후 최소 1자. 값 미존재(undefined)/빈값 모두 같은 메시지. */
export const requiredText = (message: string) => z.string(message).trim().min(1, message);

/** 선택 텍스트: 없거나 공백이면 null, 아니면 trim 값. */
export const optionalText = z
    .string()
    .optional()
    .transform((v) => {
        const trimmed = (v ?? "").trim();
        return trimmed.length > 0 ? trimmed : null;
    });

/** status enum (기본 active). */
export const statusField = z.enum(["active", "inactive"]).default("active");

/**
 * 정수 필드(level): 유효하지 않으면 실패.
 * 빈 문자열/공백은 undefined 로 정규화해 누락과 동일하게 거부한다 —
 * `z.coerce.number("")` 가 0 으로 조용히 통과하던 비일관을 막는다.
 */
export const intField = (message: string) => z.preprocess((v) => (typeof v === "string" && v.trim() === "" ? undefined : v), z.coerce.number(message).int(message));

/** displayOrder: 유효하지 않거나 빈값이면 0 (기존 parseInt isNaN→0 동작 보존). */
export const displayOrderField = z.coerce.number().int().catch(0);

// 폼 검증 메시지는 i18n 키(전체 경로)로 담는다. 실제 표시 시점(crud-factory)에서
// translate(locale, key) 로 해석된다 — 스키마는 로케일 비의존 정적 모듈이므로 키만 보관.

// ── teams ─────────────────────────────────────────────────────────────────
export const teamCreateSchema = z.object({
    name: requiredText("admin.errors.team_name_required"),
    code: optionalText,
    departmentId: optionalText,
    description: optionalText,
});
export const teamUpdateSchema = z.object({
    id: requiredText("admin.errors.invalid_request"),
    name: requiredText("admin.errors.invalid_request"),
    code: optionalText,
    departmentId: optionalText,
    description: optionalText,
    status: statusField,
});

// ── parts ─────────────────────────────────────────────────────────────────
export const partCreateSchema = z.object({
    name: requiredText("admin.errors.part_name_required"),
    code: optionalText,
    teamId: optionalText,
    description: optionalText,
});
export const partUpdateSchema = z.object({
    id: requiredText("admin.errors.invalid_request"),
    name: requiredText("admin.errors.invalid_request"),
    code: optionalText,
    teamId: optionalText,
    description: optionalText,
    status: statusField,
});

// ── positions ───────────────────────────────────────────────────────────────
export const positionCreateSchema = z.object({
    name: requiredText("admin.errors.position_name_required"),
    code: optionalText,
    level: intField("admin.errors.level_must_be_number"),
});
export const positionUpdateSchema = z.object({
    id: requiredText("admin.errors.invalid_request"),
    name: requiredText("admin.errors.invalid_request"),
    code: optionalText,
    level: intField("admin.errors.level_must_be_number"),
});

/**
 * 약관의 필수 여부. 체크박스는 미체크 시 필드가 **아예 오지 않으므로** 기본을 false 로 둔다.
 * 기존 admin 화면들이 쓰는 `=== "true"` 관례를 zod 로 흡수한 것이다.
 */
export const termsRequiredField = z.preprocess((v) => v === "true" || v === "on" || v === true, z.boolean()).default(false);

// ── terms documents ─────────────────────────────────────────────────────────
//
// `key` 는 개정을 가로지르는 안정 식별자다. 서비스 role/entitlement 와 같은 형식 규칙을 쓴다
// (점·밑줄 허용) — `service`, `privacy`, `marketing.email` 같은 값을 쓰게 된다.
//
// `version` 을 폼에서 받는다. 개정할 때 관리자가 올리는 값이고, (tenant, key, version, locale)
// 유니크가 중복을 막는다. 자동 증가로 두지 않은 이유는 "무엇을 개정으로 볼지" 가 운영 판단이기
// 때문이다 — 오탈자 수정에 version 을 올리면 전 사용자가 재동의해야 한다.
export const termsCreateSchema = z.object({
    key: z.string("admin.errors.terms_key_invalid").trim().regex(SERVICE_KEY_RE, "admin.errors.terms_key_invalid"),
    version: intField("admin.errors.terms_version_must_be_number"),
    locale: z.enum(["ko", "en"]).default("ko"),
    title: requiredText("admin.errors.terms_title_required"),
    body: requiredText("admin.errors.terms_body_required"),
    required: termsRequiredField,
    displayOrder: displayOrderField,
});
export const termsUpdateSchema = z.object({
    id: requiredText("admin.errors.invalid_request"),
    title: requiredText("admin.errors.terms_title_required"),
    body: requiredText("admin.errors.terms_body_required"),
    required: termsRequiredField,
    displayOrder: displayOrderField,
});

// ── departments ─────────────────────────────────────────────────────────────
export const departmentCreateSchema = z.object({
    name: requiredText("admin.errors.department_name_required"),
    code: optionalText,
    parentId: optionalText,
    description: optionalText,
    displayOrder: displayOrderField,
});
export const departmentUpdateSchema = z.object({
    id: requiredText("admin.errors.invalid_request"),
    name: requiredText("admin.errors.invalid_request"),
    code: optionalText,
    parentId: optionalText,
    description: optionalText,
    displayOrder: displayOrderField,
    status: statusField,
});
