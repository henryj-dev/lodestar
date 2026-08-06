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
