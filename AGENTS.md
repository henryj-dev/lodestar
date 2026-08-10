## Project Configuration

- **Language**: TypeScript
- **Package Manager**: bun
- **Add-ons**: prettier, eslint, tailwindcss, sveltekit-adapter, drizzle, mcp

## Project Rules

### Database migrations

- 스키마 변경 작업 시 **`bun run db:generate` 까지만** 수행한다. 생성된 마이그레이션 파일(`drizzle/*.sql`)과 메타 변경은 커밋/보고한다.
- **`drizzle-kit migrate`, `drizzle-kit push`, `bun run db:migrate`, `bun run db:migrate:preview`** 같은 실제 D1 적용 명령은 **절대 자동 실행하지 않는다.** 반드시 사용자에게 실행을 요청한다.
- 이유: 원격 D1 변경은 되돌리기 어렵고, 프리뷰/프로덕션 선택은 사용자 판단 영역.

---

You are able to use the Svelte MCP server, where you have access to comprehensive Svelte 5 and SvelteKit documentation. Here's how to use the available tools effectively:

## Available Svelte MCP Tools:

### 1. list-sections

Use this FIRST to discover all available documentation sections. Returns a structured list with titles, use_cases, and paths.
When asked about Svelte or SvelteKit topics, ALWAYS use this tool at the start of the chat to find relevant sections.

### 2. get-documentation

Retrieves full documentation content for specific sections. Accepts single or multiple sections.
After calling the list-sections tool, you MUST analyze the returned documentation sections (especially the use_cases field) and then use the get-documentation tool to fetch ALL documentation sections that are relevant for the user's task.

### 3. svelte-autofixer

Analyzes Svelte code and returns issues and suggestions.
You MUST use this tool whenever writing Svelte code before sending it to the user. Keep calling it until no issues or suggestions are returned.

### 4. playground-link

Generates a Svelte Playground link with the provided code.
After completing the code, ask the user if they want a playground link. Only call this tool after user confirmation and NEVER if code was written to files in their project.
