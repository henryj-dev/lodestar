import { openScriptDb } from "./lib/db";

/** One-shot integrity scan for deployment/maintenance windows. */
async function main() {
    const db = await openScriptDb();
    try {
        const rows = await db.queryRows<{ identity_id: string; identity_tenant_id: string; user_id: string; user_tenant_id: string | null }>(`
            SELECT i.id AS identity_id, i.tenant_id AS identity_tenant_id,
                   i.user_id AS user_id, u.tenant_id AS user_tenant_id
            FROM identities i
            LEFT JOIN users u ON u.id = i.user_id
            WHERE u.id IS NULL OR i.tenant_id <> u.tenant_id
            ORDER BY i.id
        `);
        if (rows.length > 0) {
            console.error(`❌ tenant 정합성 위반 ${rows.length}건`);
            for (const row of rows) console.error(JSON.stringify(row));
            process.exitCode = 1;
            return;
        }
        console.log("✅ tenant identity/user 정합성 위반 없음");
    } finally {
        await db.close();
    }
}

main().catch((error) => {
    console.error("❌ tenant 정합성 점검 실패:", error);
    process.exitCode = 1;
});
