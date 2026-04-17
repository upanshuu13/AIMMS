const db = require("../database/db");

const BRUTE_FORCE_THRESHOLD = 5;
const TIME_WINDOW_SECONDS = 60;
const POLL_INTERVAL_MS = 30000;

async function runBruteForceRule() {
    try {
        const [attackers] = await db.query(
            `SELECT source_ip, COUNT(*) AS attempt_count
             FROM events
             WHERE event_type = 'failed_login'
             AND created_at >= NOW() - INTERVAL ? SECOND
             GROUP BY source_ip
             HAVING attempt_count >= ?`,
            [TIME_WINDOW_SECONDS, BRUTE_FORCE_THRESHOLD]
        );

        if (attackers.length === 0) {
            console.log("[RuleEngine] No brute-force activity");
            return;
        }

        for (const row of attackers) {
            const { source_ip, attempt_count } = row;

            await db.query(
                `INSERT INTO incidents (source_ip, rule_type, detail)
                 VALUES (?, 'BRUTE_FORCE', ?)`,
                [source_ip, `Failed attempts: ${attempt_count}`]
            );

            console.log(`🚨 BRUTE FORCE DETECTED → ${source_ip}`);
        }

    } catch (err) {
        console.error("[RuleEngine ERROR]", err.message);
    }
}

async function runAllRules() {
    console.log("[RuleEngine] Running...");
    await runBruteForceRule();
}

console.log("[RuleEngine] Started");

runAllRules();
setInterval(runAllRules, POLL_INTERVAL_MS);