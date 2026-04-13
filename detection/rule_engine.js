

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
             AND timestamp >= NOW() - INTERVAL ? SECOND
             GROUP BY source_ip
             HAVING attempt_count >= ?`,
            [TIME_WINDOW_SECONDS, BRUTE_FORCE_THRESHOLD]
        );

        if (attackers.length === 0) {
            console.log(`[RuleEngine] ${timestamp()} — No brute-force activity`);
            return;
        }

        
        for (const row of attackers) {

            const { source_ip, attempt_count } = row;

            
            const [existing] = await db.query(
                `SELECT id FROM rule_matches
                 WHERE source_ip = ?
                 AND rule_type = 'brute_force'
                 AND detected_at >= NOW() - INTERVAL ? SECOND`,
                [source_ip, TIME_WINDOW_SECONDS]
            );

            if (existing.length > 0) {
                continue; 
            }

            
            await db.query(
                `INSERT INTO rule_matches (source_ip, rule_type, event_count)
                 VALUES (?, 'brute_force', ?)`,
                [source_ip, attempt_count]
            );

            console.log(
                `[RuleEngine] ${timestamp()} 🚨 BRUTE FORCE DETECTED → IP: ${source_ip}, Attempts: ${attempt_count}`
            );
        }

    } catch (err) {
        console.error("[RuleEngine ERROR]", err.message);
    }
}

// ─── LOOP ──────────────────────────────────────────
async function runAllRules() {
    console.log(`[RuleEngine] ${timestamp()} Running rules...`);
    await runBruteForceRule();
}

// timestamp helper
function timestamp() {
    return new Date().toISOString();
}

// ─── START ENGINE ──────────────────────────────────
console.log(`[RuleEngine] Started (interval: ${POLL_INTERVAL_MS / 1000}s)`);

runAllRules(); // run immediately
setInterval(runAllRules, POLL_INTERVAL_MS);