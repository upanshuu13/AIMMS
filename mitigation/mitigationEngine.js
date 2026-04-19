const { exec } = require('child_process');
const util = require('util');
const db = require('../database/db');
const { getScore } = require('../risk-scoring/riskScorer');

const execAsync = util.promisify(exec);

const CONFIG = {
    POLL_INTERVAL_MS: 15000,
    UNBLOCK_CHECK_MS: 30000,
    BLOCK_THRESHOLD: 90,
    PERMABAN_THRESHOLD: 150,
    TEMP_BAN_SECONDS: 300,
    PERMA_BAN_SECONDS: null,
    WHITELIST: new Set([
        '127.0.0.1',
        '::1',
        '10.57.92.252'
    ]),
};

async function blockIP(ip, permanent = false) {
    const cmd = `sudo ufw deny from ${ip} to any`;
    console.log(`[mitigation] 🔒 BLOCK ${permanent ? '(permanent)' : '(temp)'} → ${cmd}`);
    try {
        await execAsync(cmd);
        return true;
    } catch (err) {
        console.error(`[mitigation] ufw block failed for ${ip}:`, err.message);
        return false;
    }
}

async function unblockIP(ip) {
    const cmd = `sudo ufw delete deny from ${ip} to any`;
    console.log(`[mitigation] 🔓 UNBLOCK → ${cmd}`);
    try {
        await execAsync(cmd);
        return true;
    } catch (err) {
        console.warn(`[mitigation] ufw unblock warning for ${ip}:`, err.message);
        return false;
    }
}

async function isCurrentlyBlocked(ip) {
    const [rows] = await db.query(`
        SELECT id FROM mitigations
        WHERE  source_ip = ?
          AND  action    = 'BLOCK'
          AND  (unblock_at IS NULL OR unblock_at > NOW())
        LIMIT  1
    `, [ip]);
    return rows.length > 0;
}

async function logMitigation(ip, action, score, level, banSeconds, note = null) {
    const unblockAt = banSeconds
        ? new Date(Date.now() + banSeconds * 1000).toISOString().slice(0, 19).replace('T', ' ')
        : null;

    await db.query(`
        INSERT INTO mitigations
            (source_ip, action, trigger_score, trigger_level, ban_duration_s, unblock_at, note)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [ip, action, score, level, banSeconds, unblockAt, note]);
}

async function evaluateIP(ip, score, risk_level) {
    if (CONFIG.WHITELIST.has(ip)) {
        console.log(`[mitigation] ✅ SKIPPED (whitelisted): ${ip}`);
        await logMitigation(ip, 'WHITELIST_SKIP', score, risk_level, null, 'IP is whitelisted');
        return;
    }

    const alreadyBlocked = await isCurrentlyBlocked(ip);
    if (alreadyBlocked) return;

    const isPermanent = score >= CONFIG.PERMABAN_THRESHOLD;
    const banSeconds = isPermanent ? null : CONFIG.TEMP_BAN_SECONDS;

    const blocked = await blockIP(ip, isPermanent);
    if (!blocked) return;

    const note = isPermanent
        ? `Score ${score} exceeded permanent ban threshold (${CONFIG.PERMABAN_THRESHOLD})`
        : `Score ${score} is CRITICAL — temp ban for ${CONFIG.TEMP_BAN_SECONDS}s`;

    await logMitigation(ip, 'BLOCK', score, risk_level, banSeconds, note);

    console.log(
        `[mitigation] ${isPermanent ? '🔴 PERMA-BAN' : '🟠 TEMP-BAN'} | ` +
        `IP: ${ip} | score: ${score} | duration: ${isPermanent ? 'permanent' : CONFIG.TEMP_BAN_SECONDS + 's'}`
    );
}

async function runMitigation() {
    try {
        const [rows] = await db.query(`
            SELECT source_ip, total_score, risk_level
            FROM   risk_scores
            WHERE  total_score >= ?
              AND  last_calculated > NOW() - INTERVAL 5 MINUTE
            ORDER  BY total_score DESC
        `, [CONFIG.BLOCK_THRESHOLD]);

        for (const row of rows) {
            await evaluateIP(row.source_ip, row.total_score, row.risk_level);
        }
    } catch (err) {
        console.error('[mitigation] ERROR in runMitigation:', err.message);
    }
}

async function runUnblockExpired() {
    try {
        const [expired] = await db.query(`
            SELECT source_ip, trigger_score FROM mitigations
            WHERE  action      = 'BLOCK'
              AND  unblock_at  IS NOT NULL
              AND  unblock_at  <= NOW()
              AND  source_ip NOT IN (
                  SELECT source_ip FROM mitigations
                  WHERE  action = 'UNBLOCK'
                    AND  actioned_at > NOW() - INTERVAL 1 HOUR
              )
        `);

        for (const row of expired) {
            const unblocked = await unblockIP(row.source_ip);
            if (unblocked) {
                await logMitigation(
                    row.source_ip, 'UNBLOCK',
                    row.trigger_score, null, null,
                    'Temporary ban expired — auto-unblocked'
                );
                console.log(`[mitigation] ✅ AUTO-UNBLOCKED: ${row.source_ip}`);
            }
        }
    } catch (err) {
        console.error('[mitigation] ERROR in runUnblockExpired:', err.message);
    }
}

if (require.main === module) {
    console.log('[mitigation] mitigation engine starting...');
    console.log(`[mitigation] BLOCK threshold: ${CONFIG.BLOCK_THRESHOLD} | PERMA threshold: ${CONFIG.PERMABAN_THRESHOLD}`);
    console.log(`[mitigation] Temp ban: ${CONFIG.TEMP_BAN_SECONDS}s | Whitelist: ${[...CONFIG.WHITELIST].join(', ')}\n`);

    runMitigation();
    runUnblockExpired();
    setInterval(runMitigation, CONFIG.POLL_INTERVAL_MS);
    setInterval(runUnblockExpired, CONFIG.UNBLOCK_CHECK_MS);
}

module.exports = { runMitigation, runUnblockExpired, CONFIG };