const db = require('../database/db');

const WEIGHTS = {
    BRUTE_FORCE: 20,
    PORT_SCAN: 20,
    LOGIN_SPIKE: 25,
    PORT_SPIKE: 25,
    ODD_HOUR: 15,
};

const LOOKBACK_MINUTES = 10;
const POLL_INTERVAL_MS = 20000;

const THRESHOLDS = {
    CRITICAL: 90,
    HIGH: 60,
    MEDIUM: 30,
};

function getRiskLevel(score) {
    if (score >= THRESHOLDS.CRITICAL) return 'CRITICAL';
    if (score >= THRESHOLDS.HIGH) return 'HIGH';
    if (score >= THRESHOLDS.MEDIUM) return 'MEDIUM';
    return 'LOW';
}

async function getActiveIPs() {
    const [rows] = await db.query(`
        SELECT DISTINCT source_ip FROM (
            SELECT source_ip FROM incidents
            WHERE  detected_at > NOW() - INTERVAL ? MINUTE
            UNION
            SELECT source_ip FROM anomalies
            WHERE  detected_at > NOW() - INTERVAL ? MINUTE
        ) AS active
    `, [LOOKBACK_MINUTES, LOOKBACK_MINUTES]);
    return rows.map(r => r.source_ip);
}

async function computeScore(source_ip) {
    const [incidentRows] = await db.query(`
        SELECT rule_type, COUNT(*) AS cnt
        FROM   incidents
        WHERE  source_ip   = ?
          AND  detected_at > NOW() - INTERVAL ? MINUTE
        GROUP  BY rule_type
    `, [source_ip, LOOKBACK_MINUTES]);

    const [anomalyRows] = await db.query(`
        SELECT anomaly_type, COUNT(*) AS cnt
        FROM   anomalies
        WHERE  source_ip   = ?
          AND  detected_at > NOW() - INTERVAL ? MINUTE
        GROUP  BY anomaly_type
    `, [source_ip, LOOKBACK_MINUTES]);

    let score_brute = 0;
    let score_portscan = 0;
    let score_anomaly = 0;
    let score_odd_hour = 0;

    for (const { rule_type, cnt } of incidentRows) {
        if (rule_type === 'BRUTE_FORCE') score_brute += cnt * WEIGHTS.BRUTE_FORCE;
        if (rule_type === 'PORT_SCAN') score_portscan += cnt * WEIGHTS.PORT_SCAN;
    }

    for (const { anomaly_type, cnt } of anomalyRows) {
        if (anomaly_type === 'LOGIN_SPIKE') score_anomaly += cnt * WEIGHTS.LOGIN_SPIKE;
        if (anomaly_type === 'PORT_SPIKE') score_anomaly += cnt * WEIGHTS.PORT_SPIKE;
        if (anomaly_type === 'ODD_HOUR') score_odd_hour += cnt * WEIGHTS.ODD_HOUR;
    }

    const total_score = score_brute + score_portscan + score_anomaly + score_odd_hour;
    const risk_level = getRiskLevel(total_score);

    return { source_ip, score_brute, score_portscan, score_anomaly, score_odd_hour, total_score, risk_level };
}

async function saveScore(scoreData) {
    const { source_ip, score_brute, score_portscan, score_anomaly, score_odd_hour, total_score, risk_level } = scoreData;

    await db.query(`
        INSERT INTO risk_scores
            (source_ip, score_brute, score_portscan, score_anomaly, score_odd_hour, total_score, risk_level, last_calculated)
        VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE
            score_brute     = VALUES(score_brute),
            score_portscan  = VALUES(score_portscan),
            score_anomaly   = VALUES(score_anomaly),
            score_odd_hour  = VALUES(score_odd_hour),
            total_score     = VALUES(total_score),
            risk_level      = VALUES(risk_level),
            last_calculated = NOW()
    `, [source_ip, score_brute, score_portscan, score_anomaly, score_odd_hour, total_score, risk_level]);

    if (total_score > 0) {
        const bar = '█'.repeat(Math.min(Math.floor(total_score / 10), 10));
        const level = risk_level.padEnd(8);
        console.log(`[scorer] ${level} | IP: ${source_ip.padEnd(15)} | score: ${String(total_score).padStart(3)} ${bar}`);
    }

    return scoreData;
}

async function scoreAll() {
    try {
        const ips = await getActiveIPs();
        if (ips.length === 0) return;

        const results = await Promise.all(
            ips.map(ip => computeScore(ip).then(saveScore))
        );

        const critical = results.filter(r => r.risk_level === 'CRITICAL');
        const high = results.filter(r => r.risk_level === 'HIGH');

        if (critical.length > 0) {
            console.log(`[scorer] 🔴 ${critical.length} CRITICAL IP(s): ${critical.map(r => r.source_ip).join(', ')}`);
        }
        if (high.length > 0) {
            console.log(`[scorer] 🟠 ${high.length} HIGH IP(s): ${high.map(r => r.source_ip).join(', ')}`);
        }

        return results;
    } catch (err) {
        console.error('[scorer] ERROR:', err.message);
    }
}

async function getScore(source_ip) {
    const [rows] = await db.query(
        'SELECT * FROM risk_scores WHERE source_ip = ? LIMIT 1',
        [source_ip]
    );
    return rows[0] || null;
}

if (require.main === module) {
    console.log('[scorer] risk scoring engine starting...');
    console.log(`[scorer] lookback: ${LOOKBACK_MINUTES}min | poll: ${POLL_INTERVAL_MS / 1000}s`);
    console.log(`[scorer] thresholds → MEDIUM:${THRESHOLDS.MEDIUM} HIGH:${THRESHOLDS.HIGH} CRITICAL:${THRESHOLDS.CRITICAL}\n`);
    scoreAll();
    setInterval(scoreAll, POLL_INTERVAL_MS);
}

module.exports = { scoreAll, getScore, computeScore, THRESHOLDS, WEIGHTS };