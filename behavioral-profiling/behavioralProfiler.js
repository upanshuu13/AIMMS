const db = require('../database/db');

const CONFIG = {
    ANALYSIS_WINDOW_SECONDS: 60,
    POLL_INTERVAL_MS: 30000,
    LOGIN_SPIKE_MULTIPLIER: 3.0,
    PORT_SPIKE_MULTIPLIER: 3.0,
    MIN_OBSERVATIONS: 3,
    GLOBAL_FALLBACK_LOGINS: 2,
    GLOBAL_FALLBACK_PORTS: 5,
};

function updateRollingAverage(oldAvg, newValue, n) {
    return oldAvg + (newValue - oldAvg) / n;
}

function markHourActive(bitmask, hour) {
    const arr = bitmask.split('');
    arr[hour] = '1';
    return arr.join('');
}

function isOddHour(bitmask, hour, minObservations) {
    if (minObservations < CONFIG.MIN_OBSERVATIONS) return false;
    return bitmask[hour] === '0';
}

async function recordAnomaly(source_ip, anomaly_type, current_value, baseline_value) {
    const deviation_ratio = baseline_value > 0
        ? parseFloat((current_value / baseline_value).toFixed(2))
        : 0;

    const [existing] = await db.query(`
        SELECT id FROM anomalies
        WHERE  source_ip    = ?
          AND  anomaly_type = ?
          AND  detected_at  > NOW() - INTERVAL 60 SECOND
        LIMIT  1
    `, [source_ip, anomaly_type]);

    if (existing.length > 0) return;

    await db.query(`
        INSERT INTO anomalies
            (source_ip, anomaly_type, current_value, baseline_value, deviation_ratio)
        VALUES (?, ?, ?, ?, ?)
    `, [source_ip, anomaly_type, current_value, baseline_value, deviation_ratio]);

    console.log(
        `[profiler] ⚠️  ANOMALY | ${anomaly_type.padEnd(12)} | IP: ${source_ip}` +
        ` | current=${current_value} baseline=${baseline_value.toFixed(2)} ratio=${deviation_ratio}x`
    );
}

async function getCurrentLoginActivity() {
    const [rows] = await db.query(`
        SELECT   source_ip,
                 COUNT(*) AS attempt_count,
                 HOUR(MAX(created_at)) AS last_hour
        FROM     events
        WHERE    event_type = 'failed_login'
          AND    created_at  > NOW() - INTERVAL ? SECOND
        GROUP BY source_ip
    `, [CONFIG.ANALYSIS_WINDOW_SECONDS]);
    return rows;
}

async function getCurrentNetworkActivity() {
    const [rows] = await db.query(`
        SELECT   source_ip,
                 COUNT(DISTINCT port) AS unique_ports
        FROM     network_events
        WHERE    port       IS NOT NULL
          AND    timestamp  > NOW() - INTERVAL ? SECOND
        GROUP BY source_ip
    `, [CONFIG.ANALYSIS_WINDOW_SECONDS]);
    return rows;
}

async function getOrCreateProfile(source_ip) {
    const [rows] = await db.query(
        'SELECT * FROM user_profiles WHERE source_ip = ? LIMIT 1',
        [source_ip]
    );

    if (rows.length > 0) return rows[0];

    await db.query(
        `INSERT INTO user_profiles (source_ip) VALUES (?)
         ON DUPLICATE KEY UPDATE last_seen = NOW()`,
        [source_ip]
    );

    const [newRow] = await db.query(
        'SELECT * FROM user_profiles WHERE source_ip = ? LIMIT 1',
        [source_ip]
    );
    return newRow[0];
}

async function processLoginActivity(row) {
    const { source_ip, attempt_count, last_hour } = row;
    const profile = await getOrCreateProfile(source_ip);

    const newObsCount = profile.total_observations + 1;
    const newAvg = updateRollingAverage(
        profile.avg_login_attempts,
        attempt_count,
        newObsCount
    );
    const newHours = markHourActive(profile.active_hours, last_hour);

    const baseline = profile.total_observations >= CONFIG.MIN_OBSERVATIONS
        ? profile.avg_login_attempts
        : CONFIG.GLOBAL_FALLBACK_LOGINS;

    if (
        profile.total_observations >= CONFIG.MIN_OBSERVATIONS &&
        attempt_count > baseline * CONFIG.LOGIN_SPIKE_MULTIPLIER
    ) {
        await recordAnomaly(source_ip, 'LOGIN_SPIKE', attempt_count, baseline);
    }

    if (isOddHour(profile.active_hours, last_hour, profile.total_observations)) {
        await recordAnomaly(source_ip, 'ODD_HOUR', last_hour, -1);
    }

    await db.query(`
        UPDATE user_profiles
        SET    avg_login_attempts = ?,
               total_observations = ?,
               active_hours       = ?,
               last_seen          = NOW()
        WHERE  source_ip = ?
    `, [newAvg, newObsCount, newHours, source_ip]);
}

async function processNetworkActivity(row) {
    const { source_ip, unique_ports } = row;
    const profile = await getOrCreateProfile(source_ip);

    const newNetObs = profile.net_observations + 1;
    const newAvg = updateRollingAverage(
        profile.avg_ports_per_min,
        unique_ports,
        newNetObs
    );

    const baseline = profile.net_observations >= CONFIG.MIN_OBSERVATIONS
        ? profile.avg_ports_per_min
        : CONFIG.GLOBAL_FALLBACK_PORTS;

    if (
        profile.net_observations >= CONFIG.MIN_OBSERVATIONS &&
        unique_ports > baseline * CONFIG.PORT_SPIKE_MULTIPLIER
    ) {
        await recordAnomaly(source_ip, 'PORT_SPIKE', unique_ports, baseline);
    }

    await db.query(`
        UPDATE user_profiles
        SET    avg_ports_per_min = ?,
               net_observations  = ?,
               last_seen         = NOW()
        WHERE  source_ip = ?
    `, [newAvg, newNetObs, source_ip]);
}

async function profileAll() {
    try {
        const [loginActivity, networkActivity] = await Promise.all([
            getCurrentLoginActivity(),
            getCurrentNetworkActivity(),
        ]);

        await Promise.all([
            ...loginActivity.map(processLoginActivity),
            ...networkActivity.map(processNetworkActivity),
        ]);

        const total = loginActivity.length + networkActivity.length;
        if (total > 0) {
            console.log(`[profiler] cycle complete — processed ${total} active IPs`);
        }
    } catch (err) {
        console.error('[profiler] ERROR:', err.message);
    }
}

if (require.main === module) {
    console.log('[profiler] behavioral profiling engine starting...');
    console.log(`[profiler] analysis window: ${CONFIG.ANALYSIS_WINDOW_SECONDS}s, poll: ${CONFIG.POLL_INTERVAL_MS / 1000}s`);
    profileAll();
    setInterval(profileAll, CONFIG.POLL_INTERVAL_MS);
}

module.exports = { profileAll, CONFIG };