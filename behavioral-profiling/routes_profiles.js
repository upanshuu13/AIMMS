const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { profileAll } = require('./behavioralProfiler');

router.get('/profiles', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT   source_ip,
                     avg_login_attempts,
                     total_observations,
                     avg_ports_per_min,
                     net_observations,
                     active_hours,
                     first_seen,
                     last_seen
            FROM     user_profiles
            ORDER BY last_seen DESC
            LIMIT    100
        `);
        return res.json(rows);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.get('/profiles/:ip', async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT * FROM user_profiles WHERE source_ip = ? LIMIT 1',
            [req.params.ip]
        );
        if (rows.length === 0) return res.status(404).json({ error: 'IP not found' });
        return res.json(rows[0]);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.get('/anomalies', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const type = req.query.type;

    let sql = 'SELECT * FROM anomalies';
    const args = [];

    if (type) {
        sql += ' WHERE anomaly_type = ?';
        args.push(type);
    }

    sql += ' ORDER BY detected_at DESC LIMIT ?';
    args.push(limit);

    try {
        const [rows] = await db.query(sql, args);
        return res.json(rows);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.post('/profiler/run', async (req, res) => {
    try {
        await profileAll();
        return res.json({ message: 'profiling cycle complete' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

module.exports = router;