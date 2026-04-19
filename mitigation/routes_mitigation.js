const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { runMitigation, runUnblockExpired, CONFIG } = require('../mitigation/mitigationEngine');

router.get('/mitigations', async (req, res) => {
    const action = req.query.action;
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    let sql = 'SELECT * FROM mitigations';
    const args = [];

    if (action) {
        sql += ' WHERE action = ?';
        args.push(action.toUpperCase());
    }
    sql += ' ORDER BY actioned_at DESC LIMIT ?';
    args.push(limit);

    try {
        const [rows] = await db.query(sql, args);
        return res.json(rows);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.get('/mitigations/active', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT   m.source_ip,
                     m.trigger_score,
                     m.trigger_level,
                     m.ban_duration_s,
                     m.unblock_at,
                     m.actioned_at AS blocked_at,
                     m.note
            FROM     mitigations m
            WHERE    m.action     = 'BLOCK'
              AND    (m.unblock_at IS NULL OR m.unblock_at > NOW())
              AND    m.source_ip NOT IN (
                         SELECT source_ip FROM mitigations
                         WHERE  action = 'UNBLOCK'
                           AND  actioned_at > m.actioned_at
                     )
            ORDER BY m.actioned_at DESC
        `);
        return res.json(rows);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.post('/mitigations/unblock/:ip', async (req, res) => {
    const ip = req.params.ip;
    const { exec } = require('child_process');
    const util = require('util');
    const execAsync = util.promisify(exec);

    try {
        await execAsync(`sudo ufw delete deny from ${ip} to any`);
        await db.query(`
            INSERT INTO mitigations (source_ip, action, note)
            VALUES (?, 'UNBLOCK', 'Manual unblock via API')
        `, [ip]);
        return res.json({ message: `${ip} unblocked` });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.post('/mitigations/run', async (req, res) => {
    try {
        await runMitigation();
        await runUnblockExpired();
        return res.json({ message: 'mitigation cycle complete' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.get('/mitigations/config', async (req, res) => {
    return res.json({
        block_threshold: CONFIG.BLOCK_THRESHOLD,
        permaban_threshold: CONFIG.PERMABAN_THRESHOLD,
        temp_ban_seconds: CONFIG.TEMP_BAN_SECONDS,
        whitelist: [...CONFIG.WHITELIST],
    });
});

module.exports = router;