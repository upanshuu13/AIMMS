const express = require('express');
const router = express.Router();
const db = require('../database/db');
const { scoreAll, computeScore, THRESHOLDS, WEIGHTS } = require('./riskScorer');

router.get('/risk-scores', async (req, res) => {
    const level = req.query.level;
    let sql = 'SELECT * FROM risk_scores';
    const args = [];

    if (level) {
        sql += ' WHERE risk_level = ?';
        args.push(level.toUpperCase());
    }

    sql += ' ORDER BY total_score DESC LIMIT 100';

    try {
        const [rows] = await db.query(sql, args);
        return res.json(rows);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.get('/risk-scores/:ip', async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT * FROM risk_scores WHERE source_ip = ? LIMIT 1',
            [req.params.ip]
        );
        if (rows.length === 0) return res.status(404).json({ error: 'IP not scored yet' });
        return res.json({
            ...rows[0],
            weights: WEIGHTS,
            thresholds: THRESHOLDS,
        });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.get('/risk-scores/summary/counts', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT   risk_level, COUNT(*) AS count
            FROM     risk_scores
            GROUP BY risk_level
            ORDER BY FIELD(risk_level, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
        `);
        return res.json(rows);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

router.post('/risk-scores/recalculate', async (req, res) => {
    try {
        const results = await scoreAll();
        return res.json({ scored: results ? results.length : 0 });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

module.exports = router;