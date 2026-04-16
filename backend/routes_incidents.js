/**
 * AIMMS Day 5 – Incidents API route
 * Add to your Express app:
 *   const incidentRoutes = require('./routes/incidents');
 *   app.use('/api', incidentRoutes);
 */

const express      = require('express');
const router       = express.Router();
const db           = require('../database/db');
const { runRules } = require('../day5-rule-engine/ruleEngine');

/**
 * GET /api/incidents
 * Returns recent incidents, newest first.
 * Optional query params: ?limit=50&rule_type=BRUTE_FORCE
 */
router.get('/incidents', async (req, res) => {
    const limit     = Math.min(parseInt(req.query.limit) || 50, 200);
    const rule_type = req.query.rule_type;

    let sql    = 'SELECT * FROM incidents';
    const args = [];

    if (rule_type) {
        sql += ' WHERE rule_type = ?';
        args.push(rule_type);
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

/**
 * POST /api/incidents/run-rules
 * Manually trigger the rule engine (useful during testing).
 * In production, ruleEngine.js polls on its own schedule.
 */
router.post('/incidents/run-rules', async (req, res) => {
    try {
        await runRules();
        return res.json({ message: 'rules executed' });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

module.exports = router;
