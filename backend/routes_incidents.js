const express = require('express');
const router = express.Router();
const db = require('../database/db');

router.get('/incidents', async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 50, 200);

        const [rows] = await db.query(`
            SELECT * FROM incidents
            ORDER BY detected_at DESC
            LIMIT ?
        `, [limit]);

        res.json(rows);
    } catch (err) {
        console.error("Incidents API error:", err);
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;