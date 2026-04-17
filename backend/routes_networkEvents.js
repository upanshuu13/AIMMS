const express = require('express');
const router = express.Router();
const db = require('../database/db');

router.post('/network-event', async (req, res) => {
    const { events } = req.body;

    if (!Array.isArray(events) || events.length === 0) {
        return res.status(400).json({ error: 'events array required' });
    }

    const values = events.map(e => [
        e.source_ip || 'unknown',
        e.dest_ip || null,
        e.port || null,
        e.protocol || 'OTHER',
        e.timestamp || new Date().toISOString().slice(0, 19).replace('T', ' ')
    ]);

    const sql = `
        INSERT INTO network_events (source_ip, dest_ip, port, protocol, timestamp)
        VALUES ?
    `;

    try {
        await db.query(sql, [values]);
        console.log(`stored ${events.length} network events`);
        return res.json({ stored: events.length });
    } catch (err) {
        console.error('DB error:', err.message);
        return res.status(500).json({ error: 'db insert failed' });
    }
});

router.get('/network-events/recent', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT source_ip, dest_ip, port, protocol, timestamp
            FROM network_events
            ORDER BY timestamp DESC
            LIMIT 100
        `);
        return res.json(rows);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

module.exports = router;