/**
 * AIMMS Day 4 – Network event API route
 * Add this to your existing Express app:
 *   const networkRoutes = require('./routes/networkEvents');
 *   app.use('/api', networkRoutes);
 */

const express = require('express');
const router  = express.Router();
const db      = require('../database/db');   // your existing MySQL connection/pool

/**
 * POST /api/network-event
 * Body: { events: [ { source_ip, dest_ip, port, protocol, timestamp } ] }
 * Called by sniffer.py in batches
 */
router.post('/network-event', async (req, res) => {
    const { events } = req.body;

    if (!Array.isArray(events) || events.length === 0) {
        return res.status(400).json({ error: 'events array required' });
    }

    // Build a multi-row INSERT for efficiency
    const values = events.map(e => [
        e.source_ip  || 'unknown',
        e.dest_ip    || null,
        e.port       || null,
        e.protocol   || 'OTHER',
        e.timestamp  || new Date().toISOString().slice(0, 19).replace('T', ' ')
    ]);

    const sql = `
        INSERT INTO network_events (source_ip, dest_ip, port, protocol, timestamp)
        VALUES ?
    `;

    try {
        await db.query(sql, [values]);
        console.log(`[network-event] stored ${events.length} events`);
        return res.json({ stored: events.length });
    } catch (err) {
        console.error('[network-event] DB error:', err.message);
        return res.status(500).json({ error: 'db insert failed' });
    }
});

/**
 * GET /api/network-events/recent
 * Returns last 100 network events — useful for debugging
 */
router.get('/network-events/recent', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT source_ip, dest_ip, port, protocol, timestamp
            FROM   network_events
            ORDER  BY timestamp DESC
            LIMIT  100
        `);
        return res.json(rows);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

module.exports = router;
