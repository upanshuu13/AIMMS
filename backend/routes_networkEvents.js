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
router.post("/network-event", async (req, res) => {
    try {
        const events = req.body.events;

        if (!events || !Array.isArray(events)) {
            return res.status(400).json({ error: "events array required" });
        }

        // ✅ Correct values mapping
        const values = events.map(e => [
            e.src_ip,
            e.dst_ip,
            e.src_port,
            e.dst_port,
            e.protocol,
            e.length
        ]);

        // ✅ Correct SQL (matches packets table exactly)
        const sql = `
            INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, length)
            VALUES ?
        `;

        // ✅ Execute query
        await db.query(sql, [values]);

        console.log("Inserted:", values.length);
        res.json({ stored: values.length });

    } catch (err) {
        console.error("DB ERROR:", err);  // 👈 IMPORTANT
        res.status(500).json({ error: "db insert failed" });
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
