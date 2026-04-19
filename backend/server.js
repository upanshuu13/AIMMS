const express = require("express");
const db = require("../database/db");

const networkRoutes = require("./routes_networkEvents");
const incidentRoutes = require("./routes_incidents");
const profileRoutes = require("../behavioral-profiling/routes_profiles");

const app = express();

app.use(express.json());

app.post("/event", async (req, res) => {
  try {
    const { event_type, source_ip, username, message } = req.body;

    if (!event_type || !source_ip) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    await db.query(
      `INSERT INTO events (event_type, source_ip, username, message)
       VALUES (?, ?, ?, ?)`,
      [event_type, source_ip, username, message]
    );

    console.log(`Event stored → ${event_type} from ${source_ip}`);

    res.json({ message: "Event stored" });

  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.use("/api", networkRoutes);
app.use("/api", incidentRoutes);
app.use("/api", profileRoutes);

app.get("/", (req, res) => {
  res.send("AIMMS Backend Running");
});

app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err.message);
  res.status(500).json({ error: "Something went wrong" });
});

const PORT = 3000;

app.listen(PORT, () => {
  console.log(`AIMMS backend running on port ${PORT}`);
});