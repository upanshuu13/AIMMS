const express = require("express");
const db = require("../database/db");

// ROUTES
const networkRoutes = require("./routes_networkEvents");
// const incidentRoutes = require("./routes_incidents"); // <-- ADD THIS (Day 5)

const app = express();

app.use(express.json());

// =========================
// EVENT INGESTION API (Day 1)
// =========================
app.post("/event", (req, res) => {

  const { event_type, source_ip, username, message } = req.body;

  const query = `
    INSERT INTO events(event_type, source_ip, username, message)
    VALUES (?, ?, ?, ?)
  `;

  db.query(query, [event_type, source_ip, username, message], (err, result) => {

    if (err) {
      console.error("DB Error:", err);
      return res.status(500).send("Database error");
    }

    console.log("Event stored:", event_type, source_ip);
    res.send("Event stored");
  });
});

// =========================
// NETWORK EVENTS (Day 4)
// =========================
app.use("/api", networkRoutes);

// =========================
// INCIDENTS (Day 5)
// =========================
// app.use("/api/incidents", incidentRoutes);

// =========================
// HEALTH CHECK (optional)
// =========================
app.get("/", (req, res) => {
  res.send("AIMMS Backend Running");
});

// =========================
// ERROR HANDLER
// =========================
app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err);
  res.status(500).send("Something went wrong");
});

// =========================
// START SERVER
// =========================
app.listen(3000, () => {
  console.log("AIMMS backend running on port 3000");
});