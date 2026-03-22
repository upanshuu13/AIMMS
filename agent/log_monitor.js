const { spawn } = require("child_process");
const axios = require("axios");

console.log("Monitoring auth.log...");

// Use tail -F for real-time log tracking (better than fs.watchFile)
const tail = spawn("tail", ["-F", "/var/log/auth.log"]);

tail.stdout.on("data", async (data) => {

    const lines = data.toString().split("\n");

    for (let line of lines) {

        if (line.includes("Failed password")) {

            const ipMatch = line.match(/from (\d+\.\d+\.\d+\.\d+)/);
            const userMatch = line.match(/user (\w+)/);

            const ip = ipMatch ? ipMatch[1] : "unknown";
            const user = userMatch ? userMatch[1] : "unknown";

            const event = {
                event_type: "failed_login",
                source_ip: ip,
                username: user,
                message: line
            };

            console.log("⚠️ Event detected:", event);

            try {
                await axios.post("http://localhost:3000/event", event);
                console.log("✅ Event sent to backend");
            } catch (err) {
                console.log("❌ Failed to send event");
            }
        }
    }
});
