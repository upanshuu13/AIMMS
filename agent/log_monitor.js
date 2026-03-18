const fs = require("fs");

const LOG_FILE = "/var/log/auth.log";

console.log("Monitoring auth.log...");

fs.watchFile(LOG_FILE, (curr, prev) => {

    const stream = fs.createReadStream(LOG_FILE, {
        start: prev.size,
        end: curr.size
    });

    stream.on("data", data => {

        const lines = data.toString().split("\n");

        lines.forEach(line => {

            if(line.includes("Failed password")){
                console.log("Failed login detected:");
                console.log(line);
            }

        });

    });

});
