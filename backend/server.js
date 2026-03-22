const express = require("express");
const db = require("../database/db");

const app = express();

app.use(express.json());

app.post("/event", (req, res) => {

  const {event_type, source_ip, username, message} = req.body;

  const query = `
  INSERT INTO events(event_type, source_ip, username, message)
  VALUES (?, ?, ?, ?)
  `;

  db.query(query,[event_type, source_ip, username, message],(err,result)=>{

      if(err){
          console.log(err);
          res.status(500).send("Database error");
      } else {
          res.send("Event stored");
      }

  });

});

app.listen(3000,()=>{
  console.log("AIMMS backend running on port 3000");
});