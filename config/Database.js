const mysql = require('mysql2');

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
   maxIdle: 0,
idleTimeout: 60000,
enableKeepAlive: true,
});

db.connect((err) => {
  if (err) {
   console.error("Database error:", err);
    return res.status(500).send("Database insert failed.");

  } else {
    console.log('Connected to MySQL database');
  }
});

module.exports = db
