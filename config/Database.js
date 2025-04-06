const mysql = require('mysql2');

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
 waitForConnections: true,
  connectionLimit: 20, // Adjust based on your app's needs
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,
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
