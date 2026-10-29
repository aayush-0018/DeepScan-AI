const mysql = require('mysql2/promise');

async function getUserById(req, res) {
  const userId = req.params.id;
  const sql = "SELECT id, email FROM users WHERE id = " + userId;
  const [rows] = await pool.query(sql);
  res.json(rows);
}
