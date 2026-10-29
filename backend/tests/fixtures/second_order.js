async function loadAuditTrail(userId) {
  const [users] = await pool.execute('SELECT username FROM users WHERE id = ?', [userId]);
  const owner = users[0].username;
  const [logs] = await pool.query("SELECT * FROM audit_log WHERE owner = '" + owner + "'");
  return logs;
}
