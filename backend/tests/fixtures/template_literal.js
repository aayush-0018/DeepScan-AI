app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await client.query(
    `SELECT * FROM accounts WHERE username = '${username}' AND password = '${password}'`
  );
  res.json({ ok: result.rows.length > 0 });
});
