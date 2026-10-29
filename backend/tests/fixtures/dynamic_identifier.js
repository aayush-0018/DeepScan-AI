router.get('/products', async (req, res) => {
  const sortColumn = req.query.sort || 'name';
  const rows = await db.all(`SELECT id, name, price FROM products ORDER BY ${sortColumn}`);
  res.send(rows);
});
