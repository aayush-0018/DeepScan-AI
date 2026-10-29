const SORTABLE = { name: 'name', price: 'price', created: 'created_at' };
const TABLE = 'products';

async function getUser(req, res) {
  const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  res.json(rows);
}

async function listProducts(req, res) {
  const column = SORTABLE[req.query.sort] || 'name';
  const limit = parseInt(req.query.limit, 10) || 20;
  const sql = 'SELECT * FROM ' + TABLE + ' ORDER BY ' + column + ' LIMIT ' + limit;
  const rows = await db.all(sql);
  res.json(rows);
}

async function findByEmail(email) {
  return prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
}

async function search(req, res) {
  const term = req.query.q;
  console.log("SELECT * FROM products WHERE name LIKE " + term);
  const products = await knex('products').where('name', 'like', `%${term}%`).limit(10);
  res.json(products);
}

async function sortedUsers(req, res) {
  const dir = ['asc', 'desc'].includes(req.query.dir) ? req.query.dir : 'asc';
  const result = await client.query(`SELECT * FROM users ORDER BY created_at ${dir}`);
  res.json(result.rows);
}

async function updateEmail(req, res) {
  await sequelize.query('UPDATE users SET email = :email WHERE id = :id', {
    replacements: { email: req.body.email, id: req.user.id },
  });
  res.sendStatus(204);
}
