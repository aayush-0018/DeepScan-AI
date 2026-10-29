export interface Sample {
  id: string;
  label: string;
  filename: string;
  code: string;
}

export const SAMPLES: Sample[] = [
  {
    id: 'mixed',
    label: 'Express API (mixed)',
    filename: 'routes/users.js',
    code: `const express = require('express');
const router = express.Router();

// STRING_CONCAT
router.get('/users/:id', async (req, res) => {
  const sql = "SELECT id, email FROM users WHERE id = " + req.params.id;
  const [rows] = await pool.query(sql);
  res.json(rows);
});

// SAFE: parameterized
router.get('/users/by-email', async (req, res) => {
  const [rows] = await pool.query('SELECT id FROM users WHERE email = ?', [req.query.email]);
  res.json(rows);
});

// DYNAMIC_IDENTIFIER
router.get('/products', async (req, res) => {
  const sort = req.query.sort || 'name';
  const rows = await db.all(\`SELECT * FROM products ORDER BY \${sort}\`);
  res.json(rows);
});

module.exports = router;
`,
  },
  {
    id: 'template',
    label: 'Template literal login',
    filename: 'auth.js',
    code: `app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await client.query(
    \`SELECT * FROM accounts WHERE username = '\${username}' AND password = '\${password}'\`
  );
  res.json({ ok: result.rows.length > 0 });
});
`,
  },
  {
    id: 'orm',
    label: 'Sequelize raw query',
    filename: 'orders.js',
    code: `const { QueryTypes } = require('sequelize');

exports.searchOrders = async (req, res) => {
  const status = req.query.status;
  const orders = await sequelize.query(
    "SELECT * FROM orders WHERE status = '" + status + "'",
    { type: QueryTypes.SELECT }
  );
  return res.json(orders);
};
`,
  },
  {
    id: 'format',
    label: 'util.format',
    filename: 'invoices.js',
    code: `const util = require('util');

function deleteInvoice(req, res) {
  const invoiceId = req.body.invoiceId;
  const query = util.format("DELETE FROM invoices WHERE id = '%s'", invoiceId);
  connection.query(query, (err) => {
    if (err) return res.status(500).end();
    res.sendStatus(204);
  });
}
`,
  },
  {
    id: 'second-order',
    label: 'Second-order',
    filename: 'audit.js',
    code: `async function loadAuditTrail(userId) {
  const [users] = await pool.execute('SELECT username FROM users WHERE id = ?', [userId]);
  const owner = users[0].username;
  const [logs] = await pool.query("SELECT * FROM audit_log WHERE owner = '" + owner + "'");
  return logs;
}
`,
  },
  {
    id: 'typescript',
    label: 'TypeScript service',
    filename: 'report.service.ts',
    code: `interface Filter { field: string; value: string }

export class ReportService {
  constructor(private readonly db: any) {}

  async byField(filter: Filter): Promise<any[]> {
    const sql = \`SELECT * FROM reports WHERE \${filter.field} = '\${filter.value}'\`;
    return this.db.query(sql);
  }

  async byId(id: number): Promise<any[]> {
    return this.db.query('SELECT * FROM reports WHERE id = $1', [id]);
  }
}
`,
  },
  {
    id: 'safe',
    label: 'Safe patterns',
    filename: 'safe.js',
    code: `const SORTABLE = { name: 'name', price: 'price' };

async function listProducts(req, res) {
  const column = SORTABLE[req.query.sort] || 'name';
  const limit = parseInt(req.query.limit, 10) || 20;
  const rows = await db.all('SELECT * FROM products ORDER BY ' + column + ' LIMIT ' + limit);
  res.json(rows);
}

async function findByEmail(email) {
  return prisma.$queryRaw\`SELECT * FROM users WHERE email = \${email}\`;
}
`,
  },
];
