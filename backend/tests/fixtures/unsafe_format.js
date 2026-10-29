const util = require('util');

function deleteInvoice(req, res) {
  const invoiceId = req.body.invoiceId;
  const query = util.format("DELETE FROM invoices WHERE id = '%s'", invoiceId);
  connection.query(query, (err) => {
    if (err) return res.status(500).end();
    res.sendStatus(204);
  });
}
