const { QueryTypes } = require('sequelize');

exports.searchOrders = async (req, res) => {
  const status = req.query.status;
  const orders = await sequelize.query(
    "SELECT * FROM orders WHERE status = '" + status + "'",
    { type: QueryTypes.SELECT }
  );
  return res.json(orders);
};
