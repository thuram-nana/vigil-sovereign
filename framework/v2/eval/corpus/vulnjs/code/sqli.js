module.exports = (db, req, res) => {
  const id = req.query.id;                // SOURCE
  db.query('SELECT * FROM users WHERE id = ' + id, (e, rows) => res.json(rows));  // SINK: CWE-89
};
