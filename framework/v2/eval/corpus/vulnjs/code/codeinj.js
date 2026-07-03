module.exports = (req, res) => {
  const expr = req.query.expr;            // SOURCE
  res.send(String(eval(expr)));           // SINK: CWE-95
};
