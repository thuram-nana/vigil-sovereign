module.exports = (col, req, res) => {
  col.findOne({ username: req.body.username, password: req.body.password },  // SINK: CWE-943
    (e, user) => res.json(user));
};
