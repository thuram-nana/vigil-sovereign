const fs = require('fs');
module.exports = (req, res) => {
  const name = req.query.file;            // SOURCE
  res.send(fs.readFileSync('/var/data/' + name));   // SINK: CWE-22
};
