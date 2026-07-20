const cp = require('child_process');
module.exports = (req, res) => {
  const host = req.query.host;            // SOURCE
  cp.exec('ping -c1 ' + host);            // SINK: CWE-78
};
