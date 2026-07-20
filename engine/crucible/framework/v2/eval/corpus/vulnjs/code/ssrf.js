const axios = require('axios');
module.exports = async (req, res) => {
  const url = req.query.target;           // SOURCE
  const r = await axios.get(url);         // SINK: CWE-918
  res.send(r.data);
};
