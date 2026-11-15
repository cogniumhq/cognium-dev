const express = require('express');
const app = express();
app.get('/login/done', function finish(req, res) {
  const next = req.query.next;
  res.redirect(next);
});
