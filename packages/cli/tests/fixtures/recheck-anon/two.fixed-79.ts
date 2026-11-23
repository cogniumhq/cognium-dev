import express from 'express';
import escapeHtml from 'escape-html';
const app = express();
app.get('/a', (req, res) => {
  res.send('<p>' + escapeHtml(String(req.query.a)) + '</p>');
});
app.get('/b', (req, res) => {
  console.log('b for ' + req.query.b);
  res.send('ok');
});
