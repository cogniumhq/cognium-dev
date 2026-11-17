import express from 'express';
import escapeHtml from 'escape-html';
const app = express();
app.get('/a', (req, res) => {
  res.send('<p>' + req.query.a + '</p>');
});
app.get('/b', (req, res) => {
  console.log('b for ' + String(req.query.b).replace(/[\r\n]/g, ''));
  res.send('ok');
});
