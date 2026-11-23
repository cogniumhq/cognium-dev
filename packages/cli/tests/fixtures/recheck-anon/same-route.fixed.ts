import express from 'express';
import escapeHtml from 'escape-html';
const app = express();
app.get('/a', (req, res) => {
  res.send('<p>' + escapeHtml(String(req.query.first)) + '</p>');
});
app.get('/a', (req, res) => {
  res.send('<b>' + req.query.second + '</b>');
});
