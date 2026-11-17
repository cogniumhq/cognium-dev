import express from 'express';
const app = express();
app.get('/a', (req, res) => {
  res.send('<p>' + req.query.first + '</p>');
});
app.get('/a', (req, res) => {
  res.send('<b>' + req.query.second + '</b>');
});
