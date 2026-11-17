import express from 'express';
const app = express();
app.get('/a', (req, res) => {
  res.send('<p>' + req.query.a + '</p>');
});
app.get('/b', (req, res) => {
  console.log('b for ' + req.query.b);
  res.send('ok');
});
