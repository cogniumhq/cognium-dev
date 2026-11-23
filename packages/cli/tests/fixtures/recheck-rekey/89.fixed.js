const express = require('express');
const mysql = require('mysql');
const db = mysql.createConnection({});
const app = express();
app.get('/user', function getUser(req, res) {
  const id = req.query.id;
  db.query('SELECT * FROM users WHERE id = ?', [id], (e, rows) => res.json(rows));
});
