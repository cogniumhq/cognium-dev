import type { Request, Response } from 'express';
import express from 'express';
import mysql from 'mysql';
const db = mysql.createConnection({});
const app = express();
app.get('/user', function getUser(req: Request, res: Response) {
  const id = req.query.id;
  db.query('SELECT * FROM users WHERE id = ?', [id], (e, rows) => res.json(rows));
});
