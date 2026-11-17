// CWE-117 fixture (JavaScript): a request value written unchanged to a log
// call. The line marked FLAG must give one `log_injection` flow.
import express from 'express';

const app = express();

function login(req, res) {
  const user = req.query.user;
  console.log('login attempt for ' + user); // FLAG
  res.send('ok');
}

app.get('/login', login);
