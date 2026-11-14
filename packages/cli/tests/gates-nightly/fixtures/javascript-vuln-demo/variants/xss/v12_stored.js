// XSS variant: stored — persist then render without escaping.
/* eslint-disable @typescript-eslint/no-require-imports -- byte-aligned variant corpus */
const express = require('express'); const app = express(); let store = '';
app.post('/c', (req, res) => { store = req.body.comment; res.end(); });      // SOURCE persisted
app.get('/c', (req, res) => { res.send('<div>' + store + '</div>'); });       // SINK CWE-79 stored