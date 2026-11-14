// Near misses: literals that are not secrets, secrets that are not literals,
// look-alike APIs that are not the credential packages. No finding.
import jwt from 'jsonwebtoken';
import { createHash, createHmac } from 'crypto';
import session from 'express-session';
import mysql from 'mysql2';
import { Sequelize } from 'sequelize';
import type { Express } from 'express';

const config = { jwtSecret: process.env.JWT_SECRET ?? '' };

// Local helpers that share the API names but are not the libraries.
const tokens = { sign: (payload: object, key: string) => `${JSON.stringify(payload)}.${key}` };
function cookieParser(name: string): string { return name; }

export function token(userId: string): string {
  // Key from configuration, an algorithm option as a literal.
  return jwt.sign({ sub: userId }, config.jwtSecret, { algorithm: 'HS256' });
}

export function decodeOnly(t: string): unknown {
  return jwt.decode(t, { complete: true });
}

export function digest(body: string): string {
  // The algorithm is a literal, the key is not; createHash takes no key.
  return createHash('sha256').update(body).digest('hex') + createHmac('sha256', config.jwtSecret).digest('hex');
}

export function local(): string {
  return tokens.sign({ a: 1 }, 'not-a-library-key') + cookieParser('sid');
}

export function sessions(app: Express): void {
  app.use(session({ secret: `${process.env.SESSION_PREFIX}-sess`, name: 'connect.sid' }));
  app.use(session({ secret: 'changeme' }));
  app.use(session({ secret: '' }));
}

export function db(password: string) {
  return mysql.createPool({ host: 'db', user: 'app', password, database: 'shop' });
}

export function dbFromConfig(cfg: { password: string }) {
  return mysql.createConnection({ host: 'db', user: 'app', password: cfg.password });
}

export function sampleDb() {
  // Values that only name their slot, and SQLite (no password at all).
  const a = mysql.createPool({ host: 'db', user: 'user', password: 'password' });
  const b = new Sequelize('database', 'username', 'password', { dialect: 'sqlite', storage: 'data/app.sqlite' });
  return [a, b];
}
