// Hard-coded secrets passed straight into a credential position.
// Every line ending in a FLAG comment gives exactly one CWE-798 finding.
import jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { createHmac } from 'node:crypto';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import cookieSession from 'cookie-session';
import mysql from 'mysql2';
import { Pool } from 'pg';
import { Sequelize } from 'sequelize';
import nodemailer from 'nodemailer';
import type { Express } from 'express';

export function issueToken(userId: string): string {
  return jwt.sign({ sub: userId }, 'k7Hq2-session-signing', { expiresIn: '1h' }); // FLAG
}

export function readToken(token: string): unknown {
  return jwt.verify(token, `k7Hq2-session-signing`); // FLAG
}

export function signWebhook(body: string): string {
  return createHmac('sha256', 'whk_9fQ2mLx').update(body).digest('hex'); // FLAG
}

export function sealRecord(data: string, iv: Buffer): string {
  const cipher = crypto.createCipheriv('aes-256-gcm', 'B8vR2nQ5tY7wZ1xC4eF6hJ9kL3mP0sU2', iv); // FLAG
  return cipher.update(data, 'utf8', 'hex');
}

export function configureSessions(app: Express): void {
  app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: false })); // FLAG
  app.use(cookieParser('cp-Secret-41')); // FLAG
  app.use(cookieSession({
    name: 'sid',
    keys: ['rotA-2291', 'rotB-7710'], // FLAG
  }));
}

export function openDatabase() {
  return mysql.createPool({
    host: 'db.internal',
    user: 'app',
    password: 'Winter2024!', // FLAG
  });
}

export function openReporting() {
  return new Pool({ user: 'report', password: 'rep0rt-pw', host: 'reports' }); // FLAG
}

export function openOrm() {
  return new Sequelize('shop', 'root', 'r00tpass', { dialect: 'mysql' }); // FLAG
}

export function mailer() {
  return nodemailer.createTransport({
    host: 'smtp.example.org',
    auth: { user: 'noreply', pass: 'smtp-pw-55' }, // FLAG
  });
}
