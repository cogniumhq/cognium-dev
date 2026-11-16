// The same code with every secret read from the environment: no finding.
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

const env = process.env;

export function issueToken(userId: string): string {
  return jwt.sign({ sub: userId }, env.JWT_SECRET as string, { expiresIn: '1h' });
}

export function readToken(token: string): unknown {
  return jwt.verify(token, env.JWT_SECRET as string);
}

export function signWebhook(body: string): string {
  return createHmac('sha256', env.WEBHOOK_SECRET as string).update(body).digest('hex');
}

export function sealRecord(data: string, iv: Buffer): string {
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(env.RECORD_KEY as string, 'hex'), iv);
  return cipher.update(data, 'utf8', 'hex');
}

export function configureSessions(app: Express): void {
  app.use(session({ secret: env.SESSION_SECRET as string, resave: false, saveUninitialized: false }));
  app.use(cookieParser(env.COOKIE_SECRET));
  app.use(cookieSession({
    name: 'sid',
    keys: [env.COOKIE_KEY_A as string, env.COOKIE_KEY_B as string],
  }));
}

export function openDatabase() {
  return mysql.createPool({
    host: 'db.internal',
    user: 'app',
    password: env.DB_PASSWORD,
  });
}

export function openReporting() {
  return new Pool({ user: 'report', password: env.REPORT_DB_PASSWORD, host: 'reports' });
}

export function openOrm() {
  return new Sequelize('shop', 'root', env.ORM_PASSWORD, { dialect: 'mysql' });
}

export function mailer() {
  return nodemailer.createTransport({
    host: 'smtp.example.org',
    auth: { user: 'noreply', pass: env.SMTP_PASSWORD },
  });
}
