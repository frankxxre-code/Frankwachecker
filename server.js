'use strict';
/**
 * WA CHECKER PLATFORM v3 — Fixed Pairing
 * Multi-user · Private sessions · Shared permanent DB
 * Admin panel · Job history · Live progress via WebSocket
 */

// Polyfill Web Crypto API for Node.js < 19 — required by Baileys requestPairingCode
if (!globalThis.crypto) {
    globalThis.crypto = require('crypto').webcrypto;
}

const { makeWASocket, useMultiFileAuthState, DisconnectReason } = require('@whiskeysockets/baileys');
const pino      = require('pino');
const express   = require('express');
const session   = require('express-session');
const multer    = require('multer');
const http      = require('http');
const WebSocket = require('ws');
const bcrypt    = require('bcryptjs');
const Database  = require('better-sqlite3');
const fs        = require('fs').promises;
const fsSync    = require('fs');
const path      = require('path');
const qrcode    = require('qrcode');
const crypto    = require('crypto');
const os        = require('os');

// ─── CONFIG ──────────────────────────────────────────────────────
const PORT          = process.env.PORT          || 3000;
const SESSION_SECRET= process.env.SESSION_SECRET|| crypto.randomBytes(32).toString('hex');
const ADMIN_EMAIL   = process.env.ADMIN_EMAIL   || 'admin@wachecker.com';
const ADMIN_PASS    = process.env.ADMIN_PASSWORD || 'Admin@2024!';
const BASE_DIR      = process.env.BASE_DIR      || path.join(process.cwd(), 'data');
const RESULTS_DB_FILE = path.join(BASE_DIR, 'results_db.json');
const PENDING_DIR   = path.join(BASE_DIR, 'pending');
const AUTH_DIR      = path.join(BASE_DIR, 'sessions');
const DB_PATH       = path.join(BASE_DIR, 'platform.db');

// ─── TUNING ──────────────────────────────────────────────────────
const CONCURRENCY_PER_SESSION = 50;
const MAX_GLOBAL_CONCURRENT   = 300;
const BATCH_TARGET            = 100;
const REQUEST_JITTER_MS       = 10;
const BACKOFF_FAIL_THRESHOLD  = 0.30;
const COOLDOWN_EVERY_N        = 6000;
const COOLDOWN_MS             = 4000;
const MAX_CHECK_RETRIES       = 2;
const JOB_SAVE_INTERVAL       = 100;
const STARTUP_STAGGER_MS      = 7000;
const MAX_SESSIONS_PER_USER   = 10;
const MAX_JOBS_PER_USER       = 5;  // max concurrent jobs per user

const logger = pino({ level: 'silent' });

// ─── SQLITE SETUP ─────────────────────────────────────────────────
let db;
function initDB() {
    fsSync.mkdirSync(BASE_DIR,    { recursive: true });
    fsSync.mkdirSync(PENDING_DIR, { recursive: true });
    fsSync.mkdirSync(AUTH_DIR,    { recursive: true });

    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('busy_timeout = 10000');

    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT UNIQUE NOT NULL,
            username    TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'user',
            banned      INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            last_login  TEXT
        );

        CREATE TABLE IF NOT EXISTS jobs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id      TEXT UNIQUE NOT NULL,
            user_id     INTEGER NOT NULL,
            filename    TEXT,
            total       INTEGER DEFAULT 0,
            processed   INTEGER DEFAULT 0,
            registered  INTEGER DEFAULT 0,
            not_found   INTEGER DEFAULT 0,
            status      TEXT DEFAULT 'pending',
            mode        TEXT DEFAULT 'new',
            from_cache  INTEGER DEFAULT 0,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            completed_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS wa_sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT NOT NULL,
            user_id     INTEGER NOT NULL,
            phone       TEXT,
            method      TEXT DEFAULT 'qr',
            state       TEXT DEFAULT 'initializing',
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(session_id, user_id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_jobs_user   ON jobs(user_id);
        CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
        CREATE INDEX IF NOT EXISTS idx_wa_user     ON wa_sessions(user_id);
    `);

    // Create admin if not exists
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(ADMIN_EMAIL);
    if (!existing) {
        const hash = bcrypt.hashSync(ADMIN_PASS, 10);
        db.prepare('INSERT INTO users (email, username, password, role) VALUES (?,?,?,?)').run(ADMIN_EMAIL, 'admin', hash, 'admin');
        console.log(`✅ Admin created: ${ADMIN_EMAIL}`);
    }
}

// ─── SHARED RESULTS DB ────────────────────────────────────────────
let resultsCache = new Map();

async function loadResultsDB() {
    try {
        const raw  = await fs.readFile(RESULTS_DB_FILE, 'utf8');
        resultsCache = new Map(Object.entries(JSON.parse(raw)));
    } catch { resultsCache = new Map(); }
    return resultsCache;
}

async function saveResultsDB() {
    const tmp = RESULTS_DB_FILE + '.tmp';
    await fs.writeFile(tmp, JSON.stringify(Object.fromEntries(resultsCache), null, 2), 'utf8');
    await fs.rename(tmp, RESULTS_DB_FILE);
}

function lookupNumbers(numbers) {
    const known = [], unknown = [];
    for (const num of numbers) {
        const v = resultsCache.get(num);
        if (v)      known.push({ num, result: v });
        else        unknown.push(num);
    }
    return { known, unknown };
}

// ─── IN-MEMORY SESSION STATE ──────────────────────────────────────
// waSessions: Map<`${userId}:${sessionId}` → WA session object>
const waSessions     = new Map();
const sessionCleanup = new Map();

// activeJobs: Map<jobId → job state>
const activeJobs = new Map();

// ─── WEBSOCKET ROOMS ──────────────────────────────────────────────
// wsClients: Map<userId → Set<ws>>
const wsClients = new Map();

function sendToUser(userId, type, data = {}) {
    const clients = wsClients.get(userId);
    if (!clients) return;
    const msg = JSON.stringify({ type, ...data });
    for (const ws of clients) {
        if (ws.readyState === WebSocket.OPEN) {
            try { ws.send(msg); } catch (_) {}
        }
    }
}

function sendToAdmins(type, data = {}) {
    const admins = db.prepare("SELECT id FROM users WHERE role='admin'").all();
    for (const { id } of admins) sendToUser(id, type, data);
}

// ─── UTILITIES ────────────────────────────────────────────────────
const sleep = ms => new Promise(r => setTimeout(r, ms));

function makeJobId() {
    return 'job_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
}

function extractNumbers(text) {
    text = text.replace(/^\uFEFF/, '').trim();
    const numbers = new Set();
    const lines   = text.split(/[\r\n]+/).filter(l => l.trim());
    if (!lines.length) return [];

    const commaLines = lines.slice(0, 15).filter(l => l.includes(',')).length;
    if (commaLines >= Math.min(3, lines.length)) {
        const rows   = lines.map(l => l.split(',').map(c => c.trim().replace(/['"]/g, '')));
        const scores = {};
        for (const row of rows.slice(1, 21)) {
            row.forEach((c, ci) => {
                const d = c.replace(/\D/g,'').replace(/^0+/,'');
                if (d.length >= 8 && d.length <= 15) scores[ci] = (scores[ci]||0) + 1;
            });
        }
        const best = Object.keys(scores).sort((a,b) => scores[b]-scores[a])[0];
        if (best !== undefined) {
            const start = rows[0] && !/\d{8}/.test(rows[0][best]||'') ? 1 : 0;
            for (let i = start; i < rows.length; i++) {
                const d = (rows[i][best]||'').replace(/\D/g,'').replace(/^0+/,'');
                if (d.length >= 8 && d.length <= 15) numbers.add(d);
            }
            return [...numbers];
        }
    }
    for (const part of text.split(/[\n\r,;\t\s]+/)) {
        const d = part.replace(/\D/g,'').replace(/^0+/,'');
        if (d.length >= 8 && d.length <= 15) numbers.add(d);
    }
    return [...numbers];
}

function getReadySessionsForUser(userId) {
    const prefix = `${userId}:`;
    return [...waSessions.entries()]
        .filter(([key, s]) => {
            if (!key.startsWith(prefix)) return false;
            if (!s?.socket || sessionCleanup.get(key)) return false;
            const ws = s.socket.ws;
            if (s.socket?.user && ws?.readyState === ws?.OPEN) return true;
            if (['connected','checking'].includes(s.state) && ws && ws.readyState !== ws?.CLOSED) return true;
            return false;
        })
        .map(([, s]) => ({ socket: s.socket, id: s.sessionId }));
}

function broadcastSessionsToUser(userId) {
    const sessions = db.prepare('SELECT * FROM wa_sessions WHERE user_id = ? ORDER BY id').all(userId);
    // Merge with live state
    const list = sessions.map(s => {
        const key  = `${userId}:${s.session_id}`;
        const live = waSessions.get(key);
        return {
            id:     s.session_id,
            phone:  live?.phone || s.phone || live?.pairingPhone || null,
            method: s.method,
            state:  live?.state || s.state,
        };
    });
    sendToUser(userId, 'sessions', { sessions: list });
}

// ─── WA SESSION: CREATE QR ────────────────────────────────────────
async function createQRSession(userId, sessionId, isReconnect = false) {
    const key     = `${userId}:${sessionId}`;
    const authDir = path.join(AUTH_DIR, String(userId), sessionId);
    if (sessionCleanup.get(key)) return;

    // Only wipe auth on a brand-new session, not on reconnects
    if (!isReconnect) {
        try { await fs.rm(authDir, { recursive: true, force: true }); } catch (_) {}
    }

    await fs.mkdir(authDir, { recursive: true });
    const { state, saveCreds } = await useMultiFileAuthState(authDir);

    // Preserve reconnect metadata (reconnectAttempts etc) from existing entry
    const existing = waSessions.get(key);
    waSessions.set(key, {
        sessionId, userId, saveCreds,
        socket: null,
        reconnecting: false,
        state: 'initializing',
        reconnectAttempts: existing?.reconnectAttempts || 0,
        pairingMethod: 'qr',
        phone: existing?.phone || null,
    });
    const si = waSessions.get(key);

    // Use same socket options as working Telegram bot
    const sock = makeWASocket({
        auth: state,
        logger,
        browser: [`WA Checker ${sessionId}`, 'Chrome', '131.0'],
        syncFullHistory: false,
        markOnlineOnConnect: false,
        defaultQueryTimeoutMs: 15000,
        keepAliveIntervalMs:   10000,
        retryRequestDelayMs:   500,
    });

    si.socket = sock;
    si.state  = 'connecting';
    db.prepare('UPDATE wa_sessions SET state=? WHERE session_id=? AND user_id=?').run('connecting', sessionId, userId);
    broadcastSessionsToUser(userId);

    sock.ev.on('creds.update', saveCreds);
    sock.ev.on('connection.update', async (update) => {
        if (sessionCleanup.get(key)) { try { sock.ev.removeAllListeners(); sock.end(); } catch (_) {} return; }
        const { connection, lastDisconnect, qr } = update;
        const s = waSessions.get(key);
        if (!s) return;

        if (qr) {
            try {
                const dataUrl = await qrcode.toDataURL(qr, { errorCorrectionLevel: 'H', margin: 2, width: 400 });
                sendToUser(userId, 'qr', { sessionId, qr: dataUrl });
                s.state = 'awaiting_scan';
                db.prepare('UPDATE wa_sessions SET state=? WHERE session_id=? AND user_id=?').run('awaiting_scan', sessionId, userId);
                broadcastSessionsToUser(userId);
            } catch (err) { console.error(`[QR] ${sessionId}:`, err.message); }
        }

        if (connection === 'open') {
            s.reconnecting = false;
            s.reconnectAttempts = 0;
            s.state = 'connected';
            s.phone = sock.user?.id?.split(':')[0] || 'linked';
            db.prepare('UPDATE wa_sessions SET state=?, phone=? WHERE session_id=? AND user_id=?').run('connected', s.phone, sessionId, userId);
            broadcastSessionsToUser(userId);
            sendToUser(userId, 'session_connected', { sessionId, phone: s.phone });
            sendToUser(userId, 'log', { level: 'success', msg: `${sessionId} connected — ${s.phone}` });
            sendToAdmins('admin_event', { event: 'session_connected', userId, sessionId, phone: s.phone });
        }

        if (connection === 'close') {
            const code   = lastDisconnect?.error?.output?.statusCode;
            const errMsg = lastDisconnect?.error?.message || '';
            s.state = 'disconnected';
            db.prepare('UPDATE wa_sessions SET state=? WHERE session_id=? AND user_id=?').run('disconnected', sessionId, userId);
            broadcastSessionsToUser(userId);

            const banned = code === DisconnectReason.loggedOut || code === 401 || code === 403 ||
                (code === 500 && (errMsg.includes('ban') || errMsg.includes('illegal')));
            if (banned) {
                sendToUser(userId, 'log', { level: 'error', msg: `${sessionId} logged out / banned — removed` });
                await deleteWASession(userId, sessionId);
                return;
            }
            s.reconnectAttempts = (s.reconnectAttempts || 0) + 1;
            if (s.reconnectAttempts <= 6) {
                const delay = [2000,4000,8000,15000,25000,30000][s.reconnectAttempts-1] || 30000;
                s.state = 'reconnecting';
                s.reconnecting = true;
                db.prepare('UPDATE wa_sessions SET state=? WHERE session_id=? AND user_id=?').run('reconnecting', sessionId, userId);
                broadcastSessionsToUser(userId);
                sendToUser(userId, 'log', { level: 'warn', msg: `${sessionId} reconnecting in ${delay/1000}s (${s.reconnectAttempts}/6)` });
                setTimeout(() => {
                    if (!sessionCleanup.get(key)) { waSessions.delete(key); createQRSession(userId, sessionId, true); }
                }, delay);
            } else {
                sendToUser(userId, 'log', { level: 'error', msg: `${sessionId} failed after 6 retries — removed` });
                await deleteWASession(userId, sessionId);
            }
        }
    });
}

// ─── WA SESSION: PHONE PAIRING ────────────────────────────────────
async function createPhoneSession(userId, sessionId, phoneNumber) {
    return new Promise((resolve) => {
        const key = `${userId}:${sessionId}`;
        if (sessionCleanup.get(key)) { resolve('ABORT'); return; }

        (async () => {
            try {
                const authDir = path.join(AUTH_DIR, String(userId), sessionId);
                await fs.mkdir(authDir, { recursive: true });

                const { state, saveCreds } = await useMultiFileAuthState(authDir);

                const sock = makeWASocket({
                    auth: state,
                    printQRInTerminal: false,
                    browser: ['Ubuntu', 'Chrome', '120.0.0.0'],
                    logger,
                    connectTimeoutMs:      45000,
                    keepAliveIntervalMs:   8000,
                    retryRequestDelayMs:   300,
                    defaultQueryTimeoutMs: 12000,
                });

                // Always fetch fresh si from map (set by runPhonePairingWithRetry before calling us)
                const si = waSessions.get(key);
                if (!si) { sock.end(); resolve('ABORT'); return; }

                si.socket    = sock;
                si.saveCreds = saveCreds;
                si.state     = 'connecting';
                broadcastSessionsToUser(userId);

                let codeRequested = false;
                let resolved      = false;
                const done = (val) => { if (resolved) return; resolved = true; resolve(val); };

                sock.ev.on('creds.update', saveCreds);

                sock.ev.on('connection.update', async (update) => {
                    if (sessionCleanup.get(key)) { sock.end(); done('ABORT'); return; }

                    const { connection, lastDisconnect } = update;
                    const s = waSessions.get(key);
                    if (!s) { sock.end(); done('ABORT'); return; }

                    if (connection === 'open') {
                        s.state = 'connected';
                        s.phone = sock.user?.id?.split(':')[0] || phoneNumber;
                        s.reconnectAttempts = 0;
                        db.prepare('UPDATE wa_sessions SET state=?, phone=? WHERE session_id=? AND user_id=?').run('connected', s.phone, sessionId, userId);
                        broadcastSessionsToUser(userId);
                        sendToUser(userId, 'session_connected', { sessionId, phone: s.phone });
                        sendToUser(userId, 'log', { level: 'success', msg: `${sessionId} connected — ${s.phone}` });
                        sendToAdmins('admin_event', { event: 'session_connected', userId, sessionId, phone: s.phone });
                        done(true);
                        return;
                    }

                    if (connection === 'close') {
                        const code = lastDisconnect?.error?.output?.statusCode;
                        sock.end();
                        if (code === 401) {
                            setTimeout(() => done('RESET'), 2000);
                            return;
                        }
                        if (code === 515 || code === 503) {
                            setTimeout(() => done(sessionCleanup.get(key) ? 'ABORT' : 'RETRY'), 5000);
                            return;
                        }
                        setTimeout(() => done(sessionCleanup.get(key) ? 'ABORT' : 'RETRY'), 4000);
                    }

                    if (!codeRequested && connection === 'connecting' && !sock.authState.creds.registered) {
                        codeRequested = true;
                        await sleep(1500);
                        try {
                            const code = await sock.requestPairingCode(phoneNumber);
                            if (code && !sessionCleanup.get(key)) {
                                const fmt = code.match(/.{1,4}/g)?.join('-') || code;
                                s.state = 'awaiting_scan';
                                db.prepare('UPDATE wa_sessions SET state=? WHERE session_id=? AND user_id=?').run('awaiting_scan', sessionId, userId);
                                broadcastSessionsToUser(userId);
                                sendToUser(userId, 'pairing_code', { sessionId, code: fmt, phone: phoneNumber });
                                sendToUser(userId, 'log', { level: 'info', msg: `Pairing code for ${sessionId}: ${fmt}` });
                            }
                        } catch (err) {
                            console.error('[requestPairingCode]', err.message);
                            sock.end();
                            done('RETRY');
                        }
                    }
                });

            } catch (err) {
                console.error('[createPhoneSession]', err.message);
                resolve('RESET');
            }
        })();
    });
}

async function runPhonePairingWithRetry(userId, sessionId, phoneNumber) {
    let shouldResetAuth = true;

    // Pre-set session in map before the loop — exactly like working bot pre-sets sessions.set()
    // This ensures waSessions.get(key) always succeeds inside createPhoneSession
    const key = `${userId}:${sessionId}`;
    if (!waSessions.has(key)) {
        waSessions.set(key, {
            sessionId, userId, socket: null, saveCreds: null,
            state: 'initializing', reconnectAttempts: 0,
            pairingMethod: 'phone', pairingPhone: phoneNumber, phone: null,
        });
    }

    while (!sessionCleanup.get(key)) {
        if (shouldResetAuth) {
            const authDir = path.join(AUTH_DIR, String(userId), sessionId);
            try { require('fs').rmSync(authDir, { recursive: true, force: true }); } catch (_) {}
            shouldResetAuth = false;
        }

        sendToUser(userId, 'log', { level: 'info', msg: `Pairing attempt for ${sessionId} (${phoneNumber})` });
        const result = await createPhoneSession(userId, sessionId, phoneNumber);

        if (result === true)    { break; }
        if (result === 'ABORT') { break; }
        if (result === 'RESET') { shouldResetAuth = true; await sleep(2000); continue; }
        if (result === 'RETRY') { await sleep(3000); continue; }
        break;
    }
}

async function deleteWASession(userId, sessionId) {
    const key = `${userId}:${sessionId}`;
    sessionCleanup.set(key, true);
    const info = waSessions.get(key);
    if (info?.socket) { try { info.socket.ev.removeAllListeners(); info.socket.end(); } catch (_) {} }
    waSessions.delete(key);
    db.prepare('DELETE FROM wa_sessions WHERE session_id=? AND user_id=?').run(sessionId, userId);
    try { await fs.rm(path.join(AUTH_DIR, String(userId), sessionId), { recursive: true, force: true }); } catch (_) {}
    await sleep(200);
    sessionCleanup.delete(key);
    broadcastSessionsToUser(userId);
    sendToUser(userId, 'log', { level: 'warn', msg: `Session ${sessionId} removed` });
}

async function restoreUserSessions(userId) {
    const sessions = db.prepare("SELECT * FROM wa_sessions WHERE user_id=? AND state NOT IN ('disconnected')").all(userId);
    for (const s of sessions) {
        const authDir = path.join(AUTH_DIR, String(userId), s.session_id);
        try {
            await fs.access(authDir);
            sendToUser(userId, 'log', { level: 'info', msg: `Restoring ${s.session_id}...` });
            createQRSession(userId, s.session_id, true); // isReconnect=true — preserve saved credentials
            await sleep(STARTUP_STAGGER_MS);
        } catch (_) {
            db.prepare('UPDATE wa_sessions SET state=? WHERE session_id=? AND user_id=?').run('disconnected', s.session_id, userId);
        }
    }
}

// ─── CHECKING ENGINE ─────────────────────────────────────────────
async function checkNumber(number, socket) {
    for (let i = 1; i <= MAX_CHECK_RETRIES; i++) {
        try {
            const [res] = await socket.onWhatsApp(`${number}@s.whatsapp.net`);
            if (!res?.exists) return 'not_registered';
            return res.lid ? 'registered_on_device' : 'registered_no_device';
        } catch { if (i < MAX_CHECK_RETRIES) await sleep(1000 * i); }
    }
    return null;
}

async function startUserJob(userId, jobId, numbersToCheck, jobMeta) {
    if (activeJobs.has(jobId)) return;

    const mode      = jobMeta.mode || 'new';
    const allReg    = [...(jobMeta.knownReg    || [])];
    const allNotReg = [...(jobMeta.knownNotReg || [])];
    let   unknown   = [...numbersToCheck];
    const total     = jobMeta.total || unknown.length;

    activeJobs.set(jobId, { userId, jobId, total, processed: 0, reg: allReg.length, notReg: allNotReg.length, mode, aborted: false });

    db.prepare('UPDATE jobs SET status=?,processed=?,registered=?,not_found=? WHERE job_id=?').run('running', 0, allReg.length, allNotReg.length, jobId);
    sendToUser(userId, 'job_start', { jobId, total, mode: mode.toUpperCase(), fromCache: jobMeta.fromCache || 0 });
    sendToUser(userId, 'log', { level: 'success', msg: `Job started — ${total} numbers — mode: ${mode.toUpperCase()}` });

    const jobStart = Date.now();
    let saveCount  = 0, noSessTick = 0;
    let freshReg   = [], freshNotReg = [];

    // Save pending state
    const pendingFile = path.join(PENDING_DIR, `${jobId}.json`);
    const savePending = async () => {
        await fs.writeFile(pendingFile, JSON.stringify({ jobId, userId, unknown: [...unknown], knownReg: allReg, knownNotReg: allNotReg, freshReg, freshNotReg, total, mode, filename: jobMeta.filename }, null, 2), 'utf8');
    };
    await savePending();

    try {
        while (unknown.length > 0) {
            const job = activeJobs.get(jobId);
            if (!job || job.aborted) {
                await savePending();
                db.prepare('UPDATE jobs SET status=?,processed=?,registered=?,not_found=? WHERE job_id=?').run('paused', allReg.length + allNotReg.length - (jobMeta.knownReg?.length || 0) - (jobMeta.knownNotReg?.length || 0), allReg.length, allNotReg.length, jobId);
                sendToUser(userId, 'job_stopped', { jobId, processed: allReg.length + allNotReg.length, total });
                return;
            }

            const ready = getReadySessionsForUser(userId);
            if (!ready.length) {
                noSessTick++;
                if (noSessTick >= 3) {
                    await savePending();
                    db.prepare('UPDATE jobs SET status=? WHERE job_id=?').run('paused', jobId);
                    sendToUser(userId, 'job_paused', { jobId });
                    sendToUser(userId, 'log', { level: 'warn', msg: 'All sessions offline — job paused. Resume when sessions reconnect.' });
                    activeJobs.delete(jobId);
                    return;
                }
                await sleep(3000); continue;
            }
            noSessTick = 0;

            const batchSize = Math.min(unknown.length, ready.length * CONCURRENCY_PER_SESSION, MAX_GLOBAL_CONCURRENT, BATCH_TARGET);
            const batch     = unknown.splice(0, batchSize);
            let   si        = 0;

            const results = await Promise.all(batch.map(num => {
                const sess = ready[si++ % ready.length];
                return (async () => {
                    await sleep(REQUEST_JITTER_MS * (0.4 + Math.random()));
                    try { return { num, result: await checkNumber(num, sess.socket) }; }
                    catch { return { num, result: null }; }
                })();
            }));

            const failed = [];
            for (const { num, result } of results) {
                if (result === null) { failed.push(num); continue; }
                if (result === 'registered_on_device')  { freshReg.push(`${num},on_device`);  allReg.push(`${num},on_device`); }
                else if (result === 'registered_no_device') { freshReg.push(`${num},no_device`); allReg.push(`${num},no_device`); }
                else { freshNotReg.push(num); allNotReg.push(num); }
                resultsCache.set(num, result);
                saveCount++;
            }

            unknown.unshift(...failed.filter(n => !resultsCache.has(n)));

            const totalDone = allReg.length + allNotReg.length;
            const pct       = ((totalDone / total) * 100).toFixed(1);
            const elapsed   = (Date.now() - jobStart) / 1000;
            const speed     = totalDone / Math.max(elapsed, 1);
            const eta       = speed > 0 ? Math.round(unknown.length / speed) : 0;
            const hitRate   = totalDone > 0 ? ((allReg.length / totalDone) * 100).toFixed(1) : '0.0';

            const jobState = activeJobs.get(jobId);
            if (jobState) { jobState.processed = totalDone; jobState.reg = allReg.length; jobState.notReg = allNotReg.length; }

            sendToUser(userId, 'progress', { jobId, processed: totalDone, total, pct, reg: allReg.length, notReg: allNotReg.length, eta, hitRate, sessions: ready.length });

            if (saveCount >= JOB_SAVE_INTERVAL) {
                saveCount = 0;
                await saveResultsDB();
                await savePending();
                db.prepare('UPDATE jobs SET processed=?,registered=?,not_found=? WHERE job_id=?').run(totalDone, allReg.length, allNotReg.length, jobId);
            }

            let delay = 200;
            if (failed.length / Math.max(batchSize, 1) > BACKOFF_FAIL_THRESHOLD) delay = 2000 + Math.random() * 1000;
            if (totalDone % COOLDOWN_EVERY_N < batchSize) delay += COOLDOWN_MS;
            await sleep(delay);
        }

        // Complete
        await saveResultsDB();
        try { await fs.unlink(pendingFile); } catch (_) {}
        db.prepare('UPDATE jobs SET status=?,processed=?,registered=?,not_found=?,completed_at=? WHERE job_id=?')
          .run('completed', allReg.length + allNotReg.length, allReg.length, allNotReg.length, new Date().toISOString(), jobId);
        activeJobs.delete(jobId);

        sendToUser(userId, 'job_complete', { jobId, total: allReg.length + allNotReg.length, reg: allReg.length, notReg: allNotReg.length, onDevice: allReg.filter(r => r.includes('on_device')).length, regData: allReg, notRegData: allNotReg });
        sendToUser(userId, 'log', { level: 'success', msg: `Job complete — ${allReg.length} registered, ${allNotReg.length} not found` });
        sendToAdmins('admin_event', { event: 'job_complete', userId, jobId, reg: allReg.length, notReg: allNotReg.length });

    } catch (err) {
        sendToUser(userId, 'log', { level: 'error', msg: `Fatal job error: ${err.message}` });
        db.prepare('UPDATE jobs SET status=? WHERE job_id=?').run('failed', jobId);
        activeJobs.delete(jobId);
    } finally {
        for (const [key, s] of waSessions) {
            if (key.startsWith(`${userId}:`) && s.state === 'checking') s.state = 'connected';
        }
        broadcastSessionsToUser(userId);
    }
}

async function resumeUserJob(userId, jobId) {
    const pendingFile = path.join(PENDING_DIR, `${jobId}.json`);
    let state;
    try { state = JSON.parse(await fs.readFile(pendingFile, 'utf8')); }
    catch { sendToUser(userId, 'log', { level: 'warn', msg: 'No pending state found for job' }); return; }

    if (activeJobs.has(jobId)) { sendToUser(userId, 'log', { level: 'warn', msg: 'Job already running' }); return; }

    const unknown = (state.unknown || []).filter(n => !resultsCache.has(n));
    if (!unknown.length) {
        try { await fs.unlink(pendingFile); } catch (_) {}
        db.prepare('UPDATE jobs SET status=?,completed_at=? WHERE job_id=?').run('completed', new Date().toISOString(), jobId);
        sendToUser(userId, 'job_complete', { jobId, total: (state.knownReg||[]).length + (state.freshReg||[]).length + (state.knownNotReg||[]).length + (state.freshNotReg||[]).length, reg: (state.knownReg||[]).length + (state.freshReg||[]).length, notReg: (state.knownNotReg||[]).length + (state.freshNotReg||[]).length, regData: [...(state.knownReg||[]),...(state.freshReg||[])], notRegData: [...(state.knownNotReg||[]),...(state.freshNotReg||[])] });
        return;
    }

    sendToUser(userId, 'log', { level: 'info', msg: `Resuming job — ${unknown.length} numbers remaining` });
    startUserJob(userId, jobId, unknown, { ...state, mode: 'resume' });
}

// ─── EXPRESS ──────────────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false, cookie: { maxAge: 7 * 24 * 3600 * 1000 } }));
// Auto-detect whether HTML files are in /public subfolder or root
const PUBLIC_DIR = (() => {
    const sub = path.join(__dirname, 'public');
    try { require('fs').statSync(path.join(sub, 'login.html')); return sub; } catch (_) {}
    return __dirname;
})();
app.use(express.static(PUBLIC_DIR));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024 } });

// Auth middleware
function requireAuth(req, res, next) {
    if (req.session?.user) return next();
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not authenticated' });
    res.redirect('/login.html');
}

function requireAdmin(req, res, next) {
    if (req.session?.user?.role === 'admin') return next();
    if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Admin only' });
    res.redirect('/');
}

app.use(['/api/user', '/api/admin', '/api/sessions', '/api/job', '/api/db', '/dashboard.html', '/admin.html'], requireAuth);
app.use('/api/admin', requireAdmin);

// ─── WEBSOCKET ────────────────────────────────────────────────────
wss.on('connection', (ws, req) => {
    // Extract session from cookie
    const cookieHeader = req.headers.cookie || '';
    const sidMatch     = cookieHeader.match(/connect\.sid=s%3A([^.;]+)/);
    if (!sidMatch) { ws.close(); return; }

    // We'll authenticate via first message
    ws.on('message', (raw) => {
        try {
            const msg = JSON.parse(raw);
            if (msg.type === 'auth' && msg.userId) {
                ws.userId = msg.userId;
                if (!wsClients.has(msg.userId)) wsClients.set(msg.userId, new Set());
                wsClients.get(msg.userId).add(ws);
                broadcastSessionsToUser(msg.userId);
                ws.send(JSON.stringify({ type: 'authed' }));
            }
        } catch (_) {}
    });

    ws.on('close', () => {
        if (ws.userId) {
            const set = wsClients.get(ws.userId);
            if (set) { set.delete(ws); if (!set.size) wsClients.delete(ws.userId); }
        }
    });
    ws.on('error', () => ws.close());
});

// ─── AUTH ROUTES ──────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
    const { email, username, password } = req.body;
    if (!email || !username || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: 'Username: 3-20 chars, letters/numbers/underscore only' });

    try {
        const hash = await bcrypt.hash(password, 10);
        const info = db.prepare('INSERT INTO users (email, username, password) VALUES (?,?,?)').run(email.toLowerCase(), username, hash);
        const user = db.prepare('SELECT id, email, username, role FROM users WHERE id=?').get(info.lastInsertRowid);
        req.session.user = user;
        res.json({ ok: true, user });
    } catch (e) {
        if (e.message.includes('UNIQUE')) res.status(409).json({ error: 'Email or username already taken' });
        else res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email=?').get((email||'').toLowerCase());
    if (!user || !await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid email or password' });
    if (user.banned) return res.status(403).json({ error: 'Account suspended. Contact admin.' });
    db.prepare('UPDATE users SET last_login=? WHERE id=?').run(new Date().toISOString(), user.id);
    req.session.user = { id: user.id, email: user.email, username: user.username, role: user.role };
    res.json({ ok: true, user: req.session.user });
    // Restore sessions in background
    restoreUserSessions(user.id);
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy();
    res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
    res.json(req.session.user);
});

// ─── USER ROUTES ──────────────────────────────────────────────────
app.get('/api/user/sessions', requireAuth, (req, res) => {
    const userId   = req.session.user.id;
    const sessions = db.prepare('SELECT * FROM wa_sessions WHERE user_id=? ORDER BY id').all(userId);
    const list = sessions.map(s => {
        const key  = `${userId}:${s.session_id}`;
        const live = waSessions.get(key);
        return { id: s.session_id, phone: live?.phone || s.phone || live?.pairingPhone || null, method: s.method, state: live?.state || s.state };
    });
    res.json(list);
});

app.post('/api/user/sessions/add-qr', requireAuth, async (req, res) => {
    const userId  = req.session.user.id;
    const current = db.prepare('SELECT COUNT(*) as cnt FROM wa_sessions WHERE user_id=?').get(userId).cnt;
    if (current >= MAX_SESSIONS_PER_USER) return res.status(429).json({ error: `Max ${MAX_SESSIONS_PER_USER} sessions allowed` });
    const count     = db.prepare('SELECT COUNT(*) as cnt FROM wa_sessions WHERE user_id=?').get(userId).cnt;
    const sessionId = `wa${count + 1}_${crypto.randomBytes(2).toString('hex')}`;
    db.prepare('INSERT INTO wa_sessions (session_id, user_id, method, state) VALUES (?,?,?,?)').run(sessionId, userId, 'qr', 'initializing');
    res.json({ ok: true, sessionId });
    createQRSession(userId, sessionId);
});

app.post('/api/user/sessions/add-phone', requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    const phone  = (req.body.phone || '').replace(/\D/g, '');
    if (phone.length < 8) return res.status(400).json({ error: 'Invalid phone number' });
    const current = db.prepare('SELECT COUNT(*) as cnt FROM wa_sessions WHERE user_id=?').get(userId).cnt;
    if (current >= MAX_SESSIONS_PER_USER) return res.status(429).json({ error: `Max ${MAX_SESSIONS_PER_USER} sessions allowed` });
    const count     = db.prepare('SELECT COUNT(*) as cnt FROM wa_sessions WHERE user_id=?').get(userId).cnt;
    const sessionId = `wa${count + 1}_${crypto.randomBytes(2).toString('hex')}`;
    db.prepare('INSERT INTO wa_sessions (session_id, user_id, method, state) VALUES (?,?,?,?)').run(sessionId, userId, 'phone', 'initializing');
    res.json({ ok: true, sessionId });
    runPhonePairingWithRetry(userId, sessionId, phone);
});

app.delete('/api/user/sessions/:id', requireAuth, async (req, res) => {
    const userId    = req.session.user.id;
    const sessionId = req.params.id;
    const existing  = db.prepare('SELECT id FROM wa_sessions WHERE session_id=? AND user_id=?').get(sessionId, userId);
    if (!existing) return res.status(404).json({ error: 'Session not found' });
    await deleteWASession(userId, sessionId);
    res.json({ ok: true });
});

app.post('/api/user/upload', requireAuth, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const content = req.file.buffer.toString('utf8');
    const numbers = extractNumbers(content);
    if (!numbers.length) return res.status(400).json({ error: 'No valid phone numbers found' });

    const { known, unknown } = lookupNumbers(numbers);
    const knownReg    = known.filter(k => k.result !== 'not_registered').map(k => `${k.num},${k.result === 'registered_on_device' ? 'on_device' : 'no_device'}`);
    const knownNotReg = known.filter(k => k.result === 'not_registered').map(k => k.num);

    res.json({
        ok: true,
        total:      numbers.length,
        unknown:    unknown.length,
        fromCache:  known.length,
        knownReg:   knownReg.length,
        knownNotReg:knownNotReg.length,
        jobData: { allNumbers: numbers, unknown, knownReg, knownNotReg, freshReg: [], freshNotReg: [], filename: req.file.originalname }
    });
});

app.post('/api/user/job/start', requireAuth, async (req, res) => {
    const userId  = req.session.user.id;
    const { jobData, mode } = req.body;
    if (!jobData) return res.status(400).json({ error: 'No job data' });

    const jobId   = makeJobId();
    const numbers = mode === 'all' ? jobData.allNumbers : jobData.unknown;
    const total   = mode === 'all' ? jobData.allNumbers.length : jobData.allNumbers.length;
    const meta    = mode === 'all' ? { ...jobData, knownReg: [], knownNotReg: [], freshReg: [], freshNotReg: [], total, mode, fromCache: 0 } : { ...jobData, total, mode, fromCache: jobData.fromCache || 0 };

    db.prepare('INSERT INTO jobs (job_id, user_id, filename, total, status, mode, from_cache) VALUES (?,?,?,?,?,?,?)').run(jobId, userId, jobData.filename || 'upload', total, 'running', mode, meta.fromCache || 0);

    res.json({ ok: true, jobId });
    startUserJob(userId, jobId, numbers, meta);
});

app.post('/api/user/job/:jobId/stop', requireAuth, (req, res) => {
    const job = activeJobs.get(req.params.jobId);
    if (job && job.userId === req.session.user.id) job.aborted = true;
    res.json({ ok: true });
});

app.post('/api/user/job/:jobId/resume', requireAuth, async (req, res) => {
    const userId = req.session.user.id;
    const jobId  = req.params.jobId;
    const dbJob  = db.prepare('SELECT * FROM jobs WHERE job_id=? AND user_id=?').get(jobId, userId);
    if (!dbJob) return res.status(404).json({ error: 'Job not found' });
    res.json({ ok: true });
    resumeUserJob(userId, jobId);
});

app.get('/api/user/jobs', requireAuth, (req, res) => {
    const jobs = db.prepare('SELECT * FROM jobs WHERE user_id=? ORDER BY created_at DESC LIMIT 50').all(req.session.user.id);
    // Merge with active state
    const enriched = jobs.map(j => {
        const live = activeJobs.get(j.job_id);
        return live ? { ...j, status: 'running', processed: live.processed, registered: live.reg, not_found: live.notReg } : j;
    });
    res.json(enriched);
});

app.get('/api/user/job/:jobId/status', requireAuth, (req, res) => {
    const live = activeJobs.get(req.params.jobId);
    if (live && live.userId === req.session.user.id) return res.json({ running: true, ...live });
    const job = db.prepare('SELECT * FROM jobs WHERE job_id=? AND user_id=?').get(req.params.jobId, req.session.user.id);
    if (!job) return res.status(404).json({ error: 'Not found' });
    res.json({ running: false, ...job });
});

// ─── DB ROUTES (user read, admin write) ───────────────────────────
app.get('/api/db/stats', requireAuth, (req, res) => {
    let reg = 0, notReg = 0, onDev = 0;
    for (const v of resultsCache.values()) {
        if (v === 'not_registered') notReg++;
        else { reg++; if (v === 'registered_on_device') onDev++; }
    }
    res.json({ total: resultsCache.size, registered: reg, notRegistered: notReg, onDevice: onDev, noDevice: reg - onDev });
});

app.get('/api/db/export', requireAuth, (req, res) => {
    const type = req.query.type || 'registered';
    const lines = [];
    for (const [num, v] of resultsCache) {
        if (type === 'not_registered' && v === 'not_registered') lines.push(num);
        else if (type === 'registered' && v !== 'not_registered') lines.push(`${num},${v === 'registered_on_device' ? 'On Device' : 'No Device'}`);
    }
    const header   = type === 'not_registered' ? 'Number' : 'Number,Device Status';
    const filename = type === 'not_registered' ? 'not_registered.csv' : 'registered.csv';
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'text/csv');
    res.send(header + '\n' + lines.join('\n'));
});

app.get('/api/db/download', requireAdmin, (req, res) => {
    res.setHeader('Content-Disposition', 'attachment; filename="results_db.json"');
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(Object.fromEntries(resultsCache), null, 2));
});

app.post('/api/db/import', requireAdmin, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    try {
        const incoming = JSON.parse(req.file.buffer.toString('utf8'));
        let added = 0;
        for (const [k, v] of Object.entries(incoming)) {
            if (!resultsCache.has(k)) { resultsCache.set(k, v); added++; }
        }
        await saveResultsDB();
        res.json({ ok: true, added, total: resultsCache.size });
    } catch (e) { res.status(400).json({ error: 'Invalid JSON: ' + e.message }); }
});

// ─── ADMIN ROUTES ─────────────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, (req, res) => {
    const users = db.prepare('SELECT id, email, username, role, banned, created_at, last_login FROM users ORDER BY created_at DESC').all();
    const enriched = users.map(u => ({
        ...u,
        sessions:   db.prepare('SELECT COUNT(*) as cnt FROM wa_sessions WHERE user_id=?').get(u.id).cnt,
        jobs:       db.prepare('SELECT COUNT(*) as cnt FROM jobs WHERE user_id=?').get(u.id).cnt,
        activeJobs: [...activeJobs.values()].filter(j => j.userId === u.id).length,
        online:     (wsClients.get(u.id)?.size || 0) > 0,
    }));
    res.json(enriched);
});

app.post('/api/admin/users/:id/ban', requireAdmin, (req, res) => {
    const { id } = req.params;
    db.prepare('UPDATE users SET banned=1 WHERE id=?').run(id);
    // Kill active jobs
    for (const [jobId, job] of activeJobs) { if (job.userId === parseInt(id)) job.aborted = true; }
    res.json({ ok: true });
});

app.post('/api/admin/users/:id/unban', requireAdmin, (req, res) => {
    db.prepare('UPDATE users SET banned=0 WHERE id=?').run(req.params.id);
    res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
    const userId = parseInt(req.params.id);
    if (userId === req.session.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
    // Kill jobs
    for (const [, job] of activeJobs) { if (job.userId === userId) job.aborted = true; }
    // Delete sessions
    const sessions = db.prepare('SELECT session_id FROM wa_sessions WHERE user_id=?').all(userId);
    for (const { session_id } of sessions) await deleteWASession(userId, session_id).catch(() => {});
    db.prepare('DELETE FROM jobs WHERE user_id=?').run(userId);
    db.prepare('DELETE FROM wa_sessions WHERE user_id=?').run(userId);
    db.prepare('DELETE FROM users WHERE id=?').run(userId);
    try { await fs.rm(path.join(AUTH_DIR, String(userId)), { recursive: true, force: true }); } catch (_) {}
    res.json({ ok: true });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
    res.json({
        users:       db.prepare('SELECT COUNT(*) as n FROM users').get().n,
        activeUsers: wsClients.size,
        jobs:        db.prepare('SELECT COUNT(*) as n FROM jobs').get().n,
        runningJobs: activeJobs.size,
        dbEntries:   resultsCache.size,
        sessions:    db.prepare('SELECT COUNT(*) as n FROM wa_sessions').get().n,
    });
});

app.get('/api/admin/jobs', requireAdmin, (req, res) => {
    const jobs = db.prepare(`
        SELECT j.*, u.username, u.email FROM jobs j
        JOIN users u ON j.user_id = u.id
        ORDER BY j.created_at DESC LIMIT 100
    `).all();
    res.json(jobs);
});

// ─── SERVE PAGES ─────────────────────────────────────────────────
app.get('/',              (req, res) => res.redirect(req.session?.user ? '/dashboard.html' : '/login.html'));
app.get('/login.html',    (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'login.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'register.html')));
app.get('/dashboard.html',requireAuth, (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'dashboard.html')));
app.get('/admin.html',    requireAdmin, (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));

// ─── START ────────────────────────────────────────────────────────
process.on('unhandledRejection', r => console.warn('[UnhandledRejection]', r));
process.on('uncaughtException',  e => console.error('[UncaughtException]',  e));
process.on('SIGINT',  () => { saveResultsDB().finally(() => process.exit(0)); });
process.on('SIGTERM', () => { saveResultsDB().finally(() => process.exit(0)); });

async function main() {
    initDB();
    await loadResultsDB();
    console.log(`📊 Results DB loaded: ${resultsCache.size} entries`);

    server.listen(PORT, () => {
        console.log(`✅ WA Checker Platform running on port ${PORT}`);
        console.log(`👑 Admin: ${ADMIN_EMAIL}`);
    });
}

main().catch(e => { console.error('[FATAL]', e); process.exit(1); });
