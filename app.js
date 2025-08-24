
// app.js: Express + mysql2 (raw SQL). No ORM/Redis/cron.
const express = require('express');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
app.use(express.json());

// Config
const PORT = process.env.PORT || 3000;
const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'yourpassword',
  database: process.env.DB_NAME || 'otp_service',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Constants
const USER_LIMIT = 3;
const IP_LIMIT = 8;
const WINDOW_SECONDS = 15 * 60;
const OTP_TTL_SECONDS = 5 * 60;
const MAX_WRONG_ATTEMPTS = 3;
const VERIFY_LOCK_SECONDS = 10 * 60;

// Helpers
const sha256hex = s => crypto.createHash('sha256').update(s).digest('hex');
const binUUID = u => Buffer.from(u.replace(/-/g, ''), 'hex');
const gen6Digit = () => String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');

async function getRateLimitInfo(conn, { user_id, ip }) {
  const [uRows] = await conn.execute(
    `SELECT COUNT(*) AS cnt FROM request_logs
      WHERE user_id = ? AND created_at > (NOW() - INTERVAL ? SECOND)`,
    [user_id, WINDOW_SECONDS]
  );
  const userCount = uRows[0].cnt;

  const [ipRows] = await conn.execute(
    `SELECT COUNT(*) AS cnt FROM request_logs
      WHERE ip = INET6_ATON(?) AND created_at > (NOW() - INTERVAL ? SECOND)`,
    [ip, WINDOW_SECONDS]
  );
  const ipCount = ipRows[0].cnt;

  let userRemaining = 0, ipRemaining = 0;
  if (userCount >= USER_LIMIT) {
    const [r] = await conn.execute(
      `SELECT GREATEST(0, ? - TIMESTAMPDIFF(SECOND, MIN(created_at), NOW())) AS remaining
         FROM (SELECT created_at FROM request_logs
               WHERE user_id = ? AND created_at > (NOW() - INTERVAL ? SECOND)
               ORDER BY created_at ASC LIMIT ?) t`,
      [WINDOW_SECONDS, user_id, WINDOW_SECONDS, USER_LIMIT]
    );
    userRemaining = r[0].remaining || 0;
  }
  if (ipCount >= IP_LIMIT) {
    const [r] = await conn.execute(
      `SELECT GREATEST(0, ? - TIMESTAMPDIFF(SECOND, MIN(created_at), NOW())) AS remaining
         FROM (SELECT created_at FROM request_logs
               WHERE ip = INET6_ATON(?) AND created_at > (NOW() - INTERVAL ? SECOND)
               ORDER BY created_at ASC LIMIT ?) t`,
      [WINDOW_SECONDS, ip, WINDOW_SECONDS, IP_LIMIT]
    );
    ipRemaining = r[0].remaining || 0;
  }
  return { userCount, ipCount, userRemaining, ipRemaining };
}

// POST /otp/request
app.post('/otp/request', async (req, res) => {
  const idemp = req.header('Idempotency-Key');
  const { user_id, purpose } = req.body || {};
  if (!idemp) return res.status(400).json({ reason: 'idempotency_key_required' });
  if (!user_id || !purpose) return res.status(400).json({ reason: 'missing_params' });

  const ip = (req.headers['x-forwarded-for']?.split(',')[0] || req.ip || req.socket.remoteAddress || '127.0.0.1').trim();

  const conn = await pool.getConnection();
  try {
    // Idempotency short-circuit
    const [ide] = await conn.execute(
      `SELECT response_json FROM idempotency_keys WHERE idempotency_key = ? AND expires_at > NOW() LIMIT 1`,
      [idemp]
    );
    if (ide.length) return res.status(200).json(JSON.parse(ide[0].response_json));

    // Rate limits (DB time)
    const rl = await getRateLimitInfo(conn, { user_id, ip });
    if (rl.userCount >= USER_LIMIT) return res.status(429).json({ reason: 'rate_limit_user', retry_after: rl.userRemaining });
    if (rl.ipCount >= IP_LIMIT) return res.status(429).json({ reason: 'rate_limit_ip', retry_after: rl.ipRemaining });

    await conn.beginTransaction();

    // Single active OTP enforcement
    const [active] = await conn.execute(
      `SELECT id, expires_at FROM otps WHERE user_id=? AND purpose=? AND is_active=1 FOR UPDATE`,
      [user_id, purpose]
    );

    let resp, status = 200;
    if (active.length) {
      const otpId = active[0].id;
      const [ttlR] = await conn.execute(
        `SELECT GREATEST(0, UNIX_TIMESTAMP(expires_at) - UNIX_TIMESTAMP(NOW())) AS ttl FROM otps WHERE id=? LIMIT 1`,
        [otpId]
      );
      resp = {
        otp_id: otpId.toString('hex'),
        ttl: ttlR[0].ttl,
        remaining_requests: Math.max(0, USER_LIMIT - (rl.userCount + 1))
      };
    } else {
      const otpPlain = gen6Digit();
      const otpHash = sha256hex(otpPlain);
      const idBuf = binUUID(uuidv4());
      await conn.execute(
        `INSERT INTO otps (id, user_id, purpose, code_hash, created_at, expires_at, is_active)
         VALUES (?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL ? SECOND), 1)`,
        [idBuf, user_id, purpose, otpHash, OTP_TTL_SECONDS]
      );
      const [ttlR] = await conn.execute(
        `SELECT GREATEST(0, UNIX_TIMESTAMP(expires_at) - UNIX_TIMESTAMP(NOW())) AS ttl FROM otps WHERE id=? LIMIT 1`,
        [idBuf]
      );
      resp = {
        otp_id: idBuf.toString('hex'),
        ttl: ttlR[0].ttl,
        remaining_requests: Math.max(0, USER_LIMIT - (rl.userCount + 1))
      };
      status = 201;
      // For local testing convenience ONLY (do not log OTP in prod)
      console.log(`OTP for user=${user_id} purpose=${purpose} -> ${otpPlain} (id=${resp.otp_id})`);
    }

    // Save idempotency (10m) + log request
    await conn.execute(
      `INSERT INTO idempotency_keys (idempotency_key, user_id, purpose, otp_id, response_json, expires_at)
       VALUES (?, ?, ?, UNHEX(?), ?, DATE_ADD(NOW(), INTERVAL 600 SECOND))
       ON DUPLICATE KEY UPDATE response_json=VALUES(response_json), expires_at=VALUES(expires_at)`,
      [idemp, user_id, purpose, resp.otp_id, JSON.stringify(resp)]
    );
    await conn.execute(
      `INSERT INTO request_logs (user_id, ip) VALUES (?, INET6_ATON(?))`,
      [user_id, ip]
    );

    await conn.commit();
    return res.status(status).json(resp);
  } catch (e) {
    await conn.rollback().catch(()=>{});
    console.error(e);
    return res.status(500).json({ reason: 'internal_error' });
  } finally {
    conn.release();
  }
});

// POST /otp/verify
app.post('/otp/verify', async (req, res) => {
  const { user_id, purpose, otp_id, code } = req.body || {};
  if (!user_id || !purpose || !otp_id || !code) return res.status(400).json({ reason: 'missing_params' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Check lock
    const [locks] = await conn.execute(
      `SELECT GREATEST(0, TIMESTAMPDIFF(SECOND, NOW(), lock_until)) AS remaining
         FROM verification_locks
        WHERE user_id=? AND purpose=? AND lock_until>NOW()
        LIMIT 1`,
      [user_id, purpose]
    );
    if (locks.length) {
      await conn.rollback();
      return res.status(429).json({ reason: 'verification_locked', retry_after: locks[0].remaining });
    }

    const idBuf = Buffer.from(otp_id, 'hex');
    const [rows] = await conn.execute(
      `SELECT id, user_id, purpose, code_hash, expires_at, is_active, wrong_attempts, used_at
         FROM otps WHERE id=? FOR UPDATE`,
      [idBuf]
    );
    if (!rows.length) {
      await conn.rollback();
      return res.status(404).json({ reason: 'otp_not_found' });
    }
    const otp = rows[0];
    if (otp.user_id !== user_id || otp.purpose !== purpose) {
      await conn.rollback();
      return res.status(400).json({ reason: 'mismatched_context' });
    }
    if (otp.is_active === 0 || otp.used_at !== null) {
      await conn.rollback();
      return res.status(410).json({ reason: 'code_used' });
    }

    const [exp] = await conn.execute(
      `SELECT expires_at <= NOW() AS expired FROM otps WHERE id=? LIMIT 1`,
      [idBuf]
    );
    if (exp[0].expired) {
      await conn.execute(`UPDATE otps SET is_active=0 WHERE id=?`, [idBuf]);
      await conn.commit();
      return res.status(410).json({ reason: 'code_expired' });
    }

    // Compare
    const providedHash = sha256hex(code);
    if (providedHash !== otp.code_hash) {
      await conn.execute(`UPDATE otps SET wrong_attempts = wrong_attempts + 1 WHERE id=?`, [idBuf]);
      const [after] = await conn.execute(`SELECT wrong_attempts FROM otps WHERE id=?`, [idBuf]);
      const attempts = after[0].wrong_attempts;
      if (attempts >= MAX_WRONG_ATTEMPTS) {
        await conn.execute(`UPDATE otps SET is_active=0 WHERE id=?`, [idBuf]);
        await conn.execute(
          `INSERT INTO verification_locks (user_id, purpose, lock_until)
             VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))
           ON DUPLICATE KEY UPDATE lock_until = GREATEST(lock_until, DATE_ADD(NOW(), INTERVAL ? SECOND))`,
          [user_id, purpose, VERIFY_LOCK_SECONDS, VERIFY_LOCK_SECONDS]
        );
        await conn.commit();
        return res.status(429).json({ reason: 'verification_locked', retry_after: VERIFY_LOCK_SECONDS });
      }
      await conn.commit();
      return res.status(401).json({ reason: 'invalid_code', remaining_attempts: MAX_WRONG_ATTEMPTS - attempts });
    }

    // Success
    await conn.execute(`UPDATE otps SET is_active=0, used_at=NOW() WHERE id=?`, [idBuf]);
    await conn.commit();
    return res.status(200).json({ status: 'verified' });
  } catch (e) {
    await conn.rollback().catch(()=>{});
    console.error(e);
    return res.status(500).json({ reason: 'internal_error' });
  } finally {
    conn.release();
  }
});

app.listen(PORT, () => console.log(`OTP service listening on :${PORT}`));
