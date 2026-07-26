const crypto = require('crypto');

const SUPABASE_URL = 'https://roofompdejyndlpqfrjl.supabase.co';
const TABLE        = 'visitor_logs_cityofgod';
const SESSION_TTL  = 8 * 60 * 60 * 1000;

function sbHeaders() {
  const key = process.env.SUPABASE_SERVICE_KEY || '';
  return { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' };
}

function makeSession() {
  const secret  = process.env.SESSION_SECRET || 'cog-secret';
  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + SESSION_TTL })).toString('base64');
  const sig     = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function checkSession(token) {
  if (!token) return false;
  const dot = token.lastIndexOf('.');
  if (dot < 0) return false;
  const payload = token.slice(0, dot);
  const sig     = token.slice(dot + 1);
  const secret  = process.env.SESSION_SECRET || 'cog-secret';
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return false;
    const data = JSON.parse(Buffer.from(payload, 'base64').toString());
    return Date.now() < data.exp;
  } catch { return false; }
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const body   = req.body || {};
  const action = body.action;

  /* ── LOGIN ── */
  if (action === 'login') {
    const adminPass = process.env.ADMIN_PASSWORD || '';
    if (!adminPass) return res.status(503).json({ error: 'ADMIN_PASSWORD not set in Vercel environment variables.' });
    if (body.password === adminPass) return res.status(200).json({ token: makeSession() });
    return res.status(401).json({ error: 'Incorrect password.' });
  }

  /* ── AUTH CHECK ── */
  const authHeader = req.headers['authorization'] || '';
  const token      = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!checkSession(token)) return res.status(401).json({ error: 'Session expired — please log in again.' });

  if (!process.env.SUPABASE_SERVICE_KEY)
    return res.status(503).json({ error: 'SUPABASE_SERVICE_KEY not set in Vercel environment variables.' });

  /* ── LIST RECORDS (date range) ── */
  if (action === 'list') {
    const from = body.date_from || new Date().toISOString().slice(0, 10);
    const to   = body.date_to   || from;
    const url  = `${SUPABASE_URL}/rest/v1/${TABLE}?signed_in_at=gte.${from}T00:00:00&signed_in_at=lte.${to}T23:59:59&order=signed_in_at.desc&limit=1000`;
    const r    = await fetch(url, { headers: sbHeaders() });
    const data = await r.json();
    return res.status(r.status).json(data);
  }

  /* ── ADMIN SIGN OUT ── */
  if (action === 'signout') {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/${TABLE}?id=eq.${body.id}`, {
      method: 'PATCH',
      headers: { ...sbHeaders(), Prefer: 'return=representation' },
      body: JSON.stringify({ signed_out_at: new Date().toISOString() })
    });
    const data = await r.json();
    return res.status(r.status).json(data);
  }

  /* ── DELETE RECORD ── */
  if (action === 'delete') {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/${TABLE}?id=eq.${body.id}`, {
      method: 'DELETE', headers: sbHeaders()
    });
    return res.status(r.status).json({ ok: r.ok });
  }

  return res.status(400).json({ error: `Unknown action: ${action}` });
};
