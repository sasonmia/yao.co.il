// Yuli API – AWS Lambda (HTTP API payload v2) + DynamoDB + SES.
// Accounts: username + password. New accounts are "pending" until the site owner approves by email.
// DynamoDB item fields (all English): user, name, salt, hash, status, freeAccess, created, lastLogin,
//   stars, log, weak, fails, lockUntil, v
import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
const TOKEN_TTL_S = 30 * 24 * 3600;
const DECIDE_TTL_S = 14 * 24 * 3600;
const ACTIVE_MS = 30 * 24 * 3600 * 1000; // "active" = logged in during the last 30 days
const MAX_FAILS = 5;
const LOCK_MS = 5 * 60 * 1000;
const MAX_LOG = 300;
const MAX_WEAK = 200;
const KEY_RE = /^[a-z0-9_]{1,12}$/;
const WORD_RE = /^[A-Za-z0-9' ,.?!-]{1,40}$/;
const STATUSES = ['pending', 'approved', 'rejected'];
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export function makeHandler({ store, secret, adminKey = '', notifier = null, now = () => Date.now() }) {
  const json = (code, obj) => ({
    statusCode: code,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    body: JSON.stringify(obj),
  });
  const page = (code, title, body) => ({
    statusCode: code,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY' },
    body: `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>body{font-family:system-ui,Arial;max-width:520px;margin:12vh auto;padding:0 16px;text-align:center}button{font-size:18px;padding:10px 24px;border-radius:8px;border:0;background:#2563eb;color:#fff;cursor:pointer}</style></head><body>${body}</body></html>`,
  });

  const b64 = (s) => Buffer.from(s).toString('base64url');
  const mac = (p) => crypto.createHmac('sha256', secret).update(p).digest('base64url');
  const seal = (obj) => { const p = b64(JSON.stringify(obj)); return p + '.' + mac(p); };
  const unseal = (t) => {
    if (!t || typeof t !== 'string' || !t.includes('.')) return null;
    const [p, s] = t.split('.');
    const a = Buffer.from(s || ''), b = Buffer.from(mac(p));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.e > now() / 1000 ? o : null; } catch { return null; }
  };
  const exp = (ttl) => Math.floor(now() / 1000) + ttl;
  const sessionToken = (user) => seal({ k: 's', u: user, e: exp(TOKEN_TTL_S) });
  const sessionUser = (t) => { const o = unseal(t); return o && o.k === 's' ? o.u : null; };
  const decideToken = (user, action) => seal({ k: 'd', u: user, a: action, e: exp(DECIDE_TTL_S) });

  const norm = (n) => String(n ?? '').normalize('NFC').replace(/\s+/g, ' ').trim();
  const keyOf = (n) => norm(n).toLowerCase();
  const validName = (n) => { n = norm(n); return n.length >= 2 && n.length <= 20 && !/[<>&"'\\/]/.test(n); };
  const validPassword = (p) => typeof p === 'string' && p.length >= 6 && p.length <= 64;
  const hashPw = async (pw, salt) => (await scrypt(pw, salt, 32)).toString('hex');
  const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

  const publicView = (it) => ({
    name: it.name,
    stars: it.stars || {},
    created: it.created,
    updated: it.updated,
    log: (it.log || []).slice(-50),
    weak: Object.entries(it.weak || {}).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([w, n]) => ({ w, n })),
  });
  const adminRow = (it) => ({
    username: it.name,
    status: it.status || 'approved',
    active: !!it.lastLogin && now() - it.lastLogin <= ACTIVE_MS,
    freeAccess: !!it.freeAccess,
    created: it.created || null,
    lastLogin: it.lastLogin || null,
    totalStars: Object.values(it.stars || {}).reduce((a, b) => a + b, 0),
  });

  async function mutate(user, fn) {
    for (let i = 0; i < 4; i++) {
      const it = await store.get(user);
      if (!it) return null;
      const next = JSON.parse(JSON.stringify(it));
      fn(next);
      next.updated = now();
      next.v = it.v + 1;
      if (await store.put(next, it.v)) return next;
    }
    throw new Error('conflict');
  }

  async function register(body, event) {
    const name = norm(body.username);
    if (!validName(name) || !validPassword(body.password)) return json(400, { error: 'bad_input' });
    const user = keyOf(name);
    const salt = crypto.randomBytes(16).toString('hex');
    const it = { user, name, salt, hash: await hashPw(body.password, salt), status: 'pending', freeAccess: false,
                 fails: 0, lockUntil: 0, stars: {}, log: [], weak: {}, created: now(), lastLogin: 0, updated: now(), v: 0 };
    if (!(await store.put(it, null))) return json(409, { error: 'taken' });
    if (notifier) {
      const base = `https://${event.requestContext?.domainName || event.headers?.host || ''}/api/admin/decide`;
      const link = (a) => `${base}?t=${encodeURIComponent(decideToken(user, a))}`;
      try {
        await notifier.send({
          subject: `New Yuli account request: ${name}`,
          text: `New account request\nUsername: ${name}\n\nApprove: ${link('approve')}\nReject:  ${link('reject')}\n\n(links valid for 14 days)`,
          html: `<p>New account request</p><p><b>Username:</b> ${esc(name)}</p><p><a href="${esc(link('approve'))}">Approve</a> &nbsp;|&nbsp; <a href="${esc(link('reject'))}">Reject</a></p><p style="color:#666">Links are valid for 14 days.</p>`,
        });
      } catch (e) { console.error('notify failed', e?.name, e?.message); }
    }
    return json(201, { ok: true, status: 'pending' });
  }

  async function login(body) {
    const name = norm(body.username);
    if (!validName(name) || !validPassword(body.password)) return json(400, { error: 'bad_input' });
    const user = keyOf(name);
    const it = await store.get(user);
    if (!it) return json(401, { error: 'bad_credentials' });
    if ((it.lockUntil || 0) > now()) return json(429, { error: 'locked', retryMs: it.lockUntil - now() });
    if (!safeEq(await hashPw(body.password, it.salt), it.hash)) {
      const upd = { ...it, fails: (it.fails || 0) + 1, v: it.v + 1 };
      if (upd.fails >= MAX_FAILS) { upd.fails = 0; upd.lockUntil = now() + LOCK_MS; }
      await store.put(upd, it.v);
      return json(401, { error: 'bad_credentials' });
    }
    const status = it.status || 'approved'; // accounts created before approval existed stay usable
    if (status !== 'approved') return json(403, { error: status });
    const res = await mutate(user, (x) => { x.fails = 0; x.lockUntil = 0; x.lastLogin = now(); });
    return json(200, { token: sessionToken(user), ...publicView(res) });
  }

  async function progress(user, body) {
    const key = body.key, stars = body.stars;
    if (key !== undefined && (!KEY_RE.test(String(key)) || !Number.isInteger(stars) || stars < 1 || stars > 3)) return json(400, { error: 'bad_input' });
    const merge = body.merge && typeof body.merge === 'object' ? Object.entries(body.merge) : [];
    if (merge.length > 400) return json(400, { error: 'bad_input' });
    const miss = Array.isArray(body.miss) ? body.miss.filter((w) => typeof w === 'string' && WORD_RE.test(w)).slice(0, 20) : [];
    const res = await mutate(user, (it) => {
      it.stars ||= {}; it.log ||= []; it.weak ||= {};
      for (const [k, v] of merge) if (KEY_RE.test(k) && Number.isInteger(v) && v >= 1 && v <= 3) it.stars[k] = Math.max(it.stars[k] || 0, v);
      if (key !== undefined) {
        it.stars[key] = Math.max(it.stars[key] || 0, stars);
        it.log.push({ k: key, s: stars, t: Math.floor(now() / 1000), ...(miss.length ? { m: miss } : {}) });
        if (it.log.length > MAX_LOG) it.log = it.log.slice(-MAX_LOG);
      }
      for (const w of miss) it.weak[w] = (it.weak[w] || 0) + 1;
      const ws = Object.entries(it.weak);
      if (ws.length > MAX_WEAK) it.weak = Object.fromEntries(ws.sort((a, b) => b[1] - a[1]).slice(0, MAX_WEAK));
    });
    if (!res) return json(404, { error: 'no_user' });
    return json(200, { ok: true, stars: res.stars });
  }

  // Applies an owner decision. Approving also grants free access (there is no paid plan yet).
  const decide = (user, action) => mutate(user, (it) => {
    it.status = action === 'approve' ? 'approved' : 'rejected';
    if (action === 'approve') it.freeAccess = true;
  });

  async function decidePage(method, event, body) {
    const t = method === 'GET' ? event.queryStringParameters?.t : body.t;
    const o = unseal(t);
    if (!o || o.k !== 'd' || !['approve', 'reject'].includes(o.a)) return page(400, 'Invalid link', '<h2>This link is invalid or has expired.</h2>');
    const it = await store.get(o.u);
    if (!it) return page(404, 'Not found', '<h2>User not found.</h2>');
    const verb = o.a === 'approve' ? 'Approve' : 'Reject';
    if (method === 'GET') {
      return page(200, verb, `<h2>${verb} account "${esc(it.name)}"?</h2><p>Current status: <b>${esc(it.status || 'approved')}</b></p>
<form method="POST" action="/api/admin/decide"><input type="hidden" name="t" value="${esc(t)}"><button type="submit">${verb}</button></form>`);
    }
    await decide(o.u, o.a);
    return page(200, 'Done', `<h2>Done: "${esc(it.name)}" was ${o.a === 'approve' ? 'approved' : 'rejected'}.</h2>`);
  }

  const isAdmin = (event) => {
    const k = event.headers?.['x-admin-key'] || event.headers?.['X-Admin-Key'] || '';
    return !!adminKey && adminKey.length >= 16 && safeEq(k, adminKey);
  };

  return async function handler(event) {
    try {
      const method = event.requestContext?.http?.method || event.httpMethod;
      const path = event.rawPath || event.path || '';
      if (method === 'GET' && path === '/api/health') return json(200, { ok: true });

      let body = {};
      if (event.body) {
        const raw = event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString() : event.body;
        if (raw.length > 20000) return json(413, { error: 'too_large' });
        const ct = (event.headers?.['content-type'] || '').toLowerCase();
        if (ct.includes('application/x-www-form-urlencoded')) body = Object.fromEntries(new URLSearchParams(raw));
        else { try { body = JSON.parse(raw); } catch { return json(400, { error: 'bad_json' }); } }
      }

      if (path === '/api/admin/decide' && (method === 'GET' || method === 'POST')) return await decidePage(method, event, body);
      if (method === 'POST' && path === '/api/register') return await register(body, event);
      if (method === 'POST' && path === '/api/login') return await login(body);

      if (path.startsWith('/api/admin/')) {
        if (!isAdmin(event)) return json(401, { error: 'unauthorized' });
        if (method === 'GET' && path === '/api/admin/users') {
          const rows = (await store.list()).map(adminRow).sort((a, b) => (b.created || 0) - (a.created || 0));
          return json(200, { users: rows });
        }
        if (method === 'PUT' && path === '/api/admin/user') {
          const user = keyOf(body.username);
          if (body.status !== undefined && !STATUSES.includes(body.status)) return json(400, { error: 'bad_input' });
          if (body.freeAccess !== undefined && typeof body.freeAccess !== 'boolean') return json(400, { error: 'bad_input' });
          const res = await mutate(user, (it) => {
            if (body.status !== undefined) it.status = body.status;
            if (body.freeAccess !== undefined) it.freeAccess = body.freeAccess;
          });
          return res ? json(200, adminRow(res)) : json(404, { error: 'no_user' });
        }
        return json(404, { error: 'not_found' });
      }

      const auth = event.headers?.authorization || event.headers?.Authorization || '';
      const user = sessionUser(auth.replace(/^Bearer\s+/i, ''));
      if (!user) return json(401, { error: 'unauthorized' });
      const me = await store.get(user);
      if (!me || (me.status || 'approved') !== 'approved') return json(403, { error: 'not_approved' });

      if (method === 'GET' && path === '/api/me') return json(200, publicView(me));
      if (method === 'PUT' && path === '/api/progress') return await progress(user, body);
      return json(404, { error: 'not_found' });
    } catch (e) {
      console.error('handler error', e?.name, e?.message);
      return json(500, { error: 'server' });
    }
  };
}

// ---- AWS adapters (AWS SDK v3 is bundled in the Node.js Lambda runtime) ----
async function ddbStore(table) {
  const { DynamoDBClient } = await import('@aws-sdk/client-dynamodb');
  const { DynamoDBDocumentClient, GetCommand, PutCommand, ScanCommand } = await import('@aws-sdk/lib-dynamodb');
  const c = DynamoDBDocumentClient.from(new DynamoDBClient({}), { marshallOptions: { removeUndefinedValues: true } });
  return {
    async get(user) { return (await c.send(new GetCommand({ TableName: table, Key: { user } }))).Item || null; },
    async put(item, expectedV) {
      const cond = expectedV === null
        ? { ConditionExpression: 'attribute_not_exists(#u)', ExpressionAttributeNames: { '#u': 'user' } }
        : { ConditionExpression: 'v = :v', ExpressionAttributeValues: { ':v': expectedV } };
      try { await c.send(new PutCommand({ TableName: table, Item: item, ...cond })); return true; }
      catch (e) { if (e.name === 'ConditionalCheckFailedException') return false; throw e; }
    },
    async list() {
      const out = []; let key;
      do {
        const r = await c.send(new ScanCommand({ TableName: table, ExclusiveStartKey: key,
          ProjectionExpression: '#u, #n, #s, freeAccess, created, lastLogin, stars',
          ExpressionAttributeNames: { '#u': 'user', '#n': 'name', '#s': 'status' } }));
        out.push(...(r.Items || [])); key = r.LastEvaluatedKey;
      } while (key);
      return out;
    },
  };
}

async function sesNotifier({ from, to }) {
  if (!from || !to) return null;
  const { SESv2Client, SendEmailCommand } = await import('@aws-sdk/client-sesv2');
  const c = new SESv2Client({});
  return {
    async send({ subject, text, html }) {
      await c.send(new SendEmailCommand({
        FromEmailAddress: from,
        Destination: { ToAddresses: [to] },
        Content: { Simple: { Subject: { Data: subject, Charset: 'UTF-8' },
          Body: { Text: { Data: text, Charset: 'UTF-8' }, Html: { Data: html, Charset: 'UTF-8' } } } },
      }));
    },
  };
}

let cached;
export const handler = async (event) => {
  cached ??= makeHandler({
    store: await ddbStore(process.env.TABLE),
    secret: process.env.TOKEN_SECRET,
    adminKey: process.env.ADMIN_KEY,
    notifier: await sesNotifier({ from: process.env.MAIL_FROM, to: process.env.ADMIN_EMAIL }),
  });
  return cached(event);
};
