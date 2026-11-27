// Yuli API – AWS Lambda (HTTP API payload v2) + DynamoDB.
// Stores per-child: username, hashed PIN, stars per station and a detailed progress log.
import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
const TOKEN_TTL_S = 30 * 24 * 3600;
const MAX_FAILS = 5;
const LOCK_MS = 5 * 60 * 1000;
const MAX_LOG = 300;
const MAX_WEAK = 200;
const KEY_RE = /^[a-z0-9_]{1,12}$/;
const WORD_RE = /^[A-Za-z0-9' ,.?!-]{1,40}$/;

export function makeHandler({ store, secret, now = () => Date.now() }) {
  const json = (code, obj) => ({
    statusCode: code,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    body: JSON.stringify(obj),
  });
  const b64 = (s) => Buffer.from(s).toString('base64url');
  const mac = (p) => crypto.createHmac('sha256', secret).update(p).digest('base64url');

  const sign = (user) => b64(JSON.stringify({ u: user, e: Math.floor(now() / 1000) + TOKEN_TTL_S })) ;
  const makeToken = (user) => { const p = sign(user); return p + '.' + mac(p); };
  const verifyToken = (t) => {
    if (!t || typeof t !== 'string' || !t.includes('.')) return null;
    const [p, s] = t.split('.');
    const a = Buffer.from(s || ''), b = Buffer.from(mac(p));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
      const o = JSON.parse(Buffer.from(p, 'base64url').toString());
      return o.e > now() / 1000 ? o.u : null;
    } catch { return null; }
  };

  const norm = (n) => String(n ?? '').normalize('NFC').replace(/\s+/g, ' ').trim();
  const keyOf = (n) => norm(n).toLowerCase();
  const validName = (n) => { n = norm(n); return n.length >= 2 && n.length <= 20 && !/[<>&"'\\/]/.test(n); };
  const validPin = (p) => typeof p === 'string' && /^\d{4}$/.test(p);
  const hashPin = async (pin, salt) => (await scrypt(pin, salt, 32)).toString('hex');
  const safeEq = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };

  const publicView = (it) => ({
    name: it.name,
    stars: it.stars || {},
    created: it.created,
    updated: it.updated,
    log: (it.log || []).slice(-50),
    weak: Object.entries(it.weak || {}).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([w, n]) => ({ w, n })),
  });

  async function login(body) {
    const name = norm(body.username);
    if (!validName(name) || !validPin(body.pin)) return json(400, { error: 'bad_input' });
    const user = keyOf(name);
    let it = await store.get(user);
    if (!it) {
      const salt = crypto.randomBytes(16).toString('hex');
      it = { user, name, salt, hash: await hashPin(body.pin, salt), fails: 0, lockUntil: 0,
             stars: {}, log: [], weak: {}, created: now(), updated: now(), v: 0 };
      if (await store.put(it, null)) return json(200, { token: makeToken(user), ...publicView(it), isNew: true });
      it = await store.get(user); // lost a creation race: fall through to verification
      if (!it) return json(500, { error: 'server' });
    }
    if ((it.lockUntil || 0) > now()) return json(429, { error: 'locked', retryMs: it.lockUntil - now() });
    const ok = safeEq(await hashPin(body.pin, it.salt), it.hash);
    if (!ok) {
      const upd = { ...it, fails: (it.fails || 0) + 1, v: it.v + 1 };
      if (upd.fails >= MAX_FAILS) { upd.fails = 0; upd.lockUntil = now() + LOCK_MS; }
      await store.put(upd, it.v); // best effort; a conflict just means another attempt raced us
      return json(401, { error: 'bad_credentials' });
    }
    if (it.fails) await store.put({ ...it, fails: 0, v: it.v + 1 }, it.v);
    return json(200, { token: makeToken(user), ...publicView(it), isNew: false });
  }

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

  return async function handler(event) {
    try {
      const method = event.requestContext?.http?.method || event.httpMethod;
      const path = event.rawPath || event.path || '';
      if (method === 'GET' && path === '/api/health') return json(200, { ok: true });

      let body = {};
      if (event.body) {
        const raw = event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString() : event.body;
        if (raw.length > 20000) return json(413, { error: 'too_large' });
        try { body = JSON.parse(raw); } catch { return json(400, { error: 'bad_json' }); }
      }
      if (method === 'POST' && path === '/api/login') return await login(body);

      const auth = event.headers?.authorization || event.headers?.Authorization || '';
      const user = verifyToken(auth.replace(/^Bearer\s+/i, ''));
      if (!user) return json(401, { error: 'unauthorized' });

      if (method === 'GET' && path === '/api/me') {
        const it = await store.get(user);
        return it ? json(200, publicView(it)) : json(404, { error: 'no_user' });
      }
      if (method === 'PUT' && path === '/api/progress') return await progress(user, body);
      return json(404, { error: 'not_found' });
    } catch (e) {
      console.error('handler error', e?.name, e?.message);
      return json(500, { error: 'server' });
    }
  };
}

// ---- DynamoDB store (AWS SDK v3 is bundled in the Node.js Lambda runtime) ----
async function ddbStore(table) {
  const { DynamoDBClient } = await import('@aws-sdk/client-dynamodb');
  const { DynamoDBDocumentClient, GetCommand, PutCommand } = await import('@aws-sdk/lib-dynamodb');
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
  };
}

let cached;
export const handler = async (event) => {
  cached ??= makeHandler({ store: await ddbStore(process.env.TABLE), secret: process.env.TOKEN_SECRET });
  return cached(event);
};
