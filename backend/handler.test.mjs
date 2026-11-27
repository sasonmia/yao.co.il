import assert from 'node:assert/strict';
import { makeHandler } from './handler.mjs';

const db = new Map();
const store = {
  async get(u) { const x = db.get(u); return x ? JSON.parse(JSON.stringify(x)) : null; },
  async put(item, ev) {
    const cur = db.get(item.user);
    if (ev === null ? cur : (!cur || cur.v !== ev)) return false;
    db.set(item.user, JSON.parse(JSON.stringify(item))); return true;
  },
  async list() { return [...db.values()].map((x) => JSON.parse(JSON.stringify(x))); },
};
const mails = [];
const notifier = { async send(m) { mails.push(m); } };
let t = 1_700_000_000_000;
const ADMIN = 'admin-key-1234567890';
const h = makeHandler({ store, secret: 'test-secret', adminKey: ADMIN, notifier, now: () => t });
const call = async (method, path, body, token, extra = {}) => {
  const r = await h({ requestContext: { http: { method }, domainName: 'api.example.com' }, rawPath: path,
    headers: { ...(token ? { authorization: 'Bearer ' + token } : {}), ...(extra.headers || {}) },
    queryStringParameters: extra.query, body: body === undefined ? undefined : (extra.raw ?? JSON.stringify(body)) });
  let j = {}; try { j = JSON.parse(r.body); } catch { j = { html: r.body }; }
  return { code: r.statusCode, ...j };
};
const admin = { headers: { 'x-admin-key': ADMIN } };
const linkToken = (mail, label) => decodeURIComponent(mail.text.split(label)[1].trim().split('\n')[0].split('?t=')[1]);

assert.equal((await call('GET', '/api/health')).ok, true);
// validation
assert.equal((await call('POST', '/api/register', { username: 'a', password: 'secret1' })).code, 400);
assert.equal((await call('POST', '/api/register', { username: 'Dana', password: '123' })).code, 400);
assert.equal((await call('POST', '/api/register', { username: '<b>', password: 'secret1' })).code, 400);
// register -> pending + owner email with links
let r = await call('POST', '/api/register', { username: 'דנה', password: 'secret1' });
assert.equal(r.code, 201); assert.equal(r.status, 'pending');
assert.equal(mails.length, 1);
assert.match(mails[0].subject, /דנה/);
assert.match(mails[0].text, /https:\/\/api\.example\.com\/api\/admin\/decide\?t=/);
assert.equal((await call('POST', '/api/register', { username: 'דנה', password: 'other11' })).code, 409);
// pending user cannot log in (even with right password), wrong password is plain 401
assert.equal((await call('POST', '/api/login', { username: 'דנה', password: 'secret1' })).error, 'pending');
assert.equal((await call('POST', '/api/login', { username: 'דנה', password: 'wrong11' })).code, 401);
assert.equal((await call('POST', '/api/login', { username: 'nobody', password: 'secret1' })).code, 401);
// approval links: GET shows a confirm page only (no state change), POST applies
const ap = linkToken(mails[0], 'Approve:'), rj = linkToken(mails[0], 'Reject:');
let g = await h({ requestContext: { http: { method: 'GET' } }, rawPath: '/api/admin/decide', headers: {}, queryStringParameters: { t: ap } });
assert.equal(g.statusCode, 200); assert.match(g.body, /<form method="POST"/);
assert.equal(db.get('דנה').status, 'pending', 'GET must not change state');
assert.equal((await h({ requestContext: { http: { method: 'GET' } }, rawPath: '/api/admin/decide', headers: {}, queryStringParameters: { t: ap + 'x' } })).statusCode, 400);
let p = await h({ requestContext: { http: { method: 'POST' } }, rawPath: '/api/admin/decide', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 't=' + encodeURIComponent(ap) });
assert.equal(p.statusCode, 200); assert.equal(db.get('דנה').status, 'approved'); assert.equal(db.get('דנה').freeAccess, true);
// session token can't be used as a decide token and vice versa
r = await call('POST', '/api/login', { username: ' דנה ', password: 'secret1' });
assert.equal(r.code, 200); assert.ok(r.token);
const tok = r.token;
assert.equal((await h({ requestContext: { http: { method: 'GET' } }, rawPath: '/api/admin/decide', headers: {}, queryStringParameters: { t: tok } })).statusCode, 400);
assert.equal((await call('GET', '/api/me', null, ap)).code, 401);
assert.ok(db.get('דנה').lastLogin > 0);
// progress still works
r = await call('PUT', '/api/progress', { key: 'w0_1', stars: 2, miss: ['red', 'blue'] }, tok);
assert.equal(r.code, 200); assert.equal(r.stars.w0_1, 2);
assert.equal((await call('PUT', '/api/progress', { key: 'w0_1', stars: 1 }, tok)).stars.w0_1, 2);
assert.equal((await call('PUT', '/api/progress', { key: 'w0_1', stars: 7 }, tok)).code, 400);
r = await call('GET', '/api/me', null, tok);
assert.equal(r.name, 'דנה'); assert.ok(!JSON.stringify(r).includes('hash'));
// reject flow
await call('POST', '/api/register', { username: 'Noa', password: 'secret2' });
await h({ requestContext: { http: { method: 'POST' } }, rawPath: '/api/admin/decide', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 't=' + encodeURIComponent(linkToken(mails[1], 'Reject:')) });
assert.equal(db.get('noa').status, 'rejected'); assert.equal(db.get('noa').freeAccess, false);
assert.equal((await call('POST', '/api/login', { username: 'NOA', password: 'secret2' })).error, 'rejected');
// admin API: auth + columns
assert.equal((await call('GET', '/api/admin/users')).code, 401);
assert.equal((await call('GET', '/api/admin/users', null, null, { headers: { 'x-admin-key': 'wrong-key-wrong-key' } })).code, 401);
r = await call('GET', '/api/admin/users', null, null, admin);
assert.equal(r.code, 200); assert.equal(r.users.length, 2);
const dana = r.users.find((u) => u.username === 'דנה');
assert.deepEqual(Object.keys(dana).sort(), ['active', 'created', 'freeAccess', 'lastLogin', 'status', 'totalStars', 'username']);
assert.equal(dana.active, true); assert.equal(dana.status, 'approved'); assert.equal(dana.freeAccess, true); assert.equal(dana.totalStars, 2);
assert.equal(r.users.find((u) => u.username === 'Noa').active, false);
// "active" expires after 30 days
t += 31 * 24 * 3600 * 1000;
assert.equal((await call('GET', '/api/admin/users', null, null, admin)).users.find((u) => u.username === 'דנה').active, false);
// admin updates: approve rejected user, toggle freeAccess, validate input
r = await call('PUT', '/api/admin/user', { username: 'noa', status: 'approved', freeAccess: false }, null, admin);
assert.equal(r.status, 'approved'); assert.equal(r.freeAccess, false);
assert.equal((await call('PUT', '/api/admin/user', { username: 'noa', status: 'bogus' }, null, admin)).code, 400);
assert.equal((await call('PUT', '/api/admin/user', { username: 'ghost', status: 'approved' }, null, admin)).code, 404);
assert.equal((await call('PUT', '/api/admin/user', { username: 'noa', status: 'approved' })).code, 401);
// old session expires; revoked user loses API access immediately
assert.equal((await call('GET', '/api/me', null, tok)).code, 401);
t -= 20 * 24 * 3600 * 1000;
const tok2 = (await call('POST', '/api/login', { username: 'דנה', password: 'secret1' })).token;
await call('PUT', '/api/admin/user', { username: 'דנה', status: 'rejected' }, null, admin);
assert.equal((await call('GET', '/api/me', null, tok2)).code, 403);
// lockout after 5 wrong passwords
await call('PUT', '/api/admin/user', { username: 'דנה', status: 'approved' }, null, admin);
for (let i = 0; i < 5; i++) assert.equal((await call('POST', '/api/login', { username: 'דנה', password: 'bad-pass' })).code, 401);
assert.equal((await call('POST', '/api/login', { username: 'דנה', password: 'secret1' })).code, 429);
t += 5 * 60 * 1000 + 1;
assert.equal((await call('POST', '/api/login', { username: 'דנה', password: 'secret1' })).code, 200);
// email failure must not block registration
const h2 = makeHandler({ store, secret: 's', notifier: { async send() { throw new Error('ses down'); } }, now: () => t });
const rr = await h2({ requestContext: { http: { method: 'POST' } }, rawPath: '/api/register', headers: {}, body: JSON.stringify({ username: 'Lior', password: 'secret3' }) });
assert.equal(rr.statusCode, 201);
// admin disabled when no key configured
const h3 = makeHandler({ store, secret: 's', now: () => t });
assert.equal((await h3({ requestContext: { http: { method: 'GET' } }, rawPath: '/api/admin/users', headers: { 'x-admin-key': '' } })).statusCode, 401);
console.log('backend tests OK');
