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
};
let t = 1_700_000_000_000;
const h = makeHandler({ store, secret: 'test-secret', now: () => t });
const call = async (method, path, body, token) => {
  const r = await h({ requestContext: { http: { method } }, rawPath: path, headers: token ? { authorization: 'Bearer ' + token } : {}, body: body ? JSON.stringify(body) : undefined });
  return { code: r.statusCode, ...JSON.parse(r.body) };
};

assert.equal((await call('GET', '/api/health')).ok, true);
// validation
assert.equal((await call('POST', '/api/login', { username: 'a', pin: '1234' })).code, 400);
assert.equal((await call('POST', '/api/login', { username: 'דנה', pin: '12' })).code, 400);
assert.equal((await call('POST', '/api/login', { username: '<b>', pin: '1234' })).code, 400);
// create + login
let r = await call('POST', '/api/login', { username: 'דנה', pin: '1234' });
assert.equal(r.code, 200); assert.equal(r.isNew, true); assert.ok(r.token);
const tok = r.token;
r = await call('POST', '/api/login', { username: ' דנה ', pin: '1234' });
assert.equal(r.code, 200); assert.equal(r.isNew, false);
// case-insensitive latin names map to one user
await call('POST', '/api/login', { username: 'Noa', pin: '1111' });
assert.equal((await call('POST', '/api/login', { username: 'noa', pin: '1111' })).isNew, false);
// no token / bad token
assert.equal((await call('GET', '/api/me')).code, 401);
assert.equal((await call('GET', '/api/me', null, tok + 'x')).code, 401);
// progress
r = await call('PUT', '/api/progress', { key: 'w0_1', stars: 2, miss: ['red', 'blue'] }, tok);
assert.equal(r.code, 200); assert.equal(r.stars.w0_1, 2);
r = await call('PUT', '/api/progress', { key: 'w0_1', stars: 1 }, tok);
assert.equal(r.stars.w0_1, 2, 'stars never go down');
r = await call('PUT', '/api/progress', { merge: { w1_0: 3, p4: 1, 'bad key': 3, w2_0: 9 } }, tok);
assert.deepEqual(Object.keys(r.stars).sort(), ['p4', 'w0_1', 'w1_0']);
assert.equal((await call('PUT', '/api/progress', { key: 'w0_1', stars: 7 }, tok)).code, 400);
assert.equal((await call('PUT', '/api/progress', { key: '../x', stars: 1 }, tok)).code, 400);
r = await call('GET', '/api/me', null, tok);
assert.equal(r.name, 'דנה'); assert.equal(r.log.length, 2); assert.deepEqual(r.weak.map(x => x.w).sort(), ['blue', 'red']);
// log cap
for (let i = 0; i < 320; i++) await call('PUT', '/api/progress', { key: 'w0_2', stars: 1 }, tok);
assert.ok((await call('GET', '/api/me', null, tok)).log.length <= 50);
assert.ok(db.get('דנה').log.length <= 300);
// wrong pin + lockout
for (let i = 0; i < 4; i++) assert.equal((await call('POST', '/api/login', { username: 'דנה', pin: '0000' })).code, 401);
assert.equal((await call('POST', '/api/login', { username: 'דנה', pin: '0000' })).code, 401);
assert.equal((await call('POST', '/api/login', { username: 'דנה', pin: '1234' })).code, 429, 'locked even with right pin');
t += 5 * 60 * 1000 + 1;
assert.equal((await call('POST', '/api/login', { username: 'דנה', pin: '1234' })).code, 200, 'unlocks after 5 min');
// token expiry
t += 31 * 24 * 3600 * 1000;
assert.equal((await call('GET', '/api/me', null, tok)).code, 401);
// pin hash not leaked
assert.ok(!JSON.stringify(await call('GET', '/api/me', null, (await call('POST', '/api/login', { username: 'דנה', pin: '1234' })).token)).includes('hash'));
console.log('backend tests OK');
