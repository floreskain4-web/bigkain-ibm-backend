import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import app from '../server.js';

const originalNodeEnv = process.env.NODE_ENV;
const originalVercel = process.env.VERCEL;
const originalLocalOwnership = process.env.BIGKAIN_CHATGPT_ALLOW_EPHEMERAL_OWNERSHIP;
process.env.BIGKAIN_CHATGPT_API_KEY = 'test-chatgpt-key';
let server;
let base;

async function get(path, token) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  const res = await fetch(base + path, { headers });
  return { status: res.status, body: await res.json() };
}

async function post(path, body, token = 'test-chatgpt-key') {
  const res = await fetch(base + path, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

before(async () => {
  process.env.NODE_ENV = 'test';
  process.env.BIGKAIN_CHATGPT_ALLOW_EPHEMERAL_OWNERSHIP = 'true';
  delete process.env.VERCEL;
  await new Promise((resolve) => { server = app.listen(0, resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  delete process.env.BIGKAIN_CHATGPT_API_KEY;
  if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = originalNodeEnv;
  if (originalVercel === undefined) delete process.env.VERCEL;
  else process.env.VERCEL = originalVercel;
  if (originalLocalOwnership === undefined) delete process.env.BIGKAIN_CHATGPT_ALLOW_EPHEMERAL_OWNERSHIP;
  else process.env.BIGKAIN_CHATGPT_ALLOW_EPHEMERAL_OWNERSHIP = originalLocalOwnership;
});

describe('authenticated ChatGPT facade', () => {
  test('missing auth is rejected', async () => {
    const r = await get('/v1/chatgpt/status');
    assert.equal(r.status, 401);
  });

  test('invalid auth is rejected', async () => {
    const r = await get('/v1/chatgpt/status', 'wrong');
    assert.equal(r.status, 403);
  });

  test('status is authenticated and least privilege is explicit', async () => {
    const r = await get('/v1/chatgpt/status', 'test-chatgpt-key');
    assert.equal(r.status, 200);
    assert.equal(r.body.integration, 'chatgpt');
    assert.equal(r.body.signing_authority, 'BigKain');
    assert.equal(r.body.signing_by_chatgpt, undefined);
    assert.ok(r.body.chatgpt_cannot.includes('broadcast transactions'));
  });

  test('key-like request fields are rejected', async () => {
    const r = await post('/v1/chatgpt/ownership/challenge', {
      address: '1Ay8vMC7R1UbyCCZRVULMV7iQpHSAbguJP',
      privateKey: 'never-send-this',
    });
    assert.equal(r.status, 400);
  });

  test('sign and broadcast routes do not exist', async () => {
    const s = await post('/v1/chatgpt/transaction/sign', {});
    const b = await post('/v1/chatgpt/transaction/broadcast', {});
    assert.equal(s.status, 404);
    assert.equal(b.status, 404);
  });

  test('invalid addresses are rejected before upstream calls', async () => {
    const r = await get('/v1/chatgpt/address/not-a-bitcoin-address', 'test-chatgpt-key');
    assert.equal(r.status, 400);
  });

  test('Vercel disables process-local ownership challenges and reports unavailable state', async () => {
    process.env.VERCEL = '1';
    const status = await get('/v1/chatgpt/status', 'test-chatgpt-key');
    assert.equal(status.body.ownership_proof.status, 'UNAVAILABLE');
    assert.equal(status.body.chatgpt_can.includes('initiate ownership-verification challenges'), false);

    const challenge = await post('/v1/chatgpt/ownership/challenge', {
      address: '1Ay8vMC7R1UbyCCZRVULMV7iQpHSAbguJP',
    });
    assert.equal(challenge.status, 503);
    assert.equal(challenge.body.valid, false);

    const verify = await post('/v1/chatgpt/ownership/verify', {
      address: '1Ay8vMC7R1UbyCCZRVULMV7iQpHSAbguJP',
      message: 'challenge',
      signature: 'signature',
      challengeId: 'challenge-id',
    });
    assert.equal(verify.status, 503);
    delete process.env.VERCEL;
  });

  test('production fails closed even if the Vercel system flag is absent', async () => {
    process.env.NODE_ENV = 'production';
    delete process.env.VERCEL;
    const status = await get('/v1/chatgpt/status', 'test-chatgpt-key');
    assert.equal(status.body.ownership_proof.status, 'UNAVAILABLE');
    const challenge = await post('/v1/chatgpt/ownership/challenge', {
      address: '1Ay8vMC7R1UbyCCZRVULMV7iQpHSAbguJP',
    });
    assert.equal(challenge.status, 503);
    process.env.NODE_ENV = 'test';
  });

  test('local ownership challenge requires explicit opt-in and remains available for tests', async () => {
    const r = await post('/v1/chatgpt/ownership/challenge', {
      address: '1Ay8vMC7R1UbyCCZRVULMV7iQpHSAbguJP',
    });
    assert.equal(r.status, 200);
    assert.equal(r.body.gated, true);
    assert.ok(r.body.challengeId);
    assert.ok(r.body.message.includes('Nothing moves; nothing broadcasts.'));
  });
});
