import { timingSafeEqual } from 'node:crypto';

export function requireApiKey(envName, scopeName) {
  return (req, res, next) => {
    const expected = process.env[envName];
    const supplied = typeof req.get('authorization') === 'string'
      ? req.get('authorization').replace(/^Bearer\s+/i, '').trim()
      : null;

    if (!expected) {
      return res.status(503).json({
        error: 'authenticated integration is not configured',
        required_env: envName,
      });
    }

    if (!supplied) {
      return res.status(401).json({ error: 'missing bearer token' });
    }

    const a = Buffer.from(supplied);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return res.status(403).json({ error: 'invalid bearer token' });
    }

    req.bigkainAuth = { client: envName, scope: scopeName };
    next();
  };
}

export const chatgptAuth = requireApiKey(
  'BIGKAIN_CHATGPT_API_KEY',
  'chatgpt:wallet'
);
