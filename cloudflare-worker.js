/**
 * ZDM INC — Audit Proxy Worker
 *
 * Sits between the audit tool (browser) and Anthropic's API.
 * Your Claude API key never touches the browser.
 *
 * DEPLOY:
 *   1. Install Wrangler:  npm install -g wrangler
 *   2. Login:             wrangler login
 *   3. Set secrets:
 *        wrangler secret put ANTHROPIC_API_KEY
 *        wrangler secret put SUPABASE_JWT_SECRET
 *      (JWT secret is in Supabase → Settings → API → JWT Secret)
 *   4. Deploy:            wrangler deploy
 *
 * ALLOWED_ORIGINS: add your production domain here.
 */

const ALLOWED_ORIGINS = [
  'https://zdminc.com',
  'https://www.zdminc.com',
  'http://localhost:8000',
  'http://127.0.0.1:8000',
];

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];

    const cors = {
      'Access-Control-Allow-Origin':  allowedOrigin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age':       '86400',
    };

    // ── CORS preflight ──
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    if (request.method !== 'POST') {
      return json({ error: 'Method not allowed' }, 405, cors);
    }

    // ── 1. Verify Supabase JWT ──
    const auth = request.headers.get('Authorization') || '';
    if (!auth.startsWith('Bearer ')) {
      return json({ error: 'Missing authorization token' }, 401, cors);
    }

    try {
      const valid = await verifyJWT(auth.slice(7), env.SUPABASE_JWT_SECRET);
      if (!valid) throw new Error('invalid');
    } catch {
      return json({ error: 'Unauthorized' }, 401, cors);
    }

    // ── 2. Parse + sanitise request body ──
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'Invalid JSON' }, 400, cors);
    }

    // Whitelist only expected fields — never let client set the API key
    const safe = {
      model:      body.model || 'claude-opus-4-7',
      max_tokens: Math.min(Number(body.max_tokens) || 4096, 8192),
      stream:     true,
      system:     String(body.system  || ''),
      messages:   Array.isArray(body.messages) ? body.messages : [],
    };

    // ── 3. Call Anthropic and stream response back ──
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(safe),
    });

    return new Response(upstream.body, {
      status:  upstream.status,
      headers: {
        ...cors,
        'Content-Type':      'text/event-stream',
        'Cache-Control':     'no-cache, no-transform',
        'X-Accel-Buffering': 'no',
      },
    });
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function json(body, status, cors) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  });
}

async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return false;

  let payload;
  try { payload = JSON.parse(b64Decode(parts[1])); } catch { return false; }

  // Check expiry
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return false;

  // Verify HMAC-SHA256 signature
  const enc     = new TextEncoder();
  const keyData = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['verify']
  );

  return crypto.subtle.verify(
    'HMAC',
    keyData,
    b64ToBuffer(parts[2]),
    enc.encode(parts[0] + '.' + parts[1])
  );
}

function b64Decode(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  return atob(b64.padEnd(b64.length + (4 - b64.length % 4) % 4, '='));
}

function b64ToBuffer(str) {
  const bin   = b64Decode(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
