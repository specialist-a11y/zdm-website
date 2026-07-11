/**
 * ZDM INC — Audit Proxy Worker
 *
 * Sits between the audit tool (browser) and Anthropic's API.
 * Your Claude API key never touches the browser.
 *
 * DEPLOY:
 *   1. wrangler secret put ANTHROPIC_API_KEY
 *   2. wrangler deploy
 *
 * ALLOWED_ORIGINS: add your production domain here.
 */

const ALLOWED_ORIGINS = [
  'https://zdminc.com',
  'https://www.zdminc.com',
  'http://localhost:8000',
  'http://127.0.0.1:8000',
];

const SUPABASE_URL  = 'https://yzyndghubzyktkubqpqf.supabase.co';
const SUPABASE_ANON = 'sb_publishable_jVtYc6imLNSz0yvHNfnw5g_Pa20U5yF';

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    
    let isAllowed = ALLOWED_ORIGINS.includes(origin);
    if (!isAllowed && origin) {
      try {
        const url = new URL(origin);
        if (url.hostname.endsWith('.vercel.app') || 
            url.hostname === 'localhost' || 
            url.hostname === '127.0.0.1') {
          isAllowed = true;
        }
      } catch (_) {}
    }

    const allowedOrigin = isAllowed ? origin : ALLOWED_ORIGINS[0];

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

    // ── 1. Verify token via Supabase ──
    const auth = request.headers.get('Authorization') || '';
    if (!auth.startsWith('Bearer ')) {
      return json({ error: 'Missing authorization token' }, 401, cors);
    }

    const token = auth.slice(7);

    try {
      const userRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'apikey': SUPABASE_ANON,
        },
      });
      if (!userRes.ok) throw new Error('invalid');
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
