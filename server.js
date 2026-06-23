const express = require('express');
const crypto = require('crypto');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const SibApiV3Sdk = require('sib-api-v3-sdk');
const { createClient } = require('@supabase/supabase-js');
const WebSocket = require('ws');
require('dotenv').config();

// Supabase admin client (service role — never expose this key to clients)
// Pass ws as the WebSocket transport so this works on Node.js < 22
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,  // service_role key, NOT anon key
  { realtime: { transport: WebSocket } }
);

// Per-IP rate limiter for the validate-key endpoint: max 10 req / 60s
const _rlMap = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  let slot = _rlMap.get(ip);
  if (!slot || now > slot.resetAt) slot = { count: 0, resetAt: now + 60_000 };
  slot.count++;
  _rlMap.set(ip, slot);
  // Evict IPs whose window has expired to prevent unbounded growth
  if (_rlMap.size > 5000) {
    for (const [k, v] of _rlMap) if (now > v.resetAt) _rlMap.delete(k);
  }
  return slot.count <= 10;
}

// Validate a STRK-XXXXXXXX-YYYYYYYY key against the server-side HMAC secret
function validateHmac(key) {
  try {
    const norm = String(key).toUpperCase().trim();
    if (!norm.startsWith('STRK-')) return false;
    const parts = norm.substring(5).split('-');
    if (parts.length !== 2 || parts[0].length !== 8 || parts[1].length !== 8) return false;
    const expected = crypto
      .createHmac('sha256', process.env.HMAC_SECRET)
      .update(parts[0])
      .digest('hex')
      .substring(0, 8)
      .toUpperCase();
    return parts[1] === expected;
  } catch { return false; }
}

const app = express();
const PORT = process.env.PORT || 3000;

// Track issued keys and prevent duplicates
const ISSUED_KEYS_FILE = 'issued_keys.json';

function loadIssuedKeys() {
  try {
    const data = require('fs').readFileSync(ISSUED_KEYS_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    return {};
  }
}

function saveIssuedKeys(data) {
  require('fs').writeFileSync(ISSUED_KEYS_FILE, JSON.stringify(data, null, 2));
}

// Log environment variables on startup (no secret values)
console.log('=== STARTUP ===');
console.log('STRIPE_SECRET_KEY exists:', !!process.env.STRIPE_SECRET_KEY);
console.log('STRIPE_WEBHOOK_SECRET exists:', !!process.env.STRIPE_WEBHOOK_SECRET);
console.log('BREVO_API_KEY exists:', !!process.env.BREVO_API_KEY);
console.log('BREVO_FROM_EMAIL:', process.env.BREVO_FROM_EMAIL);
console.log('HMAC_SECRET exists:', !!process.env.HMAC_SECRET);
console.log('HMAC_SECRET length:', process.env.HMAC_SECRET?.length || 0);

const defaultClient = SibApiV3Sdk.ApiClient.instance;
defaultClient.authentications['api-key'].apiKey = process.env.BREVO_API_KEY;

// Serve only the landing page and its assets — never server.js, issued_keys.json, .env, etc.
const ALLOWED_STATIC = new Set(['/', '/index.html', '/preview.png', '/preview.svg']);
app.get('*', (req, res, next) => {
  const p = req.path === '/' ? '/' : req.path;
  if (!ALLOWED_STATIC.has(p)) return res.status(404).send('Not found');
  next();
});
app.use(express.static('.', { index: 'index.html' }));

// Raw body for Stripe webhook verification
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.sendStatus(400);
  }

  // Handle checkout.session.completed event
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    await handlePaymentSuccess(session);
  }

  res.sendStatus(200);
});

// Generate license key in format STRK-{8-hex}-{8-hex-sig}
function generateLicenseKey() {
  const data = crypto.randomBytes(4).toString('hex').toUpperCase();
  const sig = crypto.createHmac('sha256', process.env.HMAC_SECRET).update(data).digest('hex').substring(0, 8).toUpperCase();
  return `STRK-${data}-${sig}`;
}

// Handle successful payment
async function handlePaymentSuccess(session) {
  try {
    console.log('=== WEBHOOK RECEIVED ===');
    console.log('Session ID:', session.id);

    const customerEmail = session.customer_details?.email;

    if (!customerEmail) {
      console.error('ERROR: No customer email in session:', session.id);
      return;
    }

    console.log(`Processing payment for ${customerEmail}`);

    // Check if this session already issued a key (prevent webhook retries from issuing duplicates)
    const issuedKeys = loadIssuedKeys();
    if (issuedKeys[session.id]) {
      console.log(`Session ${session.id} already issued key. Skipping duplicate.`);
      return;
    }

    const licenseKey = generateLicenseKey();
    console.log(`Generated license key: ${licenseKey}`);

    // Send email with license key via Brevo
    const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();

    const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    sendSmtpEmail.subject = 'Your STRK Loader License Key';
    sendSmtpEmail.htmlContent = `
      <h2>Welcome to STRK Loader!</h2>
      <p>Thank you for your purchase. Your license key is:</p>
      <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; font-family: monospace; font-size: 16px; text-align: center; margin: 20px 0;">
        <strong>${licenseKey}</strong>
      </div>
      <h3>Next Steps:</h3>
      <ol>
        <li><strong>Join our Discord:</strong> <a href="https://discord.gg/bHBgVEbDuz">discord.gg/bHBgVEbDuz</a></li>
        <li><strong>Claim your Premium role:</strong> Run <code>/claim-strk ${licenseKey}</code> in #bot-commands</li>
        <li><strong>Access the loader:</strong> You'll get access to the download channel</li>
      </ol>
      <p style="margin-top: 20px; color: #666; font-size: 14px;">
        Keep your license key private — do not share it. Each key can only be used once.
      </p>
    `;
    sendSmtpEmail.sender = { name: 'STRK Loader', email: 'landonmichalak539@gmail.com' };
    sendSmtpEmail.to = [{ email: customerEmail }];

    console.log('Sending email via Brevo...');
    console.log('From:', process.env.BREVO_FROM_EMAIL);
    console.log('To:', customerEmail);
    console.log('API Key exists:', !!process.env.BREVO_API_KEY);
    console.log('API Key length:', process.env.BREVO_API_KEY?.length);

    try {
      console.log('Creating Brevo API instance...');
      const result = await apiInstance.sendTransacEmail(sendSmtpEmail);
      console.log('Email sent successfully!');
      console.log(`License key emailed to ${customerEmail}`);

      // Store key in Supabase so the loader can validate it
      const { error: dbError } = await supabase.from('cooldowns').insert({
        discord_id: `stripe:${session.id}`,
        license_key: licenseKey,
        issued_at: new Date().toISOString(),
        hwid: null,
        hwid_bound_at: null,
        hwid_reset_at: null,
      });
      if (dbError) console.error('Supabase insert error:', dbError.message);
      else console.log(`Key stored in Supabase for session ${session.id}`);

      // Track issued key to prevent duplicates
      const issuedKeys = loadIssuedKeys();
      issuedKeys[session.id] = {
        email: customerEmail,
        key: licenseKey,
        issuedAt: new Date().toISOString(),
        stripeSessionId: session.id
      };
      saveIssuedKeys(issuedKeys);
      console.log(`Key tracked for session ${session.id}`);

    } catch (emailError) {
      console.error('=== BREVO EMAIL ERROR ===');
      console.error('Error type:', emailError.constructor.name);
      console.error('Error message:', emailError.message);
      console.error('Error status:', emailError.status);
      console.error('Error response:', emailError.response);
      throw emailError;
    }

  } catch (error) {
    console.error('=== ERROR HANDLING PAYMENT ===');
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    console.error('Full error:', JSON.stringify(error, null, 2));
  }
}

// ── Key validation endpoint called by the C# loader ──────────────────────────
// POST /api/validate-key  { key, hwid, token }
// token must equal LOADER_API_SECRET env var (prevents unauthenticated probing)
// On first use: binds the HWID to the key in Supabase.
// On subsequent uses: returns valid only if HWID matches the stored binding.
app.post('/api/validate-key', express.json(), async (req, res) => {
  const ip = req.ip || req.socket?.remoteAddress;
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ valid: false, reason: 'rate_limited' });
  }

  const { key, hwid, token } = req.body || {};

  if (!token || token !== process.env.LOADER_API_SECRET) {
    return res.status(401).json({ valid: false, reason: 'unauthorized' });
  }

  if (!key || !hwid || typeof key !== 'string' || typeof hwid !== 'string') {
    return res.status(400).json({ valid: false, reason: 'missing_fields' });
  }

  if (hwid.length < 8 || hwid.length > 64) {
    return res.json({ valid: false, reason: 'invalid_hwid' });
  }

  const normalized = key.toUpperCase().trim();

  if (!validateHmac(normalized)) {
    return res.json({ valid: false, reason: 'invalid_key' });
  }

  // Check and bind HWID in Supabase cooldowns table
  try {
    const { data: rows, error } = await supabase
      .from('cooldowns')
      .select('discord_id, hwid')
      .eq('license_key', normalized)
      .limit(1);

    if (error) throw error;

    if (!rows || rows.length === 0) {
      return res.json({ valid: false, reason: 'key_not_found' });
    }

    const row = rows[0];

    if (!row.hwid) {
      // First use — bind the HWID
      const { error: updateError } = await supabase
        .from('cooldowns')
        .update({ hwid, hwid_bound_at: new Date().toISOString() })
        .eq('license_key', normalized);
      if (updateError) throw updateError;
      console.log(`[validate-key] HWID bound for key ${normalized.substring(0, 10)}...`);
      return res.json({ valid: true });
    }

    if (row.hwid !== hwid) {
      console.log(`[validate-key] HWID mismatch for key ${normalized.substring(0, 10)}...`);
      return res.json({ valid: false, reason: 'hwid_mismatch' });
    }

    return res.json({ valid: true });
  } catch (err) {
    console.error('[validate-key] Supabase error:', err.message);
    // On DB error fall back to HMAC-only validation so users aren't locked out
    return res.json({ valid: true, warning: 'db_unavailable' });
  }
});

// ── HWID reset endpoint called by the Discord bot ────────────────────────────
// POST /api/reset-hwid  { license_key, token }
app.post('/api/reset-hwid', express.json(), async (req, res) => {
  const { license_key, token } = req.body || {};

  if (!token || token !== process.env.LOADER_API_SECRET) {
    return res.status(401).json({ ok: false, reason: 'unauthorized' });
  }
  if (!license_key) return res.status(400).json({ ok: false, reason: 'missing_fields' });

  try {
    const normalized = String(license_key).toUpperCase().trim();
    const { error } = await supabase
      .from('cooldowns')
      .update({ hwid: null, hwid_bound_at: null })
      .eq('license_key', normalized);
    if (error) throw error;
    console.log(`[reset-hwid] HWID cleared for key ${normalized.substring(0, 10)}...`);
    return res.json({ ok: true });
  } catch (err) {
    console.error('[reset-hwid] error:', err.message);
    return res.status(500).json({ ok: false, reason: 'server_error' });
  }
});

app.listen(PORT, () => {
  console.log(`STRK Loader website running on port ${PORT}`);
});
