const express = require('express');
const crypto = require('crypto');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const SibApiV3Sdk = require('sib-api-v3-sdk');
require('dotenv').config();

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

// Log environment variables on startup
console.log('=== STARTUP ===');
console.log('STRIPE_SECRET_KEY exists:', !!process.env.STRIPE_SECRET_KEY);
console.log('STRIPE_WEBHOOK_SECRET exists:', !!process.env.STRIPE_WEBHOOK_SECRET);
console.log('BREVO_API_KEY exists:', !!process.env.BREVO_API_KEY);
console.log('BREVO_FROM_EMAIL:', process.env.BREVO_FROM_EMAIL);
console.log('HMAC_SECRET exists:', !!process.env.HMAC_SECRET);
console.log('HMAC_SECRET length:', process.env.HMAC_SECRET?.length || 0);
console.log('HMAC_SECRET first 5 chars:', process.env.HMAC_SECRET?.substring(0, 5) || 'NONE');

const defaultClient = SibApiV3Sdk.ApiClient.instance;
defaultClient.authentications['api-key'].apiKey = process.env.BREVO_API_KEY;

// Serve static files (index.html)
app.use(express.static('.'));

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
      <p>Use this key to activate STRK Loader. Keep it safe!</p>
      <p>Questions? Reply to this email or visit our support page.</p>
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

app.listen(PORT, () => {
  console.log(`STRK Loader website running on port ${PORT}`);
});
