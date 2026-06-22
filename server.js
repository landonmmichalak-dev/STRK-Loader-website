const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const SibApiV3Sdk = require('sib-api-v3-sdk');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

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

// Generate license key in format STRK-{8-hex}-{8-hex}
function generateLicenseKey() {
  const randomHex = () => Math.floor(Math.random() * 0xFFFFFFFF).toString(16).toUpperCase().padStart(8, '0');
  return `STRK-${randomHex()}-${randomHex()}`;
}

// Handle successful payment
async function handlePaymentSuccess(session) {
  try {
    console.log('=== WEBHOOK RECEIVED ===');
    console.log('Session ID:', session.id);
    console.log('Session object:', JSON.stringify(session, null, 2));

    const licenseKey = generateLicenseKey();
    const customerEmail = session.customer_details?.email;

    if (!customerEmail) {
      console.error('ERROR: No customer email in session:', session.id);
      console.error('Customer details:', JSON.stringify(session.customer_details, null, 2));
      return;
    }

    console.log(`Processing payment for ${customerEmail}`);
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
    sendSmtpEmail.sender = { name: 'STRK Loader', email: process.env.BREVO_FROM_EMAIL };
    sendSmtpEmail.to = [{ email: customerEmail }];

    console.log('Sending email via Brevo...');
    console.log('From:', process.env.BREVO_FROM_EMAIL);
    console.log('To:', customerEmail);

    const result = await apiInstance.sendTransacEmail(sendSmtpEmail);
    console.log('Email sent successfully:', JSON.stringify(result, null, 2));
    console.log(`License key emailed to ${customerEmail}`);

    // TODO: Store license key in database for tracking
    // await saveLicenseKey(customerEmail, licenseKey, session.id);

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
