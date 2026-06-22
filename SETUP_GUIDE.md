# STRK Loader License Key System - Setup Guide

## Step 1: Get Brevo Credentials

1. Go to https://www.brevo.com and sign up for free (no credit card needed)
2. Verify your email
3. Go to Settings → SMTP & API
4. Copy your **API Key** (starts with `xkeysib_`)
5. Use any email as your sender (e.g., `noreply@strk-loader.com`)

## Step 2: Set Up Stripe Webhook

1. Go to https://dashboard.stripe.com/webhooks
2. Click "Add an endpoint"
3. Enter your endpoint URL: `https://strk-loader.onrender.com/webhook`
4. Select events to listen for:
   - `checkout.session.completed`
5. Click "Add endpoint"
6. Copy the **Signing secret** (starts with `whsec_`)

## Step 3: Create `.env` File

Create a `.env` file in the website directory with:

```
STRIPE_SECRET_KEY=sk_test_XXXX
STRIPE_WEBHOOK_SECRET=whsec_test_XXXX
BREVO_API_KEY=xkeysib_XXXX
BREVO_FROM_EMAIL=noreply@strk-loader.com
PORT=3000
```

Get these values from:
- `STRIPE_SECRET_KEY` - Stripe Dashboard → Developers → API Keys
- `STRIPE_WEBHOOK_SECRET` - From the webhook you just created
- `BREVO_API_KEY` - Brevo Dashboard → Settings → SMTP & API
- `BREVO_FROM_EMAIL` - Any email address you'd like to send from

## Step 4: Update Render Deployment

1. Go to your Render site at https://dashboard.render.com
2. Select the STRK Loader service
3. Go to Environment
4. Add each variable from your `.env` file
5. Redeploy

## Step 5: Test

1. Make a test payment on https://strk-loader.onrender.com using test card: `4242 4242 4242 4242`
2. Check the buyer's email - they should receive the license key within seconds
