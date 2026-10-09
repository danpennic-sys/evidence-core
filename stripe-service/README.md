# stripe-service

Full Stripe Checkout + verified webhook + EvidencePack emission.

## Design rules (identical to quantumguard stripe-test)

- Test mode only
- $10 one-time payment
- `/create-checkout-session` → Stripe-hosted Checkout
- `/webhook` with Stripe signature verification
- Idempotent recording into `payments.json`
- Success / cancel pages exist but **are not** treated as payment proof
- Webhook (`checkout.session.completed` + `payment_status === 'paid'`) is the sole confirmation boundary
- No card data is stored
- Every successful paid session emits a deterministic EvidencePack

## Quick start

```bash
cd stripe-service
cp .env.example .env
# fill sk_test_... and later whsec_...

cargo run -p stripe-service
```

In a second terminal:

```bash
stripe listen --forward-to localhost:4242/webhook
```

Copy the printed `whsec_...` into `.env` and restart if needed.

Open http://localhost:4242 → Pay $10 → test card `4242 4242 4242 4242`.

After the webhook fires you will see:
- one record in `payments.json`
- one EvidencePack under `evidence/stripe_....json`

## Invariants

- STRIPE-001 signature verified
- STRIPE-002 payment_status == paid
- STRIPE-003 idempotent write
- STRIPE-004 no card data stored
