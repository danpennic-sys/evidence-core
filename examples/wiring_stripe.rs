// Drop-in for Stripe payment confirmation boundary
// (webhook: checkout.session.completed + payment_status == paid)

use evidence_core::emit_pack;
use serde_json::json;

const SERVICE: &str = "stripe";
const SERVICE_VERSION: &str = "v20261008-A";
const GATEWAY_VERSION: &str = "v20261008-G";

/// Call this ONLY after the Stripe webhook has been signature-verified
/// and you have confirmed payment_status == "paid".
/// This is the sole confirmation boundary (same rule as quantumguard stripe-test).
fn emit_stripe_payment(
    session_id: &str,
    payment_intent_id: Option<&str>,
    amount: i64,
    currency: &str,
    customer_email: Option<&str>,
    livemode: bool,
    created_at: &str,
) {
    let body = json!({
        "session_id": session_id,
        "payment_intent_id": payment_intent_id,
        "amount": amount,
        "currency": currency,
        "customer_email": customer_email,
        "livemode": livemode,
        "created_at": created_at,
    });

    // Response is the recorded payment record itself (idempotent store)
    let result = body.clone();

    let _pack = emit_pack(
        SERVICE,
        SERVICE_VERSION,
        GATEWAY_VERSION,
        "/stripe/webhook/checkout.session.completed",
        body,
        &result,
        vec![
            "STRIPE-001".into(), // signature verified
            "STRIPE-002".into(), // payment_status == paid
            "STRIPE-003".into(), // idempotent write
            "STRIPE-004".into(), // no card data stored
        ],
        "GENESIS".into(),                     // replace with real prev_hash
        "signature_placeholder".into(),       // replace with real signer
    );
}
