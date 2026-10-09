//! Stripe service — sole confirmation boundary is the verified webhook.
//! Emits EvidencePack on every successful paid checkout.session.completed.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use evidence_core::emit_pack;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tower_http::services::ServeDir;

type HmacSha256 = Hmac<Sha256>;

const SERVICE: &str = "stripe";
const SERVICE_VERSION: &str = "v20261008-A";
const GATEWAY_VERSION: &str = "v20261008-G";

#[derive(Clone)]
struct AppState {
    stripe_secret: String,
    webhook_secret: String,
    payments_file: PathBuf,
    recorded: Arc<Mutex<Vec<String>>>, // session_ids for in-memory idempotency
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PaymentRecord {
    session_id: String,
    payment_intent_id: Option<String>,
    amount: i64,
    currency: String,
    customer_email: Option<String>,
    created_at: String,
    livemode: bool,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let stripe_secret = std::env::var("STRIPE_SECRET_KEY")
        .expect("STRIPE_SECRET_KEY must be set (sk_test_...)");
    let webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET")
        .unwrap_or_else(|_| "whsec_placeholder".into());

    let payments_file = PathBuf::from("payments.json");
    if !payments_file.exists() {
        fs::write(&payments_file, "[]").expect("create payments.json");
    }

    let state = AppState {
        stripe_secret,
        webhook_secret,
        payments_file,
        recorded: Arc::new(Mutex::new(Vec::new())),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/create-checkout-session", post(create_checkout))
        .route("/webhook", post(webhook))
        .route("/success", get(success_page))
        .route("/cancel", get(cancel_page))
        .nest_service("/public", ServeDir::new("public"))
        .with_state(state);

    let addr = "0.0.0.0:4242";
    tracing::info!("stripe-service listening on http://{}", addr);
    tracing::info!("Use Stripe CLI: stripe listen --forward-to localhost:4242/webhook");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html><head><title>Evidence-Core Stripe</title></head>
<body>
  <h1>Evidence-Core Stripe Service</h1>
  <p>Sole confirmation boundary = verified webhook + payment_status == paid</p>
  <form action="/create-checkout-session" method="POST">
    <button type="submit">Pay $10 (Test Mode)</button>
  </form>
  <p>Success page is <strong>not</strong> payment proof.</p>
</body></html>"#,
    )
}

async fn create_checkout(State(state): State<AppState>) -> impl IntoResponse {
    let client = reqwest::Client::new();

    // Create Checkout Session via Stripe API
    let params = [
        ("mode", "payment"),
        ("payment_method_types[]", "card"),
        ("line_items[0][price_data][currency]", "usd"),
        ("line_items[0][price_data][product_data][name]", "Evidence-Core Test Payment"),
        ("line_items[0][price_data][product_data][description]", "Isolated $10 test — EvidencePack on webhook"),
        ("line_items[0][price_data][unit_amount]", "1000"),
        ("line_items[0][quantity]", "1"),
        ("success_url", "http://localhost:4242/success?session_id={CHECKOUT_SESSION_ID}"),
        ("cancel_url", "http://localhost:4242/cancel"),
    ];

    let res = client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .basic_auth(&state.stripe_secret, None::<&str>)
        .form(&params)
        .send()
        .await;

    match res {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            if let Some(url) = body.get("url").and_then(|u| u.as_str()) {
                Redirect::to(url).into_response()
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "no url in session").into_response()
            }
        }
        Ok(r) => {
            let err = r.text().await.unwrap_or_default();
            tracing::error!("Stripe error: {}", err);
            (StatusCode::BAD_GATEWAY, err).into_response()
        }
        Err(e) => {
            tracing::error!("request failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

async fn webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // 1. Signature verification (STRIPE-001)
    let sig_header = match headers.get("stripe-signature").and_then(|v| v.to_str().ok()) {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "missing stripe-signature").into_response(),
    };

    if !verify_stripe_signature(&body, sig_header, &state.webhook_secret) {
        tracing::error!("Webhook signature verification failed");
        return (StatusCode::BAD_REQUEST, "invalid signature").into_response();
    }

    let event: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid json").into_response(),
    };

    let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");

    if event_type == "checkout.session.completed" {
        let session = &event["data"]["object"];

        // 2. Only record paid sessions (STRIPE-002)
        let payment_status = session.get("payment_status").and_then(|s| s.as_str()).unwrap_or("");
        if payment_status != "paid" {
            tracing::info!("ignoring non-paid session");
            return (StatusCode::OK, "ignored").into_response();
        }

        let session_id = session.get("id").and_then(|s| s.as_str()).unwrap_or("").to_string();
        let payment_intent = session
            .get("payment_intent")
            .and_then(|p| p.as_str())
            .map(|s| s.to_string());
        let amount = session.get("amount_total").and_then(|a| a.as_i64()).unwrap_or(0);
        let currency = session
            .get("currency")
            .and_then(|c| c.as_str())
            .unwrap_or("usd")
            .to_string();
        let email = session
            .get("customer_details")
            .and_then(|d| d.get("email"))
            .and_then(|e| e.as_str())
            .map(|s| s.to_string());
        let livemode = session.get("livemode").and_then(|l| l.as_bool()).unwrap_or(false);
        let created_at = chrono::Utc::now().to_rfc3339();

        // 3. Idempotent write (STRIPE-003)
        {
            let mut recorded = state.recorded.lock().unwrap();
            if recorded.contains(&session_id) {
                tracing::info!("idempotent skip: {}", session_id);
                return (StatusCode::OK, "already recorded").into_response();
            }
            recorded.push(session_id.clone());
        }

        let record = PaymentRecord {
            session_id: session_id.clone(),
            payment_intent_id: payment_intent.clone(),
            amount,
            currency: currency.clone(),
            customer_email: email.clone(),
            created_at: created_at.clone(),
            livemode,
        };

        // Persist to payments.json
        if let Ok(mut list) = load_payments(&state.payments_file) {
            if !list.iter().any(|p| p.session_id == session_id) {
                list.push(record.clone());
                let _ = save_payments(&state.payments_file, &list);
            }
        }

        // 4. Emit EvidencePack (no card data — STRIPE-004)
        let body = json!({
            "session_id": session_id,
            "payment_intent_id": payment_intent,
            "amount": amount,
            "currency": currency,
            "customer_email": email,
            "livemode": livemode,
            "created_at": created_at,
        });

        let _pack = emit_pack(
            SERVICE,
            SERVICE_VERSION,
            GATEWAY_VERSION,
            "/stripe/webhook/checkout.session.completed",
            body.clone(),
            &body, // response == recorded payment
            vec![
                "STRIPE-001".into(),
                "STRIPE-002".into(),
                "STRIPE-003".into(),
                "STRIPE-004".into(),
            ],
            "GENESIS".into(),
            "signature_placeholder".into(),
        );

        tracing::info!("EvidencePack emitted for session {}", session_id);
    }

    (StatusCode::OK, "received").into_response()
}

async fn success_page() -> Html<&'static str> {
    Html("<h1>Payment submitted</h1><p>This page is <strong>not</strong> proof of payment. The verified webhook is the sole confirmation boundary.</p>")
}

async fn cancel_page() -> Html<&'static str> {
    Html("<h1>Cancelled</h1><p>No charge was made.</p>")
}

// --- helpers ---

fn verify_stripe_signature(payload: &[u8], header: &str, secret: &str) -> bool {
    // Stripe-Signature: t=timestamp,v1=signature
    let mut timestamp = None;
    let mut v1 = None;
    for part in header.split(',') {
        let mut kv = part.splitn(2, '=');
        match (kv.next(), kv.next()) {
            (Some("t"), Some(t)) => timestamp = Some(t),
            (Some("v1"), Some(s)) => v1 = Some(s),
            _ => {}
        }
    }
    let (Some(ts), Some(sig)) = (timestamp, v1) else {
        return false;
    };

    let signed = format!("{}.{}", ts, String::from_utf8_lossy(payload));
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(signed.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // Constant-time compare would be better; this is sufficient for the test slice
    expected == sig
}

fn load_payments(path: &PathBuf) -> Result<Vec<PaymentRecord>, Box<dyn std::error::Error>> {
    let data = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data)?)
}

fn save_payments(path: &PathBuf, list: &[PaymentRecord]) -> Result<(), Box<dyn std::error::Error>> {
    let data = serde_json::to_string_pretty(list)?;
    fs::write(path, data)?;
    Ok(())
}
