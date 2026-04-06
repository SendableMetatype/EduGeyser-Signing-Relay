mod common;
mod skin_convert;
mod auth;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn, error};

use crate::auth::{AuthPool, authenticate_session, sign_client_data};
use crate::skin_convert::{convert_skin, ConvertResult};

// ── Accounts file ──────────────────────────────────────────────────────

const DEFAULT_ACCOUNTS_FILE: &str = "accounts.json";
const DEFAULT_CLIENT_ID: &str = "00000000441cc96b";

#[derive(Serialize, Deserialize, Clone)]
struct SavedAccount {
    label: String,
    refresh_token: String,
}

#[derive(Serialize, Deserialize, Default)]
struct AccountsFile {
    accounts: Vec<SavedAccount>,
}

fn accounts_path() -> PathBuf {
    std::env::var("ACCOUNTS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_ACCOUNTS_FILE))
}

fn load_accounts() -> AccountsFile {
    let path = accounts_path();
    if !path.exists() {
        return AccountsFile::default();
    }
    let data = std::fs::read_to_string(&path).expect("failed to read accounts file");
    serde_json::from_str(&data).expect("failed to parse accounts file")
}

fn save_accounts(accounts: &AccountsFile) {
    let path = accounts_path();
    let data = serde_json::to_string_pretty(accounts).expect("failed to serialize accounts");
    std::fs::write(&path, data).expect("failed to write accounts file");
}

// ── Stats ──────────────────────────────────────────────────────────────

const DEFAULT_STATS_FILE: &str = "stats.json";

fn stats_path() -> PathBuf {
    std::env::var("STATS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STATS_FILE))
}

#[derive(Serialize, Deserialize, Default)]
struct PersistedStats {
    total_requests: u64,
    successful: u64,
    failed_bad_request: u64,
    failed_no_session: u64,
    failed_internal: u64,
    unique_hashes: Vec<String>,
    total_response_ms: u64,
}

struct Stats {
    total_requests: AtomicU64,
    successful: AtomicU64,
    failed_bad_request: AtomicU64,
    failed_no_session: AtomicU64,
    failed_internal: AtomicU64,
    total_response_ms: AtomicU64,
    unique_hashes: RwLock<HashSet<String>>,
    started_at: String,
}

impl Stats {
    fn load() -> Self {
        let path = stats_path();
        let persisted: PersistedStats = if path.exists() {
            let data = std::fs::read_to_string(&path).unwrap_or_default();
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            PersistedStats::default()
        };

        let unique_hashes: HashSet<String> = persisted.unique_hashes.into_iter().collect();

        Stats {
            total_requests: AtomicU64::new(persisted.total_requests),
            successful: AtomicU64::new(persisted.successful),
            failed_bad_request: AtomicU64::new(persisted.failed_bad_request),
            failed_no_session: AtomicU64::new(persisted.failed_no_session),
            failed_internal: AtomicU64::new(persisted.failed_internal),
            total_response_ms: AtomicU64::new(persisted.total_response_ms),
            unique_hashes: RwLock::new(unique_hashes),
            started_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    async fn persist(&self) {
        let hashes = self.unique_hashes.read().await;
        let persisted = PersistedStats {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            successful: self.successful.load(Ordering::Relaxed),
            failed_bad_request: self.failed_bad_request.load(Ordering::Relaxed),
            failed_no_session: self.failed_no_session.load(Ordering::Relaxed),
            failed_internal: self.failed_internal.load(Ordering::Relaxed),
            total_response_ms: self.total_response_ms.load(Ordering::Relaxed),
            unique_hashes: hashes.iter().cloned().collect(),
        };
        drop(hashes);

        let path = stats_path();
        if let Ok(data) = serde_json::to_string_pretty(&persisted) {
            if let Err(e) = std::fs::write(&path, data) {
                warn!("Failed to persist stats: {}", e);
            }
        }
    }
}

// ── CLI ────────────────────────────────────────────────────────────────

fn print_usage() {
    eprintln!("EduGeyser Signing Relay");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  edugeyser-signing-relay serve                  Start the HTTP server (default)");
    eprintln!("  edugeyser-signing-relay add-account            Add an Xbox account via device code login");
    eprintln!("  edugeyser-signing-relay list-accounts           List configured accounts");
    eprintln!("  edugeyser-signing-relay remove-account <index>  Remove an account by index");
    eprintln!();
    eprintln!("Environment:");
    eprintln!("  BIND_ADDR       Listen address (default: 0.0.0.0:8080)");
    eprintln!("  ACCOUNTS_FILE   Path to accounts file (default: accounts.json)");
    eprintln!("  STATS_FILE      Path to stats file (default: stats.json)");
    eprintln!("  MS_CLIENT_ID    Microsoft OAuth client ID");
    eprintln!("  RUST_LOG        Log level");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("serve");

    match command {
        "serve" => cmd_serve().await,
        "add-account" => cmd_add_account().await,
        "list-accounts" | "list" => cmd_list_accounts(),
        "remove-account" | "remove" => {
            let index = args.get(2)
                .and_then(|s| s.parse::<usize>().ok())
                .expect("Usage: remove-account <index>");
            cmd_remove_account(index);
        }
        "help" | "--help" | "-h" => print_usage(),
        _ => {
            eprintln!("Unknown command: {}", command);
            print_usage();
            std::process::exit(1);
        }
    }
}

// ── add-account ────────────────────────────────────────────────────────

async fn cmd_add_account() {
    let client_id = std::env::var("MS_CLIENT_ID")
        .unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string());

    let mut accounts = load_accounts();
    let index = accounts.accounts.len();
    let label = format!("account-{}", index);

    println!("Adding Xbox account '{}'...", label);
    println!();

    let pool = AuthPool::new(1);
    let session = pool.get_by_index(0).unwrap();

    authenticate_session(session.clone(), &client_id, None)
        .await
        .expect("Authentication failed");

    let guard = session.read().await;
    let refresh_token = guard.refresh_token.clone()
        .expect("No refresh token returned — authentication may have failed");
    drop(guard);

    accounts.accounts.push(SavedAccount {
        label: label.clone(),
        refresh_token,
    });

    save_accounts(&accounts);

    println!();
    println!("Account '{}' added successfully.", label);
    println!("Total accounts: {}", accounts.accounts.len());
    println!("Saved to: {}", accounts_path().display());
}

// ── list-accounts ──────────────────────────────────────────────────────

fn cmd_list_accounts() {
    let accounts = load_accounts();

    if accounts.accounts.is_empty() {
        println!("No accounts configured.");
        println!("Run 'add-account' to add one.");
        return;
    }

    println!("Configured accounts ({}):", accounts.accounts.len());
    for (i, account) in accounts.accounts.iter().enumerate() {
        let token_preview = if account.refresh_token.len() > 16 {
            format!("{}...", &account.refresh_token[..16])
        } else {
            account.refresh_token.clone()
        };
        println!("  [{}] {} (token: {})", i, account.label, token_preview);
    }
}

// ── remove-account ─────────────────────────────────────────────────────

fn cmd_remove_account(index: usize) {
    let mut accounts = load_accounts();

    if index >= accounts.accounts.len() {
        eprintln!("Index {} out of range (have {} accounts)", index, accounts.accounts.len());
        std::process::exit(1);
    }

    let removed = accounts.accounts.remove(index);
    save_accounts(&accounts);

    println!("Removed account '{}' (index {})", removed.label, index);
    println!("Remaining accounts: {}", accounts.accounts.len());
}

// ── App State ─────────────────────────────────────────────────────────

struct AppState {
    pool: AuthPool,
    stats: Stats,
}

// ── serve ──────────────────────────────────────────────────────────────

async fn cmd_serve() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "edugeyser_signing_relay=info".into())
        )
        .json()
        .init();

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let client_id = std::env::var("MS_CLIENT_ID")
        .unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string());

    let accounts = load_accounts();

    if accounts.accounts.is_empty() {
        error!("No accounts configured. Run 'add-account' first.");
        std::process::exit(1);
    }

    info!("Starting EduGeyser Signing Relay");
    info!("Bind address: {}", bind_addr);
    info!("Accounts: {}", accounts.accounts.len());

    let pool = AuthPool::new(accounts.accounts.len());

    for (i, account) in accounts.accounts.iter().enumerate() {
        let session = pool.get_by_index(i).unwrap();
        let cid = client_id.clone();
        let refresh = account.refresh_token.clone();
        let label = account.label.clone();

        tokio::spawn(async move {
            match authenticate_session(session, &cid, Some(&refresh)).await {
                Ok(()) => info!("Account '{}' authenticated", label),
                Err(e) => error!("Account '{}' failed: {}", label, e),
            }
        });
    }

    // Periodic chain refresh every 30 minutes
    let refresh_pool_sessions: Vec<_> = (0..pool.len())
        .filter_map(|i| pool.get_by_index(i))
        .collect();
    let refresh_cid = client_id.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30 * 60));
        interval.tick().await;
        loop {
            interval.tick().await;
            info!("Refreshing chains...");
            let mut tokens_changed = false;

            for (i, session) in refresh_pool_sessions.iter().enumerate() {
                let old_token = session.read().await.refresh_token.clone();
                if let Some(ref token) = old_token {
                    if let Err(e) = authenticate_session(session.clone(), &refresh_cid, Some(token)).await {
                        warn!("Account {} refresh failed: {}", i, e);
                    } else {
                        let new_token = session.read().await.refresh_token.clone();
                        if new_token != old_token {
                            tokens_changed = true;
                        }
                    }
                }
            }

            if tokens_changed {
                let mut accounts = load_accounts();
                for (i, session) in refresh_pool_sessions.iter().enumerate() {
                    if let Some(ref new_token) = session.read().await.refresh_token {
                        if let Some(account) = accounts.accounts.get_mut(i) {
                            account.refresh_token = new_token.clone();
                        }
                    }
                }
                save_accounts(&accounts);
                info!("Persisted rotated refresh tokens to {}", accounts_path().display());
            }
        }
    });

    let stats = Stats::load();
    info!("Stats loaded: {} total requests, {} unique skins",
        stats.total_requests.load(Ordering::Relaxed),
        stats.unique_hashes.read().await.len(),
    );

    let state = Arc::new(AppState { pool, stats });

    // Persist stats every 60 seconds
    let persist_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            persist_state.stats.persist().await;
        }
    });

    let app = Router::new()
        .route("/sign", post(handle_sign))
        .route("/health", get(handle_health))
        .route("/stats", get(handle_stats))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    info!("Listening on {}", bind_addr);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ── Request/response types ─────────────────────────────────────────────

#[derive(Deserialize)]
struct SignRequest {
    client_data: String,
}

#[derive(Serialize)]
struct SignResponse {
    chain_data: Vec<String>,
    client_data: String,
    hash: String,
    is_steve: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct HealthResponse {
    healthy_accounts: usize,
    total_accounts: usize,
    status: String,
}

#[derive(Serialize)]
struct StatsResponse {
    total_requests: u64,
    successful: u64,
    failed_bad_request: u64,
    failed_no_session: u64,
    failed_internal: u64,
    unique_skins: usize,
    avg_response_ms: f64,
    started_at: String,
}

// ── Handlers ───────────────────────────────────────────────────────────

async fn handle_sign(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, (StatusCode, Json<ErrorResponse>)> {
    let start = std::time::Instant::now();
    state.stats.total_requests.fetch_add(1, Ordering::Relaxed);

    let result = process_sign(&state, &req, start).await;

    let elapsed_ms = start.elapsed().as_millis() as u64;
    state.stats.total_response_ms.fetch_add(elapsed_ms, Ordering::Relaxed);

    match &result {
        Ok(resp) => {
            state.stats.successful.fetch_add(1, Ordering::Relaxed);
            state.stats.unique_hashes.write().await.insert(resp.hash.clone());
        }
        Err((status, _)) => {
            match *status {
                StatusCode::BAD_REQUEST => state.stats.failed_bad_request.fetch_add(1, Ordering::Relaxed),
                StatusCode::SERVICE_UNAVAILABLE => state.stats.failed_no_session.fetch_add(1, Ordering::Relaxed),
                _ => state.stats.failed_internal.fetch_add(1, Ordering::Relaxed),
            };
        }
    }

    result
}

async fn process_sign(
    state: &AppState,
    req: &SignRequest,
    start: std::time::Instant,
) -> Result<Json<SignResponse>, (StatusCode, Json<ErrorResponse>)> {
    let client_claims = decode_jwt_payload(&req.client_data)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            error: format!("failed to decode client_data JWT: {}", e),
        })))?;

    let (hash_hex, is_steve) = match convert_skin(&client_claims) {
        ConvertResult::Success(image_data, is_steve) => {
            (hex::encode(image_data.hash.as_ref()), is_steve)
        }
        ConvertResult::Invalid(err) => {
            return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
                error: format!("skin conversion failed: {:?}", err),
            })));
        }
        ConvertResult::Error(err) => {
            return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse {
                error: format!("skin conversion error: {}", err),
            })));
        }
    };

    let session_arc = state.pool.get_session().await
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse {
            error: "no healthy Xbox sessions available".to_string(),
        })))?;

    let session = session_arc.read().await;

    let signed_client_data = sign_client_data(&session, &client_claims)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            error: format!("JWT signing failed: {}", e),
        })))?;

    let chain_data = session.chain.clone();
    drop(session);

    info!(
        hash = %hash_hex,
        is_steve = is_steve,
        elapsed_ms = start.elapsed().as_millis(),
        "Signed education skin"
    );

    Ok(Json(SignResponse {
        chain_data,
        client_data: signed_client_data,
        hash: hash_hex,
        is_steve,
    }))
}

async fn handle_health(
    State(state): State<Arc<AppState>>,
) -> Json<HealthResponse> {
    let (healthy, total) = state.pool.health().await;

    Json(HealthResponse {
        healthy_accounts: healthy,
        total_accounts: total,
        status: if healthy == total { "ok" }
               else if healthy > 0 { "degraded" }
               else { "unhealthy" }.to_string(),
    })
}

async fn handle_stats(
    State(state): State<Arc<AppState>>,
) -> Json<StatsResponse> {
    let total = state.stats.total_requests.load(Ordering::Relaxed);
    let total_ms = state.stats.total_response_ms.load(Ordering::Relaxed);
    let avg_ms = if total > 0 { total_ms as f64 / total as f64 } else { 0.0 };

    Json(StatsResponse {
        total_requests: total,
        successful: state.stats.successful.load(Ordering::Relaxed),
        failed_bad_request: state.stats.failed_bad_request.load(Ordering::Relaxed),
        failed_no_session: state.stats.failed_no_session.load(Ordering::Relaxed),
        failed_internal: state.stats.failed_internal.load(Ordering::Relaxed),
        unique_skins: state.stats.unique_hashes.read().await.len(),
        avg_response_ms: (avg_ms * 100.0).round() / 100.0,
        started_at: state.stats.started_at.clone(),
    })
}

// ── Utility ────────────────────────────────────────────────────────────

fn decode_jwt_payload(jwt: &str) -> Result<Value, String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("JWT must have 3 parts".to_string());
    }

    let payload_bytes = BASE64URL.decode(parts[1])
        .or_else(|_| {
            let padded = match parts[1].len() % 4 {
                2 => format!("{}==", parts[1]),
                3 => format!("{}=", parts[1]),
                _ => parts[1].to_string(),
            };
            BASE64URL.decode(&padded)
        })
        .or_else(|_| BASE64.decode(parts[1]))
        .map_err(|e| format!("base64 decode failed: {}", e))?;

    serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("JSON parse failed: {}", e))
}
