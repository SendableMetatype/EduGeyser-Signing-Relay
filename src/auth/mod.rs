use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL};
use p384::ecdsa::{SigningKey, signature::Signer};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::info;

/// Holds the authenticated state for one Xbox/Mojang account.
#[derive(Clone)]
pub struct XboxSession {
    /// The Mojang-signed JWT chain for this account (2-3 JWTs).
    pub chain: Vec<String>,
    /// The ES384 signing key (P-384 private key) whose public key terminates the chain.
    pub signing_key: SigningKey,
    /// The public key in base64 (DER SubjectPublicKeyInfo), for JWT x5u header.
    pub public_key_base64: String,
    /// When the chain expires (unix seconds).
    pub chain_expires: u64,
    /// Whether this session is healthy and ready to sign.
    pub healthy: bool,
    /// The refresh token for re-authentication.
    pub refresh_token: Option<String>,
}

/// Pool of Xbox sessions with round-robin selection.
pub struct AuthPool {
    sessions: Vec<Arc<RwLock<XboxSession>>>,
    next_index: RwLock<usize>,
}

impl AuthPool {
    /// Create a pool with placeholder sessions that will be authenticated later.
    pub fn new(count: usize) -> Self {
        let mut sessions = Vec::with_capacity(count);
        for _ in 0..count {
            let key = SigningKey::random(&mut rand::thread_rng());
            let public_key = key.verifying_key();
            let point = public_key.to_encoded_point(false);
            // DER SubjectPublicKeyInfo prefix for P-384 (OID 1.3.132.0.34)
            const P384_SPKI_PREFIX: &[u8] = &[
                0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86,
                0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B,
                0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
            ];
            let mut spki = Vec::with_capacity(P384_SPKI_PREFIX.len() + point.as_bytes().len());
            spki.extend_from_slice(P384_SPKI_PREFIX);
            spki.extend_from_slice(point.as_bytes());
            let public_key_base64 = BASE64.encode(&spki);

            sessions.push(Arc::new(RwLock::new(XboxSession {
                chain: Vec::new(),
                signing_key: key,
                public_key_base64,
                chain_expires: 0,
                healthy: false,
                refresh_token: None,
            })));
        }

        AuthPool {
            sessions,
            next_index: RwLock::new(0),
        }
    }

    /// Get the next healthy session via round-robin.
    pub async fn get_session(&self) -> Option<Arc<RwLock<XboxSession>>> {
        let len = self.sessions.len();
        let mut index = self.next_index.write().await;

        for _ in 0..len {
            let session = &self.sessions[*index];
            *index = (*index + 1) % len;

            let guard = session.read().await;
            if guard.healthy && guard.chain_expires > now_secs() + 300 {
                drop(guard);
                return Some(session.clone());
            }
        }

        None
    }

    /// Get a session by index for initial authentication.
    pub fn get_by_index(&self, index: usize) -> Option<Arc<RwLock<XboxSession>>> {
        self.sessions.get(index).cloned()
    }

    /// Get the number of sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Get health status: (healthy_count, total_count)
    pub async fn health(&self) -> (usize, usize) {
        let mut healthy = 0;
        for session in &self.sessions {
            let guard = session.read().await;
            if guard.healthy {
                healthy += 1;
            }
        }
        (healthy, self.sessions.len())
    }
}

/// Authenticate a session using the Xbox Live flow.
/// This is the same flow Geyser uses for online-mode authentication:
/// 1. OAuth2 device code → MS access token
/// 2. MS token → Xbox Live user token
/// 3. Xbox user token → XSTS token
/// 4. XSTS token + our public key → Mojang-signed chain
pub async fn authenticate_session(
    session: Arc<RwLock<XboxSession>>,
    client_id: &str,
    refresh_token: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let http = reqwest::Client::new();

    // Step 1: Get MS access token (via refresh token or device code)
    let ms_token = if let Some(refresh) = refresh_token {
        refresh_ms_token(&http, client_id, refresh).await?
    } else {
        // Device code flow for initial setup
        device_code_flow(&http, client_id).await?
    };

    let access_token = ms_token["access_token"].as_str()
        .ok_or("missing access_token")?;
    let new_refresh = ms_token["refresh_token"].as_str()
        .map(String::from);

    // Step 2: Xbox Live user token
    let xbox_token = xbox_live_authenticate(&http, access_token).await?;
    let xbox_user_token = xbox_token["Token"].as_str()
        .ok_or("missing Xbox Token")?;
    let user_hash = xbox_token["DisplayClaims"]["xui"][0]["uhs"].as_str()
        .ok_or("missing user hash")?;

    // Step 3: XSTS token
    let xsts_token = xsts_authorize(&http, xbox_user_token).await?;
    let xsts_token_str = xsts_token["Token"].as_str()
        .ok_or("missing XSTS Token")?;

    // Step 4: Minecraft auth → signed chain
    let guard = session.read().await;
    let pub_key_b64 = guard.public_key_base64.clone();
    drop(guard);

    let mc_chain = minecraft_authenticate(&http, xsts_token_str, user_hash, &pub_key_b64).await?;

    let chain_array = mc_chain.as_array()
        .ok_or("chain is not an array")?;

    let chain: Vec<String> = chain_array.iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    if chain.is_empty() {
        return Err("empty chain returned from Minecraft auth".into());
    }

    // Parse expiry from the last chain JWT
    let expires = parse_jwt_expiry(chain.last().unwrap())
        .unwrap_or(now_secs() + 86400);

    // Update session
    let mut guard = session.write().await;
    guard.chain = chain;
    guard.chain_expires = expires;
    guard.healthy = true;
    guard.refresh_token = new_refresh.or(guard.refresh_token.take());
    info!("Xbox session authenticated, expires in {} hours", (expires - now_secs()) / 3600);

    Ok(())
}

async fn refresh_ms_token(
    http: &reqwest::Client,
    client_id: &str,
    refresh_token: &str,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let resp = http.post("https://login.live.com/oauth20_token.srf")
        .form(&[
            ("client_id", client_id),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
            ("scope", "XboxLive.signin XboxLive.offline_access"),
        ])
        .send().await?
        .error_for_status()
        .map_err(|e| format!("MS token refresh HTTP error: {}", e))?
        .json::<Value>().await?;

    if resp.get("error").is_some() {
        return Err(format!("MS token refresh failed: {}", resp).into());
    }

    Ok(resp)
}

async fn device_code_flow(
    http: &reqwest::Client,
    client_id: &str,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    // Request device code
    let device_resp = http.post("https://login.live.com/oauth20_connect.srf")
        .form(&[
            ("client_id", client_id),
            ("scope", "XboxLive.signin XboxLive.offline_access"),
            ("response_type", "device_code"),
        ])
        .send().await?
        .json::<Value>().await?;

    let device_code = device_resp["device_code"].as_str()
        .ok_or("missing device_code")?;
    let user_code = device_resp["user_code"].as_str()
        .ok_or("missing user_code")?;
    let verification_uri = device_resp["verification_uri"].as_str()
        .unwrap_or("https://microsoft.com/devicelogin");
    let interval = device_resp["interval"].as_u64().unwrap_or(5);

    println!("=== XBOX AUTHENTICATION REQUIRED ===");
    println!("Go to: {}", verification_uri);
    println!("Enter code: {}", user_code);
    println!("====================================");

    // Poll for token
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;

        let poll_resp = http.post("https://login.live.com/oauth20_token.srf")
            .form(&[
                ("client_id", client_id),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send().await?
            .json::<Value>().await?;

        if poll_resp.get("access_token").is_some() {
            return Ok(poll_resp);
        }

        let error = poll_resp["error"].as_str().unwrap_or("");
        match error {
            "authorization_pending" => continue,
            "slow_down" => {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
            _ => return Err(format!("Device code poll error: {}", poll_resp).into()),
        }
    }
}

async fn xbox_live_authenticate(
    http: &reqwest::Client,
    ms_access_token: &str,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let body = json!({
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": format!("d={}", ms_access_token)
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    });

    let resp = http.post("https://user.auth.xboxlive.com/user/authenticate")
        .json(&body)
        .send().await?
        .error_for_status()
        .map_err(|e| format!("Xbox Live auth HTTP error: {}", e))?
        .json::<Value>().await?;

    if resp.get("Token").is_none() {
        return Err(format!("Xbox Live auth failed: {}", resp).into());
    }

    Ok(resp)
}

async fn xsts_authorize(
    http: &reqwest::Client,
    xbox_user_token: &str,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let body = json!({
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbox_user_token]
        },
        "RelyingParty": "https://multiplayer.minecraft.net/",
        "TokenType": "JWT"
    });

    let resp = http.post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .json(&body)
        .send().await?
        .error_for_status()
        .map_err(|e| format!("XSTS auth HTTP error: {}", e))?
        .json::<Value>().await?;

    if resp.get("Token").is_none() {
        return Err(format!("XSTS auth failed: {}", resp).into());
    }

    Ok(resp)
}

async fn minecraft_authenticate(
    http: &reqwest::Client,
    xsts_token: &str,
    user_hash: &str,
    public_key_base64: &str,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let body = json!({
        "identityPublicKey": public_key_base64
    });

    let resp = http.post("https://multiplayer.minecraft.net/authentication")
        .header("Authorization", format!("XBL3.0 x={};{}", user_hash, xsts_token))
        .json(&body)
        .send().await?
        .error_for_status()
        .map_err(|e| format!("Minecraft auth HTTP error: {}", e))?
        .json::<Value>().await?;

    // The response contains a chain field with the signed JWTs
    let chain = resp.get("chain")
        .ok_or("missing chain in Minecraft auth response")?;

    Ok(chain.clone())
}

/// Build a signed client_data JWT using the session's key.
pub fn sign_client_data(session: &XboxSession, client_claims: &Value) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let header = json!({
        "alg": "ES384",
        "x5u": session.public_key_base64
    });

    let header_b64 = BASE64URL.encode(serde_json::to_vec(&header)?);
    let payload_b64 = BASE64URL.encode(serde_json::to_vec(client_claims)?);

    let message = format!("{}.{}", header_b64, payload_b64);

    // Sign with P-384 — produces a fixed-size r||s signature directly
    let signature: p384::ecdsa::Signature = session.signing_key.sign(message.as_bytes());
    let sig_b64 = BASE64URL.encode(signature.to_bytes());

    Ok(format!("{}.{}.{}", header_b64, payload_b64, sig_b64))
}

fn parse_jwt_expiry(jwt: &str) -> Option<u64> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let payload = BASE64URL.decode(parts[1]).ok()
        .or_else(|| BASE64.decode(parts[1]).ok())?;
    let claims: Value = serde_json::from_slice(&payload).ok()?;
    claims["exp"].as_u64()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
