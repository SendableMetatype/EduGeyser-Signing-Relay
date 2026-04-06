# EduGeyser Signing Relay

A Rust service that re-signs Minecraft Education Edition skin data using Xbox/Mojang-authenticated credentials, enabling education player skins to work through the [GeyserMC global API](https://github.com/GeyserMC/global_api) skin pipeline.

Companion service for [EduGeyser](https://github.com/SendableMetatype/EduGeyser).

## Why This Exists

Education Edition players' JWT chains are self-signed. The GeyserMC global API validates chains from Mojang's root key, so education chains are rejected. This relay re-signs skin data with a legitimate Xbox-authenticated chain so the global API accepts it.

## Quick Start

```bash
# Build
cargo build --release

# Add Xbox accounts (repeat for each account)
./target/release/edugeyser-signing-relay add-account

# Start the server
./target/release/edugeyser-signing-relay serve
```

## Account Management

Accounts are stored in `accounts.json` (configurable via `ACCOUNTS_FILE` env var). Add as many as you like.

```bash
# Add an account via device code flow, you sign in at microsoft.com/devicelogin
./edugeyser-signing-relay add-account

# List all configured accounts
./edugeyser-signing-relay list-accounts

# Remove an account by index
./edugeyser-signing-relay remove-account 2
```

Each account needs a free Microsoft account that has logged into Minecraft at least once. The relay round-robins across healthy accounts and skips any that are down, so more accounts means more redundancy.

Chains are refreshed every 30 minutes. If Microsoft rotates a refresh token during renewal, the updated token is automatically persisted to the accounts file.

## API

### `POST /sign`

Re-signs education skin data with a legitimate Xbox/Mojang chain.

**Request:**
```json
{
  "client_data": "<education client_data JWT>"
}
```

**Response:**
```json
{
  "chain_data": ["<jwt1>", "<jwt2>", "<jwt3>"],
  "client_data": "<re-signed client_data JWT>",
  "hash": "<hex SHA256 of converted 64x64 RGBA>",
  "is_steve": true
}
```

The public key in the JWT `x5u` header is encoded as DER SubjectPublicKeyInfo (SPKI), matching what the Mojang auth endpoint expects.

### `GET /health`

Returns account pool health status.

```json
{
  "healthy_accounts": 3,
  "total_accounts": 3,
  "status": "ok"
}
```

Status is `ok` when all accounts are healthy, `degraded` when some are down, `unhealthy` when none are available.

### `GET /stats`

Returns request statistics. Stats are persisted to disk every 60 seconds.

```json
{
  "total_requests": 1042,
  "successful": 1038,
  "failed_bad_request": 3,
  "failed_no_session": 1,
  "failed_internal": 0,
  "unique_skins": 87,
  "avg_response_ms": 12.45,
  "started_at": "2026-04-01T12:00:00Z"
}
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BIND_ADDR` | `0.0.0.0:8080` | Listen address |
| `ACCOUNTS_FILE` | `accounts.json` | Path to accounts file |
| `STATS_FILE` | `stats.json` | Path to stats persistence file |
| `MS_CLIENT_ID` | `00000000441cc96b` | Microsoft OAuth client ID |
| `RUST_LOG` | `edugeyser_signing_relay=info` | Log level |

## Docker

```bash
# Build
docker build -t edugeyser-relay .

# Add accounts (interactive, needs a terminal)
docker run -it -v ./data:/data edugeyser-relay add-account

# Run server
docker run -d -p 8080:8080 -v ./data:/data edugeyser-relay serve
```

## How It Works

1. EduGeyser sends an education player's `client_data` JWT to `POST /sign`
2. The relay decodes the skin, runs the same conversion pipeline as the global API
3. Computes the SHA256 hash of the converted RGBA (identical to global API output)
4. Signs a new `client_data` JWT with a legitimate Xbox account's P-384 key (SPKI-encoded)
5. Returns the signed JWT, Mojang-authenticated chain, and hash
6. EduGeyser feeds this into the normal global API WebSocket flow

The skin conversion code is ported directly from `GeyserMC/global_api/native/skins/src/` to ensure hash-identical output.

## License

MIT
