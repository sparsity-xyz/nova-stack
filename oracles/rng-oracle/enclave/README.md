# RNG Enclave Service

The off-chain TEE (Trusted Execution Environment) service for the Random Number Generator.

## Overview

This service runs inside an AWS Nitro Enclave and:
- Listens for `RandomNumberRequested` events from the RNG contract
- Generates cryptographically secure random numbers using the enclave's secure random source
- Signs and submits fulfillment transactions to the blockchain

## Files

| File | Description |
|------|-------------|
| `main.py` | FastAPI application and event listener |
| `odyn.py` | Odyn API wrapper (attestation, signing, random, encryption) |
| `config.py` | Configuration settings |
| `abi.json` | RNG contract ABI |
| `requirements.txt` | Python dependencies |
| `Dockerfile` | Container build file |
| `consumer-dist/` | Built consumer frontend (from consumer project) |

## Quick Start

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure

Edit `config.py` with your settings:
```python
CONTRACT_ADDRESS = "0x..."  # RNG contract address
RPC_URL = "https://sepolia.base.org"  # RPC endpoint
```

The Odyn API endpoint is automatically detected:
- In enclave (when `IN_ENCLAVE=True`): `http://localhost:18000`
- Local development: `http://odyn.sparsity.cloud:18000` (mock API)

### Run

```bash
python main.py
```

The service starts on `http://0.0.0.0:8000`.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Service status, operator info, balance |
| `/request/{request_id}` | GET | Get specific request details |
| `/consumer` | - | Consumer frontend UI |

## Service Status

```bash
curl http://localhost:8000/
```

Response:
```json
{
    "service": "RNG Oracle",
    "version": "1.0.0",
    "status": "running",
    "is_operator": true,
    "contract_address": "0x...",
    "operator": "0x...",
    "operator_balance": 0.998857,
    "processed_requests": 0,
    "explorer": "https://sepolia.basescan.org/address/0x...",
    "consumer": "http://localhost:8000/consumer"
}
```

## Startup Sequence

When the RNG enclave service starts, it goes through the following initialization process:

```
┌─────────────────────────────────────────────────────────────────┐
│                     RNG Enclave Startup                         │
├─────────────────────────────────────────────────────────────────┤
│  1. Odyn generates random ETH wallet (secp256k1 keypair)        │
│     └─> Wallet address: 0x...                                   │
│                                                                 │
│  2. Service connects to RPC and loads RNG contract              │
│     └─> Contract: 0x5a5De...                                    │
│                                                                 │
│  3. Service checks if wallet is registered as operator          │
│     └─> contract.isOperator(wallet_address)                     │
│                                                                 │
│  4. If NOT operator, service waits and polls...                 │
│     ┌──────────────────────────────────────────────────────┐    │
│     │  CONTRACT OWNER must call:                           │    │
│     │  contract.setOperator(wallet_address, true)          │    │
│     └──────────────────────────────────────────────────────┘    │
│                                                                 │
│  5. Once authorized, service starts listening for events        │
│     └─> Ready to fulfill random number requests                 │
└─────────────────────────────────────────────────────────────────┘
```

### Operator Registration

There are **two ways** to register the TEE wallet as an operator:

#### Method 1: Via NovaRegistry (Recommended for Production)

In production, the **Sparsity Nova Platform** uses a NovaRegistry contract to manage TEE wallets across multiple apps:

```
┌─────────────────────┐      setNovaRegistry()      ┌─────────────────────┐
│   Contract Owner    │ ────────────────────────────▶ │   RNG Contract      │
└─────────────────────┘                              │                     │
                                                     │ novaRegistryAddress │
┌─────────────────────┐      registerTEEWallet()     │         ↓           │
│   NovaRegistry      │ ────────────────────────────▶ │ operators[wallet]   │
│   (Platform)        │         onlyRegistry         │       = true        │
└─────────────────────┘                              └─────────────────────┘
```

1. **Contract owner** calls `setNovaRegistry(registryAddress)` to set the NovaRegistry contract address
2. **NovaRegistry** (platform-controlled) calls `registerTEEWallet(teeWalletAddress)` to register the enclave's wallet
3. The RNG contract verifies the caller is the registry (`onlyRegistry` modifier) and sets the wallet as operator

#### Method 2: Direct Owner Registration (For Testing/Development)

For testing or when not using the platform registry:

```bash
# Contract owner can directly add operator
npx hardhat run scripts/register-operator.js --network baseSepolia -- <tee_wallet_address>
```

This calls `addOperator(address)` which is restricted to `onlyOwner`.

### Funding the TEE Wallet

Before the enclave can submit transactions, the TEE wallet needs ETH for gas:

1. **Get the wallet address** from the service status endpoint (`/`)
2. **Send ETH** to the wallet address (e.g., 0.1 ETH for testing)

The service will automatically detect the authorization and begin processing requests.

## How It Works

1. **Startup**: Service connects to RPC and loads contract
2. **Wait for Authorization**: Polls until TEE wallet is registered as operator
3. **Event Listening**: Creates filter for `RandomNumberRequested` events
4. **Random Generation**: When event received:
   - Gets secure random bytes from enclave via Odyn API
   - Seeds Python's random module
   - Generates requested random numbers in range
5. **Transaction Submission**:
   - Builds `fulfillRandomNumber` transaction
   - Signs using enclave's ETH key via Odyn API
   - Submits to blockchain
6. **Callback**: Contract triggers user's callback if specified

## Dependencies

- `fastapi` / `uvicorn` - Web framework
- `web3` - Ethereum interaction
- `requests` - HTTP client for Odyn API

## Environment Variables

| Variable | Description |
|----------|-------------|
| `IN_ENCLAVE` | Set to `True` when running inside enclave (auto-set in Dockerfile) |

## For Local Development

When testing locally without an actual enclave, the Odyn class automatically uses the mock API at `http://odyn.sparsity.cloud:18000`. No configuration needed.

## License

Apache-2.0
