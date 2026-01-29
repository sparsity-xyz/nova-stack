# Nova Contracts

Smart contracts for the Sparsity Nova Platform, including the SparsityAppRegistry for on-chain TEE application registration.

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) installed
- Base Sepolia testnet ETH (get from [faucet](https://www.alchemy.com/faucets/base-sepolia))

## Setup

### 1. Install Dependencies

Since the `lib/` directory is ignored by Git to keep the repository clean, you must install the dependencies manually:

```bash
cd app-registry
forge install
```

### 2. Configure Environment

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

| Variable | Description | Example |
|----------|-------------|---------|
| `PRIVATE_KEY` | Deployer wallet private key | `0xabc123...` |
| `RPC_URL` | Base Sepolia RPC endpoint | `https://sepolia.base.org` |

> **Important:** Use the format `VAR=value` without the `export` keyword. The Makefile uses `include .env` which requires this format.

**Example `.env`:**
```bash
PRIVATE_KEY=0xyour_private_key_here
RPC_URL=https://sepolia.base.org
```

### 3. Required Files

Ensure these files exist in `samples/`:
- `aws_root.der` - AWS Nitro root certificate
- `sp1_program_id.json` - SP1 program configuration

## Contract Architecture

```
┌────────────────────────┐
│   SparsityAppRegistry  │  ← Main registry for TEE apps
├────────────────────────┤
│ registerAppWithZKP()   │  ← Register with ZK proof verification
│ registerAppWithoutZKP()│  ← Register without ZK proof (zkVerified=false)
│ removeApp()            │
└─────────┬──────────────┘
          │ verifies via (for ZKP registration)
          ▼
┌──────────────────────┐
│ NitroEnclaveVerifier │  ← Verifies ZK proofs of attestations
├──────────────────────┤
│ verify()             │  (has onlyOwner functions)
│ batchVerify()        │
│ setRootCert()        │
│ setZkConfiguration() │
└─────────┬────────────┘
          │ uses
          ▼
┌──────────────────────┐
│     SP1 Verifier     │  ← Succinct SP1 ZK proof system
└──────────────────────┘   (no owner, anyone can use)
```

### Libraries
- **JsonParser** - Gas-optimized library for extracting `eth_addr` from JSON userData in attestations

## Deployment

### Option 1: Atomic Deployment (Recommended)

Deploys all contracts in a single transaction:

```bash
source .env
make deploy-atomic
```

This deploys and configures:
1. **SP1 Verifier** - ZK proof verification
2. **NitroEnclaveVerifier** - AWS Nitro attestation verification
3. **SparsityAppRegistry** - TEE app registration registry

### Option 2: Step-by-Step Deployment

```bash
source .env
make deploy-all
```

This runs each step separately with detailed output.

## Deployment Reuse Logic

The deployment scripts use `deployments/<chainId>.json` to track deployed contracts. This enables **smart reuse**:

| Contract | Ownership | Reuse Behavior |
|----------|-----------|----------------|
| **SP1_VERIFIER** | No owner | Always reused if exists. Safe because it has no admin functions. |
| **VERIFIER** (NitroEnclaveVerifier) | Has owner | Reused if exists. **Warning:** Only the original deployer can call `setRootCert()` and `setZkConfiguration()`. |
| **REGISTRY** (SparsityAppRegistry) | Has owner | Reused if exists. Only the original deployer can call admin functions. |

### Forcing a Redeploy

If you need to redeploy a contract (e.g., you're using a different private key than the original deployer):

1. **Check current deployments:**
   ```bash
   cat deployments/84532.json
   ```

2. **Remove the entry you want to redeploy:**
   
   Edit `deployments/<chainId>.json` and remove the contract entry. For example, to redeploy `VERIFIER`:
   
   Before:
   ```json
   {"REGISTRY":"0x...","SP1_VERIFIER":"0x...","VERIFIER":"0x..."}
   ```
   
   After:
   ```json
   {"REGISTRY":"0x...","SP1_VERIFIER":"0x..."}
   ```

3. **Redeploy:**
   ```bash
   source .env
   make deploy-all
   ```

> **Note:** If you redeploy `VERIFIER`, you should also redeploy `REGISTRY` since the registry needs to be configured with the new verifier address.

### Checking Contract Ownership

To verify who owns a deployed contract:

```bash
# Check NitroEnclaveVerifier owner
cast call <VERIFIER_ADDRESS> "owner()(address)" --rpc-url https://sepolia.base.org

# Check your wallet address
cast wallet address <YOUR_PRIVATE_KEY>
```

## Post-Deployment

### Check Deployed Addresses

```bash
make check-deployments
```

Deployment addresses are saved to `deployments/<chainId>.json`:
```json
{
  "SP1_VERIFIER": "0x...",
  "VERIFIER": "0x...",
  "REGISTRY": "0x..."
}
```

For Base Sepolia (chain ID: 84532), the file is `deployments/84532.json`.

### Verify Contracts on Explorer

#### Option 1: Blockscout (No API key required)

```bash
make verify-all-blockscout
```

This verifies contracts on [Blockscout](https://base-sepolia.blockscout.com/).

#### Option 2: Basescan (Requires API key)

1. Get an API key from https://basescan.org/myapikey
2. Add to your `.env`:
   ```bash
   BASESCAN_API_KEY=your_api_key_here
   ```
3. Run verification:
   ```bash
   make verify-all-basescan
   ```

After verification, view your contracts:
- **Blockscout:** `https://base-sepolia.blockscout.com/address/<ADDRESS>`
- **Basescan:** `https://sepolia.basescan.org/address/<ADDRESS>`

## Register an App

After deployment, you can register a TEE app:

```bash
# Required parameters
export PROOF_JSON=samples/proof.json
export APP_URL=https://myapp.example.com
export TEE_ARCH=nitro

# Optional parameters
# export CONTRACT_ADDR=0x...     # Contract implementing ISparsityApp
# export METADATA_URI=https://example.com/metadata.json

make register-app
```

## Available Make Targets

| Target | Description |
|--------|-------------|
| `build` | Build all contracts |
| `clean` | Clean build artifacts |
| `deploy-atomic` | Deploy everything atomically |
| `deploy-all` | Deploy everything step-by-step |
| `deploy-sp1` | Deploy only SP1Verifier |
| `deploy-verifier` | Deploy only NitroEnclaveVerifier |
| `deploy-registry` | Deploy only SparsityAppRegistry |
| `set-root-cert` | Set AWS root certificate on verifier |
| `set-sp1-config` | Configure SP1 ZK verifier |
| `check-deployments` | Show deployed contract addresses |
| `verify-all-blockscout` | Verify all contracts on Blockscout (no API key) |
| `verify-all-basescan` | Verify all contracts on Basescan (requires API key) |
| `verify-sp1-blockscout` | Verify SP1Verifier on Blockscout |
| `verify-verifier-blockscout` | Verify NitroEnclaveVerifier on Blockscout |
| `verify-registry-blockscout` | Verify SparsityAppRegistry on Blockscout |
| `verify-sp1-basescan` | Verify SP1Verifier on Basescan |
| `verify-verifier-basescan` | Verify NitroEnclaveVerifier on Basescan |
| `verify-registry-basescan` | Verify SparsityAppRegistry on Basescan |
| `register-app` | Register a TEE app on-chain |

## Network Configuration

| Network | Chain ID | RPC URL |
|---------|----------|---------|
| Base Sepolia | 84532 | `https://sepolia.base.org` |
| Local (Anvil) | 31337 | `http://localhost:8545` |

## Gas Estimates

Full deployment typically consumes 0.01-0.02 ETH on Base Sepolia.

## Troubleshooting

### "No deployments found"
Run `make deploy-atomic` or `make deploy-all` first.

### "PRIVATE_KEY not set" or empty value
1. Ensure your `.env` file uses `VAR=value` format (no `export` keyword)
2. Run `source .env` before running make commands

### "Unauthorized()" when setting root certificate
This means you're not the owner of the deployed `NitroEnclaveVerifier`. Either:
1. Use the original private key that deployed the contract, OR
2. Force a redeploy (see [Forcing a Redeploy](#forcing-a-redeploy))

### Verification fails
- Wait a few minutes after deployment before verifying
- Blockscout verification is automatic and doesn't require an API key

### "AttestationFailed()" with InvalidTimestamp
This occurs when the sample proof has a timestamp that doesn't match the current time. The `NitroEnclaveVerifier` validates that attestation timestamps are within an acceptable range (default: 30 hours).

**For local testing with sample proofs:**
1. Generate a fresh proof with a current timestamp, OR
2. The proof's timestamp must be in the recent past (within `maxTimeDiff` seconds of the current block timestamp)

**Diagnosing:** If you see `result: 3` in the trace output, that indicates `InvalidTimestamp`. The proof timestamp is either too old or in the future.

### "match" reserved keyword error
If you see `Expected ';' but got reserved keyword 'match'` during compilation, this is a Solidity 0.8.30+ issue. The codebase has been updated to avoid reserved keywords. Run:
```bash
git pull  # or update the code
make clean
make build
```
