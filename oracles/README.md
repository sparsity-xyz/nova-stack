# Blockchain Oracles on Nova Platform

The Nova Platform enables developers to deploy off-chain applications inside **AWS Nitro Enclaves (TEE)**, making it an ideal platform for building **trustless blockchain oracles**.

## Why Nova for Oracles?

Traditional oracles require users to trust the operator. Nova-powered oracles solve this with:

| Feature                   | Benefit                                                          |
|---------------------------|------------------------------------------------------------------|
| **TEE Execution**         | Code runs in isolated, hardware-secured environment              |
| **Remote Attestation**    | Cryptographic proof that specific code is running                |
| **Secure Key Management** | Ethereum wallet generated inside TEE, private key never exposed  |
| **On-Chain Integration**  | Nova Registry can automatically set TEE as contract operator     |

## Oracle Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Nova Platform                           │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    AWS Nitro Enclave                      │  │
│  │  ┌───────────────┐   ┌─────────────────────────────────┐  │  │
│  │  │     Odyn      │   │      Your Oracle Service        │  │  │
│  │  │  (Supervisor) │──▶│  - Listen for on-chain events   │  │  │
│  │  │               │   │  - Fetch external data          │  │  │
│  │  │  • ETH Wallet │   │  - Sign & submit transactions   │  │  │
│  │  │  • Attestation│   └─────────────────────────────────┘  │  │
│  │  │  • RNG        │                                        │  │
│  │  └───────────────┘                                        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
         │                                        │
         ▼                                        ▼
   ┌───────────┐                          ┌─────────────────┐
   │ Blockchain│◀─────────────────────────│  External APIs  │
   │  (Events) │     fulfill request      │  (Data Sources) │
   └───────────┘                          └─────────────────┘
```

## Development Workflow

### 1. Develop Oracle Service (Off-Chain)

Create a Python/Node.js service that:

```python
# Typical oracle service pattern
from odyn import Odyn
from web3 import Web3

odyn = Odyn()  # Handles TEE features automatically
w3 = Web3(Web3.HTTPProvider(RPC_URL))

# 1. Get TEE wallet address
address = odyn.eth_address()

# 2. Listen for on-chain events
contract.events.RequestCreated().process_events(handle_request)

# 3. Fetch external data
def handle_request(event):
    data = fetch_from_external_api(event.args.params)
    
    # 4. Sign and submit fulfillment transaction
    tx = contract.functions.fulfill(event.args.requestId, data)
    signed_tx = odyn.sign_transaction(tx)
    w3.eth.send_raw_transaction(signed_tx)
```

**Key Files:**
- `main.py` / `app.py` — Service entry point
- `odyn.py` — Copy from examples, handles Odyn API
- `config.py` — Contract address, RPC URL
- `Dockerfile` — Container build
- `requirements.txt` — Dependencies

### 2. Deploy Smart Contract (On-Chain)

Your oracle contract typically needs:

```solidity
contract MyOracle {
    address public operator;  // TEE wallet address
    
    modifier onlyOperator() {
        require(msg.sender == operator, "Not operator");
        _;
    }
    
    // Called by Nova Registry or manually
    function registerTEEWallet(address teeWallet) external {
        operator = teeWallet;
    }
    
    // Users call this to request data
    function request(...) external {
        emit RequestCreated(requestId, ...);
    }
    
    // Only TEE can fulfill
    function fulfill(uint256 requestId, bytes calldata data) external onlyOperator {
        // Store result, callback user, etc.
    }
}
```

### 3. Local Testing

```bash
# Terminal 1: Start local blockchain
anvil

# Terminal 2: Deploy contract
make deploy-contract-local

# Terminal 3: Run oracle service (uses mock Odyn)
IN_ENCLAVE=false python main.py
```

### 4. Deploy to Nova Platform

1. **Deploy contract** to testnet (e.g., Base Sepolia)
2. **Create app** on [sparsity.cloud](https://sparsity.cloud)
3. **Get TEE wallet address** from deployed app
4. **Register TEE as operator** on your contract
5. **Fund TEE wallet** with gas tokens

```bash
# Get TEE wallet address
curl https://your-app.sparsity.cloud/
# Response: { "operator": "0x...", ... }

# Fund the wallet, then oracle starts processing automatically
```

## Example Oracles

| Oracle                         | Description                        | Key Features                                             |
|--------------------------------|------------------------------------|----------------------------------------------------------|
| [rng-oracle](./rng-oracle)     | Verifiable random number generator | Hardware RNG, event-driven fulfillment, callback support |
| [price-oracle](./price-oracle) | BTC price feed from CoinGecko      | External API integration, periodic updates               |
