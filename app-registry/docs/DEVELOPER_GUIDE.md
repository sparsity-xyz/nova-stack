# Nova App Registry - Developer Guide

This guide provides step-by-step instructions for building, testing, deploying, and verifying the `NovaAppRegistry` and its related contracts.

## 1. Quickstart

```bash
cd app-registry
make install
make build
make test
```

## 2. Prerequisites

*   [Foundry](https://book.getfoundry.sh/getting-started/installation) (Expects `forge` >= 1.5)
*   `jq` (Required for deployment verification scripts)
*   Network: Base Sepolia testnet ETH (faucet: [Alchemy Faucet](https://www.alchemy.com/faucets/base-sepolia))

## 3. Dependency Management

Dependencies are managed via `forge` and installed into `lib/`. They are gitignored.

*   **Install**: `make install`
*   **Reset**: `rm -rf lib/* && make install`

## 4. Environment Configuration

Create a `.env` file in the `app-registry/` directory:

```bash
# REQUIRED
RPC_URL=https://sepolia.base.org
PRIVATE_KEY=0x... # Your deployer private key (do not share!)

# OPTIONAL
BASESCAN_API_KEY=... # For verifying on Basescan
# ETHERSCAN_API_KEY=... # Fallback if BASESCAN_API_KEY is not set
```

## 5. Build & Test

```bash
make build
make test
```

*   **Contract Code**: `src/`
*   **Tests**: `test/`
*   **Scripts**: `script/`

## 6. Deployment

### Deploy Nova Platform

This command deploys the full stack: `SP1Verifier`, `NitroEnclaveVerifier`, `NovaAppRegistry` (Implementation), and `ERC1967Proxy`.

```bash
make deploy-nova
```

Outputs are saved to `deployments/<chainId>_nova.json`.

**Address Guide**:
- `REGISTRY_PROXY`: The main entry point. **Use this address** for all interactions.
- `REGISTRY_IMPLEMENTATION`: The logic contract. Do not interact directly.

### Upgrade Nova Registry

To upgrade the implementation logic behind the proxy:

```bash
PROXY=0x<YOUR_PROXY_ADDRESS> make upgrade-nova
```

> **IMPORTANT**: Before upgrading, read the [Upgrade Guide](./UPGRADE_GUIDE.md) to ensure storage compatibility.

## 7. Verification

Verify specific contracts on block explorers.

| Target | Explorer | Notes |
|--------|----------|-------|
| `make verify-all-blockscout` | Blockscout | No API key required. |
| `make verify-all-basescan` | Basescan | Requires `BASESCAN_API_KEY`. |

Individual targets are also available, e.g., `make verify-nova-basescan`.

## 8. Available Make Targets

| Target | Description |
|--------|-------------|
| `install` | Install dependencies |
| `build` | Build contracts |
| `clean` | Clean artifacts |
| `deploy-nova` | Deploy full Nova stack |
| `upgrade-nova` | Upgrade registry proxy |
| `check-deployments` | List deployed addresses |
| `verify-all-blockscout` | Verify all on Blockscout |
| `verify-all-basescan` | Verify all on Basescan |
| `test` | Run tests |

## 9. RegisterInstance & App Wallet Anchoring

`registerInstance` uses only app/version + ZK proof inputs:

```solidity
registerInstance(
  uint256 appId,
  uint256 versionId,
  string instanceUrl,
  ZkCoProcessorType zkCoprocessor,
  bytes publicValues,
  bytes proofBytes
)
```

Behavior:
- Instance registration is based only on app/version ownership and ZK attestation verification.

App wallet anchoring is a separate explicit step:

```solidity
setAppWalletIfUnset(
  uint256 appId,
  address appWallet
)
```

Rules:
- `setAppWalletIfUnset` can only be called by the app owner.
- `setAppWalletIfUnset` succeeds only when the current app wallet is unset.
- Any later call reverts with `AppWalletMismatch`.
- No signature proof or deadline is required.

## 10. Troubleshooting

*   **"No deployments found"**: Run `make deploy-nova` first.
*   **"Unauthorized()"**: Ensure you are using the same private key that deployed the contracts (the owner).
*   **Verification fails**: Wait a few minutes after deployment for the explorer to index the contract.
*   **"match" reserved keyword**: Update your code (we use Solidity 0.8.33 which avoids old reserved keywords).

## 11. Nova Platform Integration Notes (Control Plane)

To keep registry integrations consistent across API endpoints:

- Use `control-plane/app/services/nova_registry.py:NOVA_REGISTRY_ABI` as the canonical ABI source for control-plane reads/writes.
- Avoid duplicating partial ABI fragments in other modules (for example, signature-verification flows should import the shared ABI).
- `web3.py` is synchronous; when calling registry functions from `async def` handlers/services, run RPC operations in a worker thread (for example, via `asyncio.to_thread`) to avoid blocking the FastAPI event loop.

These constraints reduce ABI drift bugs and improve runtime responsiveness under concurrent request load.

## 12. Explorer App-Wallet View

Portal explorer pages (`AppExplorer` / `ExplorerAppView`) now surface the latest on-chain `appWallet` from `getApp(appId)`:

- Card/list pages show whether an app wallet is anchored.
- App detail page shows `App Wallet` and links to BaseScan when anchored.
- Search now supports app-wallet address text.

If the value appears as zero address, it means app-wallet anchoring has not happened yet for that app.
