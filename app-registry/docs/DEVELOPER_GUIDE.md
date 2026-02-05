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

## 9. Troubleshooting

*   **"No deployments found"**: Run `make deploy-nova` first.
*   **"Unauthorized()"**: Ensure you are using the same private key that deployed the contracts (the owner).
*   **Verification fails**: Wait a few minutes after deployment for the explorer to index the contract.
*   **"match" reserved keyword**: Update your code (we use Solidity 0.8.33 which avoids old reserved keywords).
