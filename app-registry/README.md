# Nova App Registry

This repository contains the smart contracts and deployment scripts for a **Trusted Execution Environment (TEE) Application Registry**.

While originally designed for the **Sparsity Nova Platform**, this registry is a core component of the open-source **[Nova Stack](https://github.com/sparsity-xyz/nova-stack)**. It is a general-purpose solution for any project needing to manage identity, code measurements, and runtime verification for TEE applications.

The **Sparsity Nova Platform** is one such implementation that deploys and uses this registry to secure its network.

The registry is the source of truth for TEE apps, managing:
*   **Application Identity**: Who owns the app.
*   **Version Control**: What code (PCR measurements) is authorized to run.
*   **Runtime Verification**: Which instances are running verified code.

## Documentation Index

**Start here to understand the system:**

*   📘 **[App Registry Design](./docs/APP_REGISTRY_DESIGN.md)** - Learn about the 3-layer hierarchy (App -> Version -> Instance), roles, and the lifecycle workflow.

**For Developers & Node Operators:**

*   🛠️ **[Developer Guide](./docs/DEVELOPER_GUIDE.md)** - Instructions for building, testing, deploying, and verifying contracts.
*   🔄 **[Upgrade Guide](./docs/UPGRADE_GUIDE.md)** - Critical information for upgrading the registry safely (UUPS pattern).

## Quick Links

*   **Contract Logic**: [`src/NovaAppRegistry.sol`](./src/NovaAppRegistry.sol)
*   **Deployments**: [`deployments/`](./deployments/)
*   **Tests**: [`test/`](./test/)

## Key Features

*   **3-Layer Hierarchy**: `App` (Identity) -> `Version` (Code) -> `Instance` (Runtime).
*   **TEE Verification**: Integrates with `NitroEnclaveVerifier` to validate ZK proofs from AWS Nitro Enclaves.
*   **App-Wallet Anchoring**: Supports app-level persistent identity via `appWallet` with ownership proof checks during `registerInstance`.
*   **Control-Plane Friendly**: Designed for shared ABI consumption (`NOVA_REGISTRY_ABI`) across Nova control-plane services and proxy verification paths.
*   **Upgradeable**: Uses the UUPS proxy pattern for future-proof improvements.
*   **Gas Optimized**: Efficient storage packing and optimized validation logic.
*   **Secure Deployment Pipeline**:
    The system performs build measurement enrollment (PCRs) to create a new **Version** prior to instance deployment.
    After deployment, each running **Instance** produce a zero-knowledge attestation proof, which is verified against the enrolled version's measurement.
    Successfully verified instances are then registered as **Attested Runtime Instances**, with their TEE public keys bound to the registry.

---
_Sparsity Nova Platform - Secure TEE Computing_
