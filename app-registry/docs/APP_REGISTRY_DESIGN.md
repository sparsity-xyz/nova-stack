# Nova App Registry Design

The **Nova App Registry** is the core on-chain component of the Sparsity Nova Platform. It serves as the source of truth for all Trusted Execution Environment (TEE) applications, managing their identity, code integrity, and runtime instances.

## 1. Core Concepts

### 1.1 The 3-Layer Hierarchy

The registry organizes data in a strict three-layer hierarchy:

1.  **Application (App)**
    *   **Definition**: Represents the abstract identity of a dApp or service.
    *   **Key Data**: `AppID`, `Owner`, `TEE Architecture`, `Metadata URI`, `Status`, `appWallet`.
    *   **Role**: Acts as the container for all versions and configuration.
    *   **Status**:
        *   `ACTIVE`: The application is fully functional.
        *   `INACTIVE`: The application is paused (e.g., by owner).
        *   `REVOKED`: The application is permanently revoked (e.g., by registry owner).

2.  **Version**
    *   **Definition**: Represents a specific, immutable build of the application code.
    *   **Key Data**: `VersionID`, `Semantic Version` (e.g., "1.0.0"), `Code Measurement` (Hash of PCRs), `Container Image URI`, `Audit URL/Hash`, `GitHub Run ID`, `Status` (`ENROLLED`, `DEPRECATED`, `REVOKED`).
    *   **Role**: Defines **what** code is allowed to run. Once a version is enrolled, its code measurement is fixed. This ensures users know exactly what code is running inside the TEE.

3.  **Instance**
    *   **Definition**: A live, running Enclave executing a specific `Version`.
    *   **Key Data**: `InstanceID`, `AppID`, `VersionID`, `Operator`, `Instance URL`, `TEE Public Key`, `TEE Wallet Address`, `ZK Verification Status`, `Status` (`ACTIVE`, `STOPPED`, `FAILED`).
    *   **Role**: Represents **where** the code is running. Instances must prove (via ZK Proof) that they are running a valid, enrolled `Version`.

### 1.2 Roles & Permissions

*   **Registry Any-One**: Can view app details, versions, and instances. Verify attestations.
*   **Registry Owner (Admin)**:
    *   Deploys and upgrades the registry contract.
    *   Configures global parameters (e.g., ZK Verifier address, callback gas limits).
    *   Has emergency powers to revoke versions or register instances in special cases.
*   **App Owner**:
    *   Creates the App.
    *   Enrolls new Versions (`enrollVersion`).
    *   Deprecates or Revokes versions.
    *   Registers and manages Instances (`registerInstance`, `updateInstanceStatus`).

---

## 2. Secure Deployment Pipeline

The system follows a rigorous security pipeline to ensure only verified code runs on the network.

### 2.1 Pre-Deployment: Audited Measurement Enrollment

Before any instance can launch, the "Reference Measurement" must be established.

1.  **Independent Audit**:
    *   The application code is audited and built in a reproducible environment.
    *   This produces the expected **Platform Configuration Registers (PCRs)** (PCR0, PCR1, PCR2).

2.  **Measurement Enrollment**:
    *   **Actor**: App Owner
    *   **Action**: Calls `enrollVersion()` on the Registry.
    *   **Logic**: The registry stores the **Code Measurement** (hash of PCRs). This effectively whitelists this specific build.

### 2.2 Post-Deployment: Attestation & Registration

Once the measurement is enrolled, operators can deploy instances.

1.  **Zero-Knowledge Attestation Proof**:
    *   The enclave generates a hardware attestation report (containing its actual PCRs).
    *   A ZK Prover generates a proof that verifies the attestation signature and extracts the PCRs.

2.  **Proof Verification**:
    *   **Actor**: App Owner
    *   **Action**: Calls `registerInstance()` with the ZK Proof.
    *   **Logic**: The `NitroEnclaveVerifier` contract verifies the ZK proof on-chain.

3.  **Runtime Instance Registration**:
    *   **Logic**: The Registry compares the proven PCRs from the live instance against the Enrolled Measurement.
    *   **Result**: If they match, the instance is registered as an **Attested Runtime Instance**. Its TEE Public Key is now trusted.

### 2.3 App-Wallet Anchoring & Consistency

`registerInstance` does not accept app-wallet arguments.

App wallet anchoring is an explicit one-time call:
- `setAppWalletIfUnset(appId, appWallet)`

Rules:
1. Only the app owner can call `setAppWalletIfUnset`.
2. `appWallet` must be non-zero.
3. If `appWallet` is already set, the call reverts with `AppWalletMismatch`.
4. No proof or deadline is required.

---

## 3. Integration

### For Developers (dApps)
Developers building on Nova can act on `registerInstance` events or implement the `INovaAppInterface` to receive callbacks when new operators join their network.

*   **INovaAppInterface.sol**:
    *   `addOperator(address teeWalletAddress, uint256 appId, uint256 versionId, uint256 instanceId)`: Called when a new instance is successfully registered.
    *   `removeOperator(address teeWalletAddress, uint256 appId, uint256 versionId, uint256 instanceId)`: Called when an instance is stopped or fails.

### For Users
Users can verify the security of an application by looking up its `AppID` on the Registry. If an instance is listed with `zkVerified = true`, it guarantees:
1.  The code running in that enclave matches the open-source code enrolled by the App Owner.
2.  The TEE Public Key belongs to that specific secure enclosure and cannot be accessed by the node operator.

Common read APIs used by platform components:
- `getApp(appId)` (includes `appWallet`)
- `getInstanceByWallet(teeWalletAddress)`
- `getActiveInstances(appId)`

Control-plane implementation note:
- Keep a single shared ABI definition for these methods (do not maintain duplicate ABI snippets per endpoint).
- Async HTTP handlers that call `web3.py` should offload synchronous RPC calls to worker threads to avoid event-loop stalls.
