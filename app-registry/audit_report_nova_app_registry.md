# Smart Contract Audit Report: NovaAppRegistry.sol

## 1. Executive Summary
`NovaAppRegistry` is the centerpiece of the Nova Platform, managing the lifecycle of applications, versions, and TEE instances. It uses a ZK-based attestation verification mechanism (`NitroEnclaveVerifier`) to ensure that only legitimate enclave instances can register and participate in app-specific logic.

The contract is implemented as a UUPS Upgradeable proxy and includes sophisticated storage packing and external callback logic.

## 2. Risk Rating (Overall)
**Risk Score: Medium**
While the core cryptography and access controls are solid, the audit revealed a significant functional issue (TEE Wallet Lock-out) and several consistency/maintenance risks.

---

## 3. High Issues

### 3.1 TEE Wallet Registration Lock-out
- **Severity**: High
- **Code Location**: `_createInstance` (Line 717-718)
- **Description**: The registry prevents a `teeWalletAddress` from being registered more than once. However, `walletToInstance` is never cleared when an instance is stopped or fails. If an enclave instance needs to re-register (e.g., after a restart or failure), it will be permanently blocked by `revert DuplicateTEEWallet()`.
- **Attack Scenario**: An enclave instance fails and restarts. It attempts to re-register with the same TEE identity. The transaction reverts, rendering that specific enclave instance permanently unusable on the platform.
- **Recommended Fix**: Clear `walletToInstance[teeWalletAddress]` in `_removeActiveInstanceWallet`. Alternatively, allow re-registration if the existing instance is in `STOPPED` or `FAILED` status.

---

## 4. Medium Issues

### 4.1 Reentrancy Risk in Operator Callbacks
- **Severity**: Medium
- **Code Location**: `_createInstance` -> `_callAddOperator` (Line 750) and `updateInstanceStatus` -> `_callRemoveOperator` (Line 868)
- **Description**: The contract makes external calls to `dappContract` which are not protected by `nonReentrant`. While the contract follows Checks-Effects-Interactions (CEI) to an extent, a malicious or compromised `dappContract` could re-enter the registry.
- **Risk**: A dApp could re-enter and manipulate other state, or trigger a loop of registration/deactivation.
- **Recommended Fix**: Use OpenZeppelin's `ReentrancyGuardUpgradeable` and apply `nonReentrant` to `registerInstance` and `updateInstanceStatus`.

### 4.2 Rigid JSON Parsing
- **Severity**: Medium
- **Code Location**: `JsonParser.extractEthAddr` (Lines 40-63)
- **Description**: The `JsonParser` uses a rigid pattern match (`"eth_addr":"0x`) with no support for whitespace or alternative formatting (e.g. single quotes, different field order). If the off-chain ZK-prover or enclave code changes its JSON serialization format slightly, all registrations will fail.
- **Risk**: Ecosystem-wide denial of service if the enclave-side JSON library is updated or changed.
- **Recommended Fix**: Implement a more robust JSON parser or use a standard format like RLP for TEE attestation user data.

---

## 5. Low Issues

### 5.1 Inconsistent Status on Version Revocation
- **Severity**: Low
- **Code Location**: `revokeVersion` (Lines 426-450)
- **Description**: When a version is revoked, it is removed from the active wallet list, but the individual `RuntimeInstanceStorage` status is **not** updated. `getInstance()` will still report the instance as `ACTIVE`.
- **Recommended Fix**: Update the status of all instances belonging to the revoked version during the revocation loop.

### 5.2 Assembly Memory Management
- **Severity**: Low
- **Code Location**: `_computeVersionMeasurement` and `_computeMeasurementKey` (Lines 959-978)
- **Description**: Assembly blocks use memory starting at `0x40` (the free memory pointer) but do not update it. While safe in these specific `pure`/`internal` helper functions, it is bad practice and could lead to issues if the functions are modified.

---

## 6. Gas Optimization Suggestions

### 6.1 `_activeInstanceWalletIndexPlusOne` Optimization
- **Description**: Using "Index + 1" to differentiate from zero is standard but slightly adds gas to every read/write. 
- **Recommendation**: If total active instances per app is small, the gas savings are negligible, but for large sets, consider alternative mapping structures.

---

## 7. Final Verdict
The `NovaAppRegistry` is a well-engineered contract with a clever integration of ZK proofs and TEE identities. However, the **TEE Wallet Lock-out** bug is a critical operational risk that must be addressed before production deployment to ensure the platform can handle enclave restarts and failures gracefully.
