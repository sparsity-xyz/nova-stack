# NovaAppRegistry Upgrade Guide

The `NovaAppRegistry` contract uses the **UUPS (Universal Upgradeable Proxy Standard)** pattern. This allows us to upgrade the contract logic while preserving the state (data) and the contract address.

## ⚠️ Critical Rules for Upgrades

When modifying `NovaAppRegistry.sol` for a new version, you **MUST** follow these rules to avoid corrupting storage:

### 1. Storage Layout Rules (Append-Only)

*   **NEVER change the type or order of existing state variables.**
*   **NEVER remove existing state variables.**
*   **ALWAYS add new state variables at the end** of the existing variables.
*   **Structs**: If you have a struct used in a mapping or array, you generally cannot change its layout safely unless you are very careful. It is safer to add a new mapping for new data.

**Bad Example (Corrupts Storage):**
```solidity
// V1
uint256 public a;
uint256 public b;

// V2 - BAD: Changed order
uint256 public b;
uint256 public a;

// V2 - BAD: Changed type
uint128 public a;
```

**Good Example:**
```solidity
// V1
uint256 public a;
uint256 public b;

// V2 - GOOD: Appended new variable
uint256 public a;
uint256 public b;
uint256 public c; // New variable
```

### 2. No Constructors

*   Upgradeable contracts **cannot** use a `constructor` to initialize state variables.
*   Use the `initialize()` function instead.
*   For upgrades, if you need to initialize new variables, create a new function (e.g., `initializeV2()`) protected by `reinitializer(2)`.

### 3. Gap Variables (Optional but Recommended)

If we were using standard OpenZeppelin contracts, they often include `uint256[50] __gap;` at the end to reserve storage slots. Since we act as the final implementation, strict append-only is sufficient, but be aware of this pattern in parent contracts.

## How to Upgrade

The upgrade process involves two steps:
1.  **Deploy** the new implementation contract.
2.  **Call** `upgradeToAndCall` on the proxy to point to the new implementation.

### Using the Make Command

We have a dedicated script and Makefile target for this.

1.  **Modify** `src/NovaAppRegistry.sol` with your changes.
2.  **Get** the current proxy address (from `deployments/<chain_id>_nova.json`).
3.  **Run** the upgrade command:

```bash
PROXY=0xYourProxyAddress make upgrade-nova
```

This will:
*   Deploy the new implementation contract.
*   Call `upgradeTo(newImplementation)` on your proxy.
*   Update the `deployments/` JSON file with the new implementation address.

## Verification

After upgrading, you should verify:
1.  **State Preservation**: Check that existing data (e.g., registered apps) is still accessible.
2.  **New Logic**: specific tests for your new features.
3.  **Address Consistency**: Ensure you are still interacting with the **same Proxy address**.
