# ZKP CLI

> ⚠️ **This component is currently under development.**

A command-line tool for interacting with running TEE enclaves to obtain attestations, generate Zero-Knowledge Proofs, and register applications on the App Registry.

## Overview

The ZKP CLI streamlines the final step of the Nova Stack pipeline. It provides tools to:

1.  **Retrieve Remote Attestations**: Connect to a running enclave and obtain a cryptographic attestation document from the AWS Nitro Secure Module (NSM).
2.  **Generate ZK Proofs**: Submit the attestation to an SP1 proving service to generate a succinct Zero-Knowledge Proof of the enclave's identity and integrity.
3.  **On-Chain Registration**: Submit the ZK proof to the `SparsityAppRegistry` smart contract on-chain, completing the verifiable registration of the TEE application.

## Planned Features

-   [ ] `zkp-cli attest <enclave-url>` - Fetch attestation from a running enclave.
-   [ ] `zkp-cli prove <attestation-file>` - Generate a ZK proof from an attestation.
-   [ ] `zkp-cli register <proof-file> --registry <address>` - Register a verified app on-chain.
-   [ ] Configuration file support for network settings and registry addresses.
-   [ ] Integration with local or remote SP1 proving backends.

## Integration with Nova Stack

The ZKP CLI is designed to work seamlessly with the other components of the Nova Stack:

Applications are built and deployed with Nova Enclave Capsule before the final attestation and registration step handled by ZKP CLI.

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                             NOVA STACK PIPELINE                                          │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│   1. DEVELOP              2. BUILD               3. DEPLOY             4. REGISTER       │
│   ──────────              ────────               ────────              ────────────      │
│   ┌────────────┐          ┌────────────┐         ┌────────────┐        ┌────────────┐    │
│   │  Capsule   │  ──────▶ │  App Hub   │ ──────▶ │  Capsule   │ ─────▶ │  ZKP CLI   │    │
│   │            │          │            │         │            │        │            │    │
│   │ Build &    │          │ Transparent│         │ Run your   │        │ Attest,    │    │
│   │ test your  │          │ CI/CD build│         │ release    │        │ Prove &    │    │
│   │ TEE app    │          │ with proofs│         │ image      │        │ Register   │    │
│   └────────────┘          └─────┬──────┘         └────────────┘        └─────┬──────┘    │
│                                 │ Upload hash                                │ Verify &  │
│                                 ▼    (WIP)                                   ▼ Register  │
│                           ┌─────────────────────────────────────────────────────────┐    │
│                           │                       App Registry                      │    │
│                           │                        (On-Chain)                       │    │
│                           └─────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

## Status

🚧 **Coming Soon** - This tool is actively being developed. Stay tuned for updates.

## Resources

- [Nova Stack Overview](../README.md)
- [App Registry Documentation](../app-registry/README.md)
- [Sparsity Cloud Platform](https://sparsity.cloud)
