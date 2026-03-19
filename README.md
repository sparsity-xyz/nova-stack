# Nova Stack

The **Nova Stack** is a comprehensive, self-contained suite of open-source tools for building, deploying, and verifying Trusted Execution Environment (TEE) applications on blockchain and AWS Nitro Enclaves.

With Nova Stack, you can independently develop, build, deploy, and register **trustless** TEE applications. You own and control the entire pipeline.

## Stack Overview

Nova Stack consists of four core components that together provide a complete, end-to-end workflow for confidential computing applications.

### The Development & Deployment Pipeline

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
│                                 ▼                                            ▼ Register  │
│                           ┌─────────────────────────────────────────────────────────┐    │
│                           │                       App Registry                      │    │
│                           │                        (On-Chain)                       │    │
│                           └─────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

1. **Develop**: Use **Nova Enclave Capsule** to build and test your TEE application locally in mock mode or on a real Nitro Enclave.
2. **Build**: Use **App Hub** (or your own CI/CD) to transparently build your application, producing a verifiable EIF and measurement (PCRs). The measurements are enrolled into the on-chain registry as a new **Version**.
3. **Deploy**: Use **Nova Enclave Capsule** to run the built release image, which contains the EIF, on your own AWS EC2 instances with Nitro Enclave support.
4. **Register**: Use **ZKP CLI** to obtain remote attestation from your running enclave, generate a Zero-Knowledge Proof, and register your **Instance** on-chain in the **App Registry** by verifying it against the enrolled version.

Learn more about this workflow at [https://sparsity.cloud/how-it-works](https://sparsity.cloud/how-it-works).

---

## Core Components

Note that this repo contains the latest released version of the components, while they are being actively developed in the original repos.

### 1. Nova Enclave Capsule
**The Development & Runtime Engine**  
[./enclave-capsule/](./enclave-capsule/)  
*Original Repo: [https://github.com/sparsity-xyz/nova-enclave-capsule](https://github.com/sparsity-xyz/nova-enclave-capsule)*

Nova Enclave Capsule is the core toolkit for the entire lifecycle of AWS Nitro Enclave applications, from local development to production deployment. It uses `capsule-cli build` plus a `capsule.yaml` manifest to turn a standard container image into a release image with an embedded EIF, and `capsule-cli run` to launch that image on Nitro-enabled EC2. Inside the enclave, `capsule-runtime` supervises the application, while `capsule-shell` manages the host-side runtime and Nitro lifecycle.

#### Key Features

*   **Capsule CLI Workflow**: Build and run enclave applications with `capsule-cli build` and `capsule-cli run`, using a single `capsule.yaml` manifest to describe the runtime contract.
*   **Networking & Proxies**: Nitro Enclaves have no native networking. Nova Enclave Capsule provides ingress and egress proxy layers so your app can communicate with the outside world using standard protocols.
*   **Capsule Runtime & Capsule API**: `capsule-runtime` runs as PID 1 inside the enclave and exposes local HTTP APIs for attestation, randomness, signing, encryption, storage, and related enclave services.
*   **Trustless RPC (Helios)**: Includes a built-in **Helios Light Client** that syncs with Ethereum/OP Stack chains. Your app gets a local, trustless JSON-RPC endpoint (`http://localhost:8545`) verified by cryptographic proofs, eliminating reliance on trusted 3rd party RPCs.
*   **Storage & Mounts**: Supports encrypted S3-backed storage as well as host-backed directory mounts for stateful enclave workloads.
*   **KMS-Backed Key Management**: Integrates enclave identity with external KMS-backed signing and derivation flows for application wallets and related services.

### 2. App Hub
**The Transparent Builder**  
[./app-hub/](./app-hub/)  
*Original Repo: [https://github.com/sparsity-xyz/sparsity-nova-app-hub](https://github.com/sparsity-xyz/sparsity-nova-app-hub)*

A transparent build system using GitHub Actions. Applications submitted here are built publicly, ensuring that the binary running in the enclave matches the source code. This creates a "chain of custody" for the software supply chain.

*   **SLSA Level 3**: Builds are signed and verifiable.
*   **PCR Generation**: Automatically calculates the measurements needed for remote attestation.
*   **Build Attestation**: Creates cryptographic proofs tying source code commits to built EIF artifacts.

> 💡 **Note**: You can also set up your own build pipeline using the same GitHub Actions workflows provided in App Hub.

### 3. App Registry
**The On-Chain Registry**  
[./app-registry/](./app-registry/)  

Smart contracts for on-chain TEE application registration and verification.

> 🔗 **Live Deployment**: [Base Sepolia (0x0f68...4cc8)](https://sepolia.basescan.org/address/0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8)  
> 🔍 **Live App Explorer**: [https://sparsity.cloud/explore/](https://sparsity.cloud/explore/)

#### Key Features

*   **NovaAppRegistry**: The core registry managing the 3-layer hierarchy of TEE applications:
    *   **App**: Identity and ownership.
    *   **Version**: Immutable code measurements (PCRs) and metadata.
    *   **Instance**: Live running enclaves verified via ZK proofs.
*   **NitroEnclaveVerifier**: Verifies ZK proofs of AWS Nitro attestations on-chain using SP1.
*   **Access Control**: Granular permissions for App Owners and the Registry Admin.
*   **Upgradeable**: Built using the UUPS proxy pattern for future extensibility.

### 4. ZKP CLI
**The Attestation & Registration Tool**  
[./zkp-cli/](./zkp-cli/)

> ⚠️ **Under Development**

A command-line tool for the final step of the deployment pipeline. It connects to proving services to:

*   **Retrieve Remote Attestations**: Connect to a running enclave and obtain attestation from the AWS Nitro Secure Module (NSM).
*   **Generate ZK Proofs**: Submit the attestation to an SP1 proving service to generate a Zero-Knowledge Proof of the enclave's identity.
*   **On-Chain Registration**: Submit the ZK proof to the App Registry smart contract, completing the verifiable registration.

---

## Quick Start

### Step 1: Develop Your Application

1.  Check the [Sparsity Nova Examples](https://github.com/sparsity-xyz/sparsity-nova-examples) for reference implementations.
2.  Use **Nova Enclave Capsule** and a `capsule.yaml` manifest to build and test your application locally.
3.  Start with the [Nova Enclave Capsule README](./enclave-capsule/README.md) or the [HN Fetcher example](./enclave-capsule/examples/hn-fetcher/readme.md).


### Step 2: Build Transparently

1.  Submit your application to **App Hub** for transparent, verifiable builds.
2.  GitHub Actions will build your EIF and generate PCR measurements.
3.  Download the built artifacts (EIF + attestation).

### Step 3: Deploy to AWS

1.  Launch an EC2 instance with Nitro Enclave support in your own AWS account.
2.  Deploy the built release image using `capsule-cli run`.
3.  Your enclave is now running and accessible through the ports you publish from the Capsule release image.

### Step 4: Register On-Chain

1.  Deploy your own App Registry (or use an existing deployment):
2.  Use **ZKP CLI** to attest, prove, and register your running enclave:

---

## Why Nova Stack?

| Feature | Benefit |
|---------|---------|
| **Fully Open Source** | Inspect, modify, and self-host every component |
| **Verifiable Builds** | Transparent CI/CD ensures binary integrity |
| **On-Chain Registration** | Cryptographic proof of your enclave's identity on the blockchain |
| **Self-Contained** | Complete pipeline from development to on-chain registration |

---

## Resources

- [How It Works](https://sparsity.cloud/how-it-works)
- [Nova App Template](https://github.com/sparsity-xyz/nova-app-template)
- [Nova App Examples](https://github.com/sparsity-xyz/sparsity-nova-examples)
- [Nova Enclave Capsule](./enclave-capsule/README.md)
- [Nova Enclave Capsule Documentation](./enclave-capsule/docs/)
- [App Registry Documentation](./app-registry/README.md)
- [Sparsity Cloud (With Managed Nova Stack)](https://sparsity.cloud) - Optional managed platform for simplified deployment
