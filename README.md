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
│   │  Enclaver  │  ──────▶ │  App Hub   │ ──────▶ │  Enclaver  │ ─────▶ │  ZKP CLI   │    │
│   │            │          │            │         │            │        │            │    │
│   │ Build &    │          │ Transparent│         │ Run your   │        │ Attest,    │    │
│   │ test your  │          │ CI/CD build│         │ EIF on AWS │        │ Prove &    │    │
│   │ TEE app    │          │ with proofs│         │ Nitro      │        │ Register   │    │
│   └────────────┘          └─────┬──────┘         └────────────┘        └─────┬──────┘    │
│                                 │ Upload hash                                │ Verify &  │
│                                 ▼    (WIP)                                   ▼ Register  │
│                           ┌─────────────────────────────────────────────────────────┐    │
│                           │                       App Registry                      │    │
│                           │                        (On-Chain)                       │    │
│                           └─────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

1. **Develop**: Use **Enclaver** to build and test your TEE application locally in mock mode or on a real Nitro Enclave.
2. **Build**: Use **App Hub** (or your own CI/CD) to transparently build your application, producing a verifiable EIF and measurement (PCR0). The measurements are uploaded to the on-chain registry (WIP).
3. **Deploy**: Use **Enclaver** to run the built EIF on your own AWS EC2 instances with Nitro Enclave support.
4. **Register**: Use **ZKP CLI** to obtain remote attestation from your running enclave, generate a Zero-Knowledge Proof, and verify and register your app on-chain in the **App Registry**.

Learn more about this workflow at [https://sparsity.cloud/how-it-works](https://sparsity.cloud/how-it-works).

---

## Core Components

Note that this repo contains the latest released version of the components, while they are being actively developed in the original repos.

### 1. Enclaver
**The Development & Runtime Engine**  
[./enclaver/](./enclaver/)  
*Original Repo: [https://github.com/sparsity-xyz/enclaver/](https://github.com/sparsity-xyz/enclaver/)*

Enclaver is the core toolkit for the entire lifecycle of AWS Nitro Enclave applications - from development to production. It builds a Docker image into an Enclave Image File (EIF), runs the enclave, and provides a runtime supervisor called **Odyn** that manages your application inside the enclave.

#### Key Features

*   **Networking & Proxies**: Nitro Enclaves have no native networking. Enclaver provides transparent Ingress (TCP) and Egress (HTTP) proxies so your app can communicate with the outside world using standard protocols.
*   **Odyn Supervisor**: The PID 1 process inside the enclave. It manages your application lifecycle, proxies, and provides an internal API for security primitives.
*   **Trustless RPC (Helios)**: Includes a built-in **Helios Light Client** that syncs with Ethereum/OP Stack chains. Your app gets a local, trustless JSON-RPC endpoint (`http://localhost:8545`) verified by cryptographic proofs, eliminating reliance on trusted 3rd party RPCs.
*   **Persistent Storage (S3)**: An encrypted, isolated storage layer backed by AWS S3. The enclave uses its unique identity to read/write data securely, allowing stateful apps to run in a stateless enclave environment.
*   **Internal Security API**: A local HTTP API (`http://localhost:9000`) for:
    *   **Attestation**: Generating cryptographic proofs of the enclave's identity (PCRs).
    *   **Key Management**: Signing transactions with enclave-generated keys.
    *   **Encryption**: ECIES (ECDH + AES-GCM) for secure communication with clients.
    *   **Randomness**: Hardware-based true random number generation from the NSM.

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

#### Key Features

*   **NovaAppRegistry**: The core registry managing the 3-layer hierarchy of TEE applications:
    *   **App**: Identity and ownership.
    *   **Version**: Immutable code measurements (PCRs) and metadata.
    *   **Instance**: Live running enclaves verified via ZK proofs.
*   **NitroEnclaveVerifier**: Verifies ZK proofs of AWS Nitro attestations on-chain using SP1.
*   **Access Control**: Granular permissions for App Owners, Instance Operators, and the Registry Admin.
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
2.  Use **Enclaver** to build and test your application locally:


### Step 2: Build Transparently

1.  Submit your application to **App Hub** for transparent, verifiable builds.
2.  GitHub Actions will build your EIF and generate PCR measurements.
3.  Download the built artifacts (EIF + attestation).

### Step 3: Deploy to AWS

1.  Launch an EC2 instance with Nitro Enclave support in your own AWS account.
2.  Deploy the built EIF using the Enclaver runtime.
3.  Your enclave is now running and accessible.

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
- [Enclaver Documentation](./enclaver/docs/)
- [App Registry Documentation](./app-registry/README.md)
- [Sparsity Cloud (With Managed Nova Stack)](https://sparsity.cloud) - Optional managed platform for simplified deployment
