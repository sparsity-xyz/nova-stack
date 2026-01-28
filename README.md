# Nova Stack

The **Nova Stack** is a comprehensive suite of tools designed to build, deploy, and verify Trusted Execution Environment (TEE) applications on AWS Nitro Enclaves.

It unifies the entire lifecycle of a confidential application: from local development and packaging to transparent building and verifiable on-chain registration.

## System Overview

The Nova ecosystem consists of several specialized components that work together to ensure that applications are not only secure but also **transparently built** and **verifiable**.

### The Flow
1. **Develop**: Use the **Nova App Template** and **Enclaver** to build and test your TEE application locally.
2. **Build**: Push to **App Hub**, where your application is transparently built via GitHub Actions, producing a verifiable measurement (PCR0).
3. **Deploy**: Use the **Nova Platform** to deploy your application to the cloud. The platform generates a Zero-Knowledge Proof (ZKP) of the application's integrity and registers it on-chain to the Nova Registry.

---

## Core Components

### 1. Enclaver
**The Engine**  
[https://github.com/sparsity-xyz/enclaver/](https://github.com/sparsity-xyz/enclaver/)

Enclaver is the core toolkit that simplifies packaging and running applications inside AWS Nitro Enclaves. It builds a docker image into an Enclave Image File (EIF) and provides a runtime supervisor called **Odyn** that runs inside the enclave.

#### Key Features

*   **Networking & Proxies**: NITRO Enclaves have no native networking. Enclaver provides transparent Ingress (TCP) and Egress (HTTP) proxies so your app can communicate with the outside world using standard protocols.
*   **Odyn Supervisor**: The PID 1 process inside the enclave. It manages your application lifecycle, proxies, and provides an internal API for security primitives.
*   **Trustless RPC (Helios)**: Includes a built-in **Helios Light Client** that syncs with Ethereum/OP Stack chains. Your app gets a local, trustless JSON-RPC endpoint (`http://localhost:8545`) verified by cryptographic proofs, eliminating reliance on trusted 3rd party RPCs.
*   **Persistent Storage (S3)**: An encrypted, isolated storage layer backed by AWS S3. The enclave uses its unique identity to read/write data securely, allowing stateful apps to run in a stateless enclave environment.
*   **Internal Security API**: A local HTTP API (`http://localhost:9000`) for:
    *   **Attestation**: Generating cryptographic proofs of the enclave's identity (PCRs).
    *   **Key Management**: Signing transactions with enclave-generated keys.
    *   **Encryption**: ECIES (ECDH + AES-GCM) for secure communication with clients.
    *   **Randomness**: Hardware-based true random number generation from the NSM.
### 2. Nova App Hub
**The Transparent Builder**  
[https://github.com/sparsity-xyz/sparsity-nova-app-hub](https://github.com/sparsity-xyz/sparsity-nova-app-hub)

A centralized, transparent build platform. Applications submitted here are built publicly using GitHub Actions. This ensures that the binary running in the enclave matches the source code, creating a "chain of custody" for the software supply chain.
- **SLSA Level 3**: Builds are signed and verifiable.
- **PCR Generation**: Automatically calculates the measurements needed for remote attestation.

### 3. Nova Examples
**The Reference**  
[https://github.com/sparsity-xyz/sparsity-nova-examples](https://github.com/sparsity-xyz/sparsity-nova-examples)

A collection of reference applications demonstrating how to use the Nova Stack. Includes examples for:
- Secure Chat Bots (End-to-end encryption)
- Oracles (Data fetching and signing)
- Key Management

### 4. Nova App Template
**The Starter**  
[https://github.com/sparsity-xyz/nova-app-template](https://github.com/sparsity-xyz/nova-app-template)

The standard boilerplate for creating new Nova applications. It comes pre-configured with:
- **FastAPI / Python** backend structure.
- **Enclaver** configuration (`enclaver.yaml`).
- **Helios** light client integration for trustless blockchain access.
- **Frontend** templates.

### 5. Sparsity Nova Platform
**The Cloud**  
[https://sparsity.cloud](https://sparsity.cloud)

The management platform that orchestrates the infrastructure. It connects the dots by currently running the infrastructure that interacts with the Enclaver runtime and the on-chain Registry.
- **Automated Deployment**: One-click deploy to AWS Nitro Enclaves.
- **ZKP Verification**: Automatically generates SP1 proofs of attestation.
- **On-Chain Registry**: Registers verified applications on the Base Sepolia network.

---

## Developer Workflow

To build a secure application on Nova:

1.  **Clone the Template**: Start with `nova-app-template`.
    ```bash
    git clone https://github.com/sparsity-xyz/nova-app-template my-app
    ```
2.  **Develop Locally**: Use `enclaver` (or the mock mode in the template) to iterate on your logic.
3.  **Publish**: Submit your application configuration to the **Nova App Hub**.
4.  **Deploy**: Use the **Nova Platform** console to launch your application. The platform will verify your build from the App Hub and launch it into a secure enclave.

## Resources

- [Sparsity Cloud Website](https://sparsity.cloud)
- [Enclaver Documentation](https://github.com/sparsity-xyz/enclaver/tree/sparsity/docs)
