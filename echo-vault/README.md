# Echo Vault

Echo Vault is a TEE-backed vault whose behavior is simple, deterministic, and remotely attestable: all inbound transfers are echoed back to the sender.

## Architecture

Echo Vault consists of two main components:

1.  **TEE Enclave (Backend)**:
    *   **FastAPI Service**: Runs a Python backend within the Nitro Enclave.
    *   **Trustless Helios Node**: Integrates the Helios light client for verified access to Base Sepolia, bypassing central RPC providers.
    *   **Per-Transaction Persistence**: Stores each transaction's state individually in S3 (`echoes/<hash>.json`). Rebuilds history and processed state on startup.
    *   **Resilient Sync**: Automatically detects and recovers from light client history limits (EIP-2935 buffer range), jumping to the latest block if offline too long.
    *   **Batch Nonce Management**: Tracks nonces locally to support echoing multiple transactions in rapid succession or within the same block.
2.  **Web Dashboard (Frontend)**:
    *   **Vite/React UI**: A premium dashboard to monitor vault status.
    *   **Real-time Activity Log**: Displays verified transaction history with timestamps and direct links to BaseScan.
    *   **TEE Attestation**: Allows users to fetch and verify the hardware-backed Nitro attestation document.

## Quick Start

### Prerequisites
- Python 3.12+
- Node.js 18+
- [Enclaver CLI](https://github.com/mclarkson/enclaver) (for TEE builds)

### Local Development (Mock Mode)
To run the application locally without a real TEE:

1.  **Backend**:
    ```bash
    cd enclave
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    IN_ENCLAVE=false python -m uvicorn app:app --host 0.0.0.0 --port 8000
    ```
2.  **Frontend**:
    ```bash
    cd frontend
    npm install
    npm run dev
    ```

### Build and Run as a Container

To build the Docker image and run it locally as a container:

1.  **Build the Image**:
    ```bash
    docker build -t echo-vault .
    ```
2.  **Run the Container**:
    ```bash
    docker run -p 8000:8000 -e IN_ENCLAVE=false echo-vault
    ```
    *This will start both the backend and frontend in mock mode at [http://localhost:8000](http://localhost:8000).*

## Security Model

The vault's private key is derived within the enclave and never leaves the TEE. Every echo transaction is performed by the deterministic logic of the enclave, which is verifiable via remote attestation. The use of Helios ensures that the enclave cannot be tricked by the host machine providing false blockchain data.
