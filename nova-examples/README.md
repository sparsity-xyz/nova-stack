# Nova Platform Development Guide

This guide explains how to develop enclave applications for the Nova Platform.

## 1. Enclave Architecture

On the Nova Platform, user applications run inside an **AWS Nitro Enclave** — an isolated, hardware-secured environment.

### The Challenge: Nitro Enclave Complexity

Deploying applications directly to Nitro Enclaves is notoriously difficult:

- **No standard networking** — Enclaves have no network interfaces; all communication must go through VSOCK, requiring custom proxy implementations
- **No persistent storage** — Applications cannot access the host filesystem and must handle all state management carefully
- **Limited entropy sources** — Standard `/dev/random` doesn't work; you must integrate with the Nitro Secure Module (NSM) for cryptographic randomness
- **Complex attestation workflow** — Generating and verifying attestation documents requires deep understanding of NSM APIs and CBOR encoding
- **Custom key management** — Secure key generation and storage inside the enclave requires significant cryptographic engineering
- **Process supervision challenges** — No systemd or standard init systems; you must build your own process lifecycle management

These challenges make enclave development inaccessible to most developers and significantly slow down time-to-production.

### The Solution: Odyn

**Odyn** is the enclave supervisor that runs alongside your application, abstracting away all enclave complexity. You write a normal web application; Odyn handles the rest.

**What Odyn Does For You:**

| Challenge | Odyn Solution |
|-----------|---------------|
| No networking | Provides HTTP ingress/egress proxies over VSOCK |
| No entropy | Seeds RNG from NSM automatically |
| Complex attestation | Simple REST API: `POST /v1/attestation` |
| Key management | Built-in Ethereum wallet with signing APIs |
| Process supervision | Launches, monitors, and restarts your app |
| Logging | Captures stdout/stderr and exposes via VSOCK |

### Services Provided to Your Application

- Secure key management and Ethereum signing
- Cryptographic random number generation (from NSM)
- Hardware-level remote attestation
- End-to-end encryption (ECDH + AES-256-GCM)

## 2. Application Packaging and Deployment

Your application needs to be packaged as a **Docker image**. During development, you can follow standard practices:

- Use any programming language and framework
- Use network functionality normally (HTTP requests, database connections, etc.)
- Remember your application's listening port (needed for configuration)

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

# Remember your application's listening port
EXPOSE 8080
CMD ["python", "main.py"]
```

## 3. Odyn API Service

Inside the enclave, access Odyn's API service to use Nitro Enclave security features:

| Environment              | Base URL                           |
|--------------------------|------------------------------------|
| Production (in enclave)  | `http://localhost:18000`           |
| Development (mock)       | `http://odyn.sparsity.cloud:18000` |

### API Reference

| Endpoint                  | Method | Description                                  |
|---------------------------|--------|----------------------------------------------|
| `/v1/eth/address`         | GET    | Get enclave's Ethereum address and public key |
| `/v1/eth/sign`            | POST   | Sign a message (EIP-191) with optional attestation |
| `/v1/eth/sign-tx`         | POST   | Sign an Ethereum transaction                 |
| `/v1/random`              | GET    | Get 32 cryptographically secure random bytes |
| `/v1/attestation`         | POST   | Generate a hardware attestation document     |
| `/v1/encryption/public_key` | GET  | Get enclave's encryption public key          |
| `/v1/encryption/encrypt`  | POST   | Encrypt data with client's public key        |
| `/v1/encryption/decrypt`  | POST   | Decrypt data sent to the enclave             |

> 📖 For complete API documentation with request/response examples, see: [Enclaver Internal API](https://github.com/sparsity-xyz/enclaver/blob/sparsity/docs/internal_api.md)

### Environment Configuration

Use the `IN_ENCLAVE` environment variable to switch between development and production:

```python
import os

IN_ENCLAVE = os.getenv("IN_ENCLAVE", "false").lower() == "true"

if IN_ENCLAVE:
    ODYN_BASE_URL = "http://localhost:18000"
else:
    ODYN_BASE_URL = "http://odyn.sparsity.cloud:18000"
```

Set in your Dockerfile:

```dockerfile
ENV IN_ENCLAVE=false  # Set to true in production
```

## 4. Reference Implementation

Refer to the Odyn wrapper implementation in the `secured-chat-bot` example project:

📁 [`secured-chat-bot/enclave/odyn.py`](./secured-chat-bot/enclave/odyn.py)

This implementation demonstrates:
- Automatic environment detection and endpoint switching
- Complete API method wrappers
- Encryption/decryption usage examples
- Message signing functionality

```python
from odyn import Odyn

# Automatically selects endpoint based on environment
odyn = Odyn()

# Get Ethereum address
address = odyn.eth_address()

# Sign a message
signature = odyn.sign_message({"data": "hello"})

# Get random bytes
random_bytes = odyn.get_random_bytes(16)

# Get attestation document
attestation = odyn.get_attestation()
```

## 5. Frontend Deployment

Enclave applications typically run as API services. There are two approaches for frontend deployment:

### Option 1: Separate Frontend Deployment

Deploy frontend code separately on an external server or CDN, communicating with the enclave service via API.

> ⚠️ **CORS Configuration Required**: When your frontend is hosted on a different domain than your enclave API, you must configure CORS (Cross-Origin Resource Sharing) on your backend to allow cross-origin requests. Otherwise, browsers will block API requests from your frontend.

**FastAPI CORS Example:**
```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-frontend-domain.com"],  # Or ["*"] for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Option 2: Enclave-Embedded Frontend

Provide a static file serving endpoint within your enclave application, such as `/frontend`, to serve compiled frontend code:

```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI()

# Mount static frontend files
app.mount("/frontend", StaticFiles(directory="frontend_dist", html=True), name="frontend")

# API routes
@app.get("/api/status")
def get_status():
    return {"status": "running"}
```

This approach allows users to access the complete application interface directly.

---

## Quick Start

1. **Create Application Directory Structure**
   ```
   my-enclave-app/
   ├── enclave/
   │   ├── main.py
   │   ├── odyn.py      # Copy from secured-chat-bot/enclave/odyn.py
   │   ├── requirements.txt
   │   └── Dockerfile
   └── frontend/        # Optional
       └── ...
   ```

2. **Copy Odyn Helper**
   ```bash
   cp secured-chat-bot/enclave/odyn.py my-enclave-app/enclave/
   ```

3. **Use Odyn Service**
   ```python
   from odyn import Odyn
   
   odyn = Odyn()
   # Now you can use all enclave features
   ```

4. **Local Testing**
   ```bash
   IN_ENCLAVE=false python main.py
   ```

5. **Build Docker Image and Deploy to Nova Platform**

---

## More Examples

| Example Project | Description |
|-----------------|-------------|
| [secured-chat-bot](./secured-chat-bot) | Secure chatbot demonstrating end-to-end encryption |
| [rng-oracle](./oracles/rng-oracle) | RNG Oracle for verifiable on-chain random numbers |
| [price-oracle](./oracles/price-oracle) | Price oracle demonstrating API signature verification |

---

## Related Links

- [Enclaver Internal API Documentation](https://github.com/sparsity-xyz/enclaver/blob/sparsity/docs/internal_api.md)
- [Nova Platform](https://sparsity.cloud)
