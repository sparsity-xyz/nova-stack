# Capsule API Mock

This repository does not implement a local `capsule-api-mock` service.

What exists here is:

- the real Capsule API implemented in `capsule-cli/src/capsule_api.rs`
- the real Aux API implemented in `capsule-cli/src/aux_api.rs`
- example client code in external Nova example repositories

## External mock endpoints

Some applications choose to talk to a separately hosted development endpoint
when they are not running inside an enclave.

That endpoint is not part of this repository and is not versioned together with
Nova Enclave Capsule. Treat any such URL as an external development convenience, not as a
guaranteed mirror of the current `capsule-api` implementation.

## Recommended usage pattern

If you want your app to switch between enclave-local and external development endpoints, use an app-level environment variable:

```python
import os

IN_ENCLAVE = os.getenv("IN_ENCLAVE", "false").lower() == "true"
CAPSULE_API_MOCK_URL = os.getenv("CAPSULE_API_MOCK_URL", "http://localhost:18000")
CAPSULE_API_BASE_URL = "http://127.0.0.1:18000" if IN_ENCLAVE else CAPSULE_API_MOCK_URL
```

Notes:

- `IN_ENCLAVE` is not set automatically by Nova Enclave Capsule
- `CAPSULE_API_MOCK_URL` is an application choice, not a Nova Enclave Capsule-managed endpoint
- choose and manage that convention in your own application image or deployment environment
- if your manifest uses a different `api.listen_port`, update the enclave-local URL accordingly

## Compatibility expectations

When using an external mock service, do not assume:

- every endpoint from `docs/capsule-api.md` exists
- response bodies exactly match the current repository implementation
- KMS, app-wallet, S3, or attestation behavior is fully faithful
- error codes and edge cases match the current `capsule-api`

The authoritative contract for this repository is the implementation plus:

- `docs/capsule-api.md`
- `docs/encryption.md`
- `docs/capsule-runtime.md`

## Recommendation

Use the external mock only for lightweight application development loops. Before relying on a behavior, verify it against the real enclave runtime or the actual code in this repository.
