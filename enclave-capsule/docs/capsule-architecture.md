# Nova Enclave Capsule Architecture and Module Reference

This document maps repository files to the build and runtime behavior implemented today.

## Top-level concerns

The codebase has three execution domains:

1. build time
   - turn an app image into an amended image
   - convert that image into an EIF
   - package the EIF into a Capsule Shell image

2. host/container runtime
   - run the Capsule Shell image
   - launch the enclave with `nitro-cli`
   - provide host-side ingress, egress, hostfs, log, status, and clock-sync plumbing

3. enclave runtime
   - run `capsule-runtime` as PID 1
   - provide local platform services
   - launch the user process

## Key modules

### Build path

- `capsule-cli/src/build.rs`
  - main build orchestration
  - resolves default images
  - injects `/sbin/capsule-runtime` and `/etc/capsule/capsule.yaml`
  - packages `/enclave/application.eif` and `/enclave/capsule.yaml`

- `capsule-cli/src/images.rs`
  - Docker image operations and layer append logic

- `capsule-cli/src/nitro_cli_container.rs`
  - runs `nitro-cli build-enclave` inside a container
  - consumes the tiny temporary Docker context that points at the locally tagged amended image

- `capsule-cli/src/manifest.rs`
  - manifest schema
  - validation rules
  - effective defaults such as default-on `clock_sync`
  - `storage.mounts[]` validation for host-backed directory mounts

### Host/runtime path

- `capsule-cli/src/run_container.rs`
  - Docker wrapper for running the Capsule Shell image
  - mounts `/dev/nitro_enclaves`
  - sets `privileged: true`
  - wires `-p/--publish` host port mappings
  - prepares loopback-backed host mount images and bind-mounts them into Capsule Shell

- `capsule-cli/src/hostfs.rs`
  - resolves `--mount` runtime bindings against `storage.mounts[]`
  - creates or reuses fixed-size loopback images
  - mounts them on the parent instance and exposes bind mounts to Capsule Shell
  - stores per-mount runtime metadata under `<host_state_dir>/.capsule-hostfs/`
  - key paths are `disk.img`, `lock`, and transient `mnt-<uuid>/data`

- `capsule-cli/src/run.rs`
  - runtime orchestrator inside the Capsule Shell container
  - starts host-side egress proxy when `egress.allow` enables proxying
  - starts host-side hostfs proxies
  - starts host-side clock-sync server
  - launches the enclave with `nitro-cli`
  - attaches debug console if requested
  - streams status/logs
  - starts host-side ingress proxies

- `capsule-cli/src/fs_protocol.rs`
  - request/response protocol for host-backed filesystem operations over vsock

- `capsule-cli/src/hostfs_service.rs`
  - host-side filesystem service with path validation and read-only enforcement

- `capsule-cli/src/proxy/fs_host.rs`
  - host-side vsock server that exposes one hostfs service per mount

- `capsule-cli/src/nitro_cli.rs`
  - host-side `nitro-cli` wrapper for `run-enclave`, `terminate-enclave`, `describe-eif`, and console access

### Capsule Runtime path

- `capsule-cli/src/bin/capsule-runtime/main.rs`
  - startup and shutdown order

- `capsule-cli/src/bin/capsule-runtime/config.rs`
  - runtime configuration helpers
  - important detail: if `api` is enabled, Aux API is required for attestation and defaults to `api.listen_port + 1`

- `capsule-cli/src/bin/capsule-runtime/enclave.rs`
  - loopback setup and RNG seeding from NSM

- `capsule-cli/src/bin/capsule-runtime/egress.rs`
  - enclave-side HTTP proxy
  - sets uppercase and lowercase proxy env vars

- `capsule-cli/src/bin/capsule-runtime/fs_mount.rs`
  - enclave-side FUSE mount service for host-backed directory mounts
  - probes hostfs proxies, ensures `/dev/fuse` exists, and mounts each configured path

- `capsule-cli/src/bin/capsule-runtime/clock_sync.rs`
  - default-on clock sync client
  - initial sync plus periodic sync

- `capsule-cli/src/bin/capsule-runtime/helios_rpc.rs`
  - Helios Ethereum/OP Stack light-client RPC services
  - background startup, with readiness wait on port `18545` only for registry-backed KMS

- `capsule-cli/src/bin/capsule-runtime/capsule_api.rs`
  - starts the Capsule API server
  - wires S3 and Nova KMS integrations

- `capsule-cli/src/bin/capsule-runtime/aux_api.rs`
  - starts the restricted proxy API

- `capsule-cli/src/bin/capsule-runtime/ingress.rs`
  - enclave-side ingress listeners

- `capsule-cli/src/bin/capsule-runtime/console.rs`
  - stdout/stderr capture
  - status and log VSOCK services

- `capsule-cli/src/bin/capsule-runtime/launcher.rs`
  - launches the user process
  - reaps children

## Shared library modules used by Capsule Runtime

- `capsule-cli/src/capsule_api.rs`
  - Capsule API route implementation

- `capsule-cli/src/aux_api.rs`
  - Aux API proxy and sanitization implementation

- `capsule-cli/src/encryption_key.rs`
  - P-384 ECDH keypair management

- `capsule-cli/src/eth_key.rs`
  - enclave Ethereum key management

- `capsule-cli/src/eth_tx.rs`
  - EIP-1559 transaction parsing/signing helpers

- `capsule-cli/src/http_util.rs`
  - localhost HTTP server helpers

- `capsule-cli/src/proxy/ingress.rs`
  - host and enclave ingress proxy implementations

- `capsule-cli/src/proxy/egress_http.rs`
  - host and enclave egress proxy implementations

- `capsule-cli/src/hostfs_client.rs`
  - enclave-side hostfs client used by the FUSE filesystem implementation

- `capsule-cli/src/policy/*`
  - egress allow/deny rules for domain/IP matching

- `capsule-cli/src/integrations/nova_kms.rs`
  - Nova KMS registry discovery, authz, node selection, end-to-end request protection

- `capsule-cli/src/integrations/nova_kms/app_wallet.rs`
  - app-wallet material lifecycle in KMS KV

- `capsule-cli/src/integrations/s3.rs`
  - S3-backed storage proxy with optional KMS-derived encryption

- `capsule-cli/src/integrations/aws_util.rs`
  - IMDS-based AWS config and credential loading via egress proxy

## Runtime order that matters

### Host side (`capsule-shell`)

1. load `/enclave/capsule.yaml`
2. start host-side egress proxy when `egress.allow` is non-empty
3. start host-side hostfs proxies for bound `storage.mounts[]`
4. start host-side clock-sync server unless `clock_sync.enabled=false`
5. call `nitro-cli run-enclave`
6. after enclave startup:
   - attach debug console if requested
   - start log stream
   - start ingress proxies
   - wait for status stream

### Enclave side (`capsule-runtime`)

1. open status and log listeners first
2. load manifest from `/etc/capsule/capsule.yaml`
3. bootstrap loopback and RNG unless `--no-bootstrap`
4. start host-backed mount service for `storage.mounts[]`
5. start egress service
6. start clock sync
7. start Helios background tasks
8. if registry-backed KMS is enabled, wait for Helios readiness on `18545`
9. start Capsule API and Aux API
10. start ingress
11. launch user process

Shutdown is the reverse order of service startup.

## Image and layout facts

Default images from `capsule-cli/src/build.rs`:

- Nitro CLI: `public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest`
- Capsule Runtime: `public.ecr.aws/d4t4u8d2/sparsity-ai/capsule-runtime:latest`
- Capsule Shell: `public.ecr.aws/d4t4u8d2/sparsity-ai/capsule-shell:latest`

Current published platforms:

- Nitro CLI: `linux/amd64`
- Capsule Runtime: `linux/amd64`
- Capsule Shell: `linux/amd64`

Release image layout:

```text
Capsule Shell base
|- /usr/local/bin/capsule-shell
|- /bin/nitro-cli
|- /enclave/capsule.yaml
`- /enclave/application.eif
```

`capsule-shell` reads the packaged `/enclave/capsule.yaml` copy. Inside the EIF,
`capsule-runtime` reads the matching `/etc/capsule/capsule.yaml` copy that was embedded
before `nitro-cli build-enclave`.

Amended app image before EIF conversion:

```text
original app image
|- /sbin/capsule-runtime
`- /etc/capsule/capsule.yaml
```

## Important constants

- status VSOCK port: `17000`
- app log VSOCK port: `17001`
- host-side egress VSOCK port: `20000 + (CID * 128) + 0`
- host-side clock-sync VSOCK port: `20000 + (CID * 128) + 1`
- host-side hostfs VSOCK port for mount index `N`: `20000 + (CID * 128) + 16 + N`
- default enclave egress proxy port: `10000`

`capsule-shell` manages the enclave CID automatically when it launches the EIF,
so separate Nova Enclave Capsule instances on one EC2 get different host-side VSOCK blocks.

## Related documents

- `docs/architecture.md`
- `docs/capsule-runtime.md`
- `docs/capsule-runtime-details.md`
- `docs/capsule-api.md`
