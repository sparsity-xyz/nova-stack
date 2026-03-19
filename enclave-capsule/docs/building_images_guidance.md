# Building Nova Enclave Capsule Images

This document covers the image-building paths that exist in the repository today:

- local developer images via `scripts/build-docker-images.sh`
- release-style images via `dockerfiles/*-release.dockerfile`
- Nitro CLI image rebuilds with a FUSE-enabled enclave kernel
- the current `capsule-cli build` handoff from a locally tagged intermediate image to `nitro-cli build-enclave --docker-dir`

## Prerequisites

- Docker with `buildx`
- Rust toolchain
- `cross` for musl cross-compilation

Typical setup:

```bash
cargo install cross
docker buildx create --use
```

If `cargo install cross` fails because `cc` is missing, install a C toolchain first.

## One-command local builds

From the repository root:

```bash
./scripts/build-docker-images.sh
```

This default mode:

- currently requires an `x86_64` host
- builds `capsule-runtime` and `capsule-shell` for `x86_64-unknown-linux-musl`
- uses `dockerfiles/capsule-runtime-dev.dockerfile`
- uses `dockerfiles/capsule-shell-dev.dockerfile`
- produces:
  - `capsule-runtime-dev:latest`
  - `capsule-shell-dev:latest`

The helper is currently `x86_64`-only because the default Capsule Shell Dockerfiles
copy `nitro-cli` from the self-hosted Nitro CLI image, and that image is
currently published only for `linux/amd64`.

Release-style local tags:

```bash
./scripts/build-docker-images.sh --release
```

This produces:

- `capsule-runtime:latest`
- `capsule-shell:latest`

## What the helper script actually does

`scripts/build-docker-images.sh`:

1. maps host architecture to:
   - `x86_64` -> `x86_64-unknown-linux-musl`
   - `aarch64` -> unsupported in the default helper
2. runs:
   ```bash
   cross build --target <target> --features run_enclave,capsule-runtime [--release]
   ```
3. copies `capsule-runtime` and `capsule-shell` into a temporary Docker build context
4. builds Capsule Runtime and Capsule Shell images from the selected Dockerfiles

## Current `capsule-cli build` flow

The current `capsule-cli build` implementation in `capsule-cli/src/build.rs` no longer
hands Nitro CLI an unnamed transient image reference.

Instead it:

1. amends the app image with `/sbin/capsule-runtime` and `/etc/capsule/capsule.yaml`
2. tags that amended image locally as `capsule-intermediate-<uuid>:latest`
3. writes a tiny temporary Docker context whose `Dockerfile` is just `FROM <that-local-tag>`
4. runs `nitro-cli build-enclave --docker-dir /build/docker-context --docker-uri capsule-eif-build-<uuid>:latest`

That keeps the EIF build on the local Docker-daemon path and avoids Nitro CLI
trying to resolve a temporary image name from a remote registry.

## Manual developer-image build

Example for `x86_64` debug builds:

```bash
cd capsule-cli
cross build --target x86_64-unknown-linux-musl --features run_enclave,capsule-runtime

tmpdir="$(mktemp -d)"
cp target/x86_64-unknown-linux-musl/debug/capsule-runtime "$tmpdir/"
docker buildx build -f ../dockerfiles/capsule-runtime-dev.dockerfile -t capsule-runtime-dev:latest "$tmpdir"

cp target/x86_64-unknown-linux-musl/debug/capsule-shell "$tmpdir/"
docker buildx build -f ../dockerfiles/capsule-shell-dev.dockerfile -t capsule-shell-dev:latest "$tmpdir"

rm -rf "$tmpdir"
```

For release binaries, switch `debug` to `release` and add `--release` to `cross build`.

## Release Dockerfiles

The release Dockerfiles are designed around the layout used by `.github/workflows/release.yaml`.

Expected artifact layout before building the currently published release images:

```text
./amd64/capsule-runtime
./amd64/capsule-shell
```

Local release-image build example:

```bash
docker buildx build \
  --file dockerfiles/capsule-runtime-release.dockerfile \
  --build-context artifacts=. \
  --platform linux/amd64 \
  -t capsule-runtime:local .

docker buildx build \
  --file dockerfiles/capsule-shell-release.dockerfile \
  --build-context artifacts=. \
  --platform linux/amd64 \
  -t capsule-shell:local .
```

How those Dockerfiles work:

- `capsule-runtime-release.dockerfile` copies `${TARGETARCH}/capsule-runtime` from the `artifacts` build context
- `capsule-shell-release.dockerfile` copies `${TARGETARCH}/capsule-shell` from the `artifacts` build context
- `capsule-shell-release.dockerfile` also copies `nitro-cli` and required runtime libraries from the default Nitro CLI image
- `capsule-runtime-release.dockerfile` is currently published only for `linux/amd64`
- `capsule-shell-release.dockerfile` is currently published only for `linux/amd64`

## Nitro CLI image

This repository includes `dockerfiles/nitro-cli.dockerfile`, `scripts/build-and-publish-nitro-cli.sh`, and `scripts/validate-nitro-cli-image.sh`.

Detailed background on the Nitro CLI kernel/blob rebuild flow lives in
[`docs/nitro_cli_fuse_image.md`](nitro_cli_fuse_image.md).

Build it locally:

```bash
docker buildx build -f dockerfiles/nitro-cli.dockerfile -t nitro-cli:latest .
```

Or use the helper script:

```bash
./scripts/build-and-publish-nitro-cli.sh --tag latest
```

The nitro-cli Dockerfile now rewrites the upstream kernel config in place to set `CONFIG_FUSE_FS=y` before rebuilding the official Nitro Enclaves blobs. The helper script then builds a local `linux/amd64` validation image, checks that the rebuilt enclave kernel exposes `CONFIG_FUSE_FS`, performs a smoke `nitro-cli build-enclave`, and only then pushes the `linux/amd64` image. Nova Enclave Capsule uses `public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest` by default.
That self-hosted Nitro CLI image is what gives Nova Enclave Capsule EIFs the FUSE support required for host-backed directory mounts and the hostfs file proxy.

To smoke-test the full `capsule-cli build` path itself, including the local Docker-context handoff to `nitro-cli build-enclave --docker-dir`, run:

```bash
cargo build --manifest-path capsule-cli/Cargo.toml --bin capsule-cli
CAPSULE_CLI_BIN=./capsule-cli/target/debug/capsule-cli ./scripts/capsule-build-smoke-test.sh
```

For a deterministic Linux-only smoke path that avoids public-registry pulls by
prebuilding local fixture images, run:

```bash
cargo build --manifest-path capsule-cli/Cargo.toml --bin capsule-cli
CAPSULE_CLI_SMOKE_MODE=fixture \
  CAPSULE_CLI_BIN=./capsule-cli/target/debug/capsule-cli \
  ./scripts/capsule-build-smoke-test.sh
```

## Troubleshooting

- Missing `cross`: `cargo install cross`
- Missing `buildx`: `docker buildx create --use`
- Missing `protoc` during cross builds: provide `PROTOC` or use a build image that includes it
- On macOS, remember these images target Linux musl; build and runtime validation should happen on Linux

## Related files

- `scripts/build-docker-images.sh`
- `scripts/build-and-publish-nitro-cli.sh`
- `scripts/capsule-build-smoke-test.sh`
- `dockerfiles/capsule-runtime-dev.dockerfile`
- `dockerfiles/capsule-runtime-release.dockerfile`
- `dockerfiles/capsule-shell-dev.dockerfile`
- `dockerfiles/capsule-shell-release.dockerfile`
- `dockerfiles/nitro-cli.dockerfile`
- `.github/workflows/release.yaml`
