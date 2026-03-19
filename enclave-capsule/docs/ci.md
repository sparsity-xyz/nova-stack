# CI and Release Workflows

This repository has three GitHub Actions workflows:

- `.github/workflows/ci.yaml`
- `.github/workflows/release.yaml`
- `.github/workflows/nitro-cli.yaml`

This document describes the workflows as they exist in the repository today.

## CI

`ci.yaml` runs on:

- every `push`
- every `pull_request`

Shared behavior:

- concurrency group: `${{ github.workflow }}-${{ github.ref }}`
- `cancel-in-progress: true`
- `CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse`

Jobs:

1. `fmt-check`
   - installs the MSRV from `capsule-cli/Cargo.toml`
   - installs `rustfmt`
   - runs:
     ```bash
     cargo fmt --manifest-path capsule-cli/Cargo.toml --all -- --check
     ```

2. `clippy-check`
   - installs the MSRV
   - installs `clippy`
   - caches `capsule-cli/target`
   - runs:
     ```bash
     RUSTFLAGS="-Dwarnings" \
       cargo clippy --quiet --no-deps --manifest-path capsule-cli/Cargo.toml

     RUSTFLAGS="-Dwarnings" \
       cargo clippy --quiet --no-deps --manifest-path capsule-cli/Cargo.toml \
       --features=run_enclave,capsule-runtime

     RUSTFLAGS="--cfg=tokio_unstable -Dwarnings" \
       cargo clippy --quiet --no-deps --manifest-path capsule-cli/Cargo.toml \
       --features=run_enclave,capsule-runtime,tracing
     ```

3. `test`
   - installs the MSRV
   - caches `capsule-cli/target`
   - runs `cargo test` across this feature matrix:
     - default
     - `run_enclave`
     - `capsule-runtime`
     - `run_enclave,capsule-runtime`

Local reproduction:

```bash
rustup toolchain install "$(sed -n 's/^rust-version = \"\\(.*\\)\"$/\\1/p' capsule-cli/Cargo.toml)"
rustup component add rustfmt clippy

cargo fmt --manifest-path capsule-cli/Cargo.toml --all -- --check

RUSTFLAGS="-Dwarnings" \
  cargo clippy --quiet --no-deps --manifest-path capsule-cli/Cargo.toml

RUSTFLAGS="-Dwarnings" \
  cargo clippy --quiet --no-deps --manifest-path capsule-cli/Cargo.toml \
  --features=run_enclave,capsule-runtime

RUSTFLAGS="--cfg=tokio_unstable -Dwarnings" \
  cargo clippy --quiet --no-deps --manifest-path capsule-cli/Cargo.toml \
  --features=run_enclave,capsule-runtime,tracing

cargo test --quiet --manifest-path capsule-cli/Cargo.toml
cargo test --quiet --manifest-path capsule-cli/Cargo.toml --features=run_enclave
cargo test --quiet --manifest-path capsule-cli/Cargo.toml --features=capsule-runtime
cargo test --quiet --manifest-path capsule-cli/Cargo.toml --features=run_enclave,capsule-runtime
```

## Release

`release.yaml` runs on:

- `release` events of type `published`
- `workflow_dispatch`

Manual workflow inputs:

- `publish_images`
- `upload_artifacts`

Jobs:

1. `build-release-binaries`
   - targets:
     - `x86_64-unknown-linux-musl`
   - builds with `--features=run_enclave,capsule-runtime`
   - uses `./.github/actions/cargo-zigbuild` for musl builds
   - uploads three binaries:
     - `capsule-cli`
     - `capsule-shell`
     - `capsule-runtime`
   - emits SLSA build provenance for `capsule-cli`

2. `publish-images`
   - runs when either:
     - the event is `release`
     - a manual dispatch sets `publish_images=true`
   - downloads build artifacts
   - renames target directories to Docker architecture names:
     - `x86_64-unknown-linux-musl` -> `amd64`
   - publishes only these runtime images:
     - `public.ecr.aws/d4t4u8d2/sparsity-ai/capsule-runtime`
     - `public.ecr.aws/d4t4u8d2/sparsity-ai/capsule-shell`
   - authenticates to AWS via OIDC and pushes image provenance

3. `upload-release-artifact`
   - runs when either:
     - the event is `release`
     - a manual dispatch sets `upload_artifacts=true`
   - packages only the `x86_64` `capsule-cli` binary into a release tarball
   - uploads GitHub Release assets plus matching SHA256 files

Notably:

- `nitro-cli.yaml` is the manual workflow for publishing just the Nitro CLI image
- the Nitro CLI publish path is currently `linux/amd64` only
- `nitro-cli.yaml` validates that the nitro-cli image ships a FUSE-enabled enclave kernel and can complete a smoke `build-enclave` before push
- `ci.yaml` also runs `CAPSULE_CLI_SMOKE_MODE=fixture ./scripts/capsule-build-smoke-test.sh` to validate that `capsule-cli build` completes the `--docker-dir` EIF handoff and release-image packaging path on Linux without depending on public-registry pulls during every CI run
- selected docs, workflows, and helper scripts are also pinned by unit tests in `capsule-cli/src/build.rs`, so some doc/workflow drift fails CI as a normal test regression
- the release workflow still does not upload `capsule-runtime` or `capsule-shell` as standalone GitHub Release tarballs

## Local release reproduction

Build musl release binaries locally:

```bash
cargo install cargo-zigbuild

cargo zigbuild --release \
  --target x86_64-unknown-linux-musl \
  --manifest-path capsule-cli/Cargo.toml \
  --features=run_enclave,capsule-runtime
```

Build release images locally after arranging the `amd64/` artifact directory:

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

Build and validate the amd64-only Nitro CLI image locally:

```bash
./scripts/build-and-publish-nitro-cli.sh --tag latest
```

The official release workflow currently publishes both Capsule Runtime and Capsule Shell only for
`linux/amd64`.

## AWS prerequisites for `publish-images`

The repository includes AWS infrastructure definitions in `aws/cloudformation/infrastructure.yml`.
To run the official publish flow, you need:

- an OIDC trust relationship for GitHub Actions
- the IAM role referenced by `release.yaml`
- public ECR repositories for `sparsity-ai/capsule-runtime` and `sparsity-ai/capsule-shell`

If you also run `.github/workflows/nitro-cli.yaml`, that separate workflow needs the public ECR repository for `sparsity-ai/nitro-cli`.

## References

- workflow definitions: `.github/workflows/ci.yaml`, `.github/workflows/release.yaml`, `.github/workflows/nitro-cli.yaml`
- custom build action: `./.github/actions/cargo-zigbuild`
- local helper: `scripts/build-docker-images.sh`
- AWS infra: `aws/cloudformation/infrastructure.yml`
