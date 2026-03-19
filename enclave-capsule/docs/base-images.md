# Nova Enclave Capsule Base Images

Nova Enclave Capsule uses three important images in its build and runtime flow. The defaults live in `capsule-cli/src/build.rs`:

- Nitro CLI: `public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest`
- Capsule Runtime: `public.ecr.aws/d4t4u8d2/sparsity-ai/capsule-runtime:latest`
- Capsule Shell: `public.ecr.aws/d4t4u8d2/sparsity-ai/capsule-shell:latest`

## What each image does

### Nitro CLI image

Purpose:

- provides `nitro-cli`
- provides the runtime libraries copied into capsule-shell images
- is used as the build environment for `nitro-cli build-enclave`

Relevant files:

- `dockerfiles/capsule-shell-release.dockerfile`
- `dockerfiles/capsule-shell-dev.dockerfile`
- `dockerfiles/nitro-cli.dockerfile`
- `scripts/build-and-publish-nitro-cli.sh`

The repository now publishes a self-hosted `nitro-cli` image through the manual `nitro-cli.yaml` workflow, and Nova Enclave Capsule consumes that image by default. The nitro-cli build rewrites the upstream kernel config to set `CONFIG_FUSE_FS=y`, then replaces the stock enclave blobs with rebuilt bootstrap artifacts.
That rebuilt kernel support is what allows Capsule Runtime to mount host-backed directories through `/dev/fuse` inside the enclave. The publish flow for this image is manual and currently targets `linux/amd64` only.

### Capsule Runtime image

Purpose:

- supplies the `capsule-runtime` supervisor binary at `/usr/local/bin/capsule-runtime`
- is read at build time, then copied into the amended app image as `/sbin/capsule-runtime`

Relevant files:

- `capsule-cli/src/build.rs`
- `dockerfiles/capsule-runtime-dev.dockerfile`
- `dockerfiles/capsule-runtime-release.dockerfile`

Local tags used by repository tooling:

- debug helper build: `capsule-runtime-dev:latest`
- release-style local build: `capsule-runtime:latest`

The published Capsule Runtime image is currently `linux/amd64` only to match the current
release-image publish policy.

### Capsule Shell image

Purpose:

- provides the host-side runtime container entrypoint `capsule-shell`
- provides `nitro-cli` and its runtime libraries
- receives `/enclave/application.eif` and `/enclave/capsule.yaml` as appended layers during `capsule-cli build`

Relevant files:

- `dockerfiles/capsule-shell-dev.dockerfile`
- `dockerfiles/capsule-shell-release.dockerfile`
- `capsule-cli/src/build.rs`
- `capsule-cli/src/run_container.rs`

Local tags used by repository tooling:

- debug helper build: `capsule-shell-dev:latest`
- release-style local build: `capsule-shell:latest`

The published Capsule Shell image is currently `linux/amd64` only. Capsule Shell embeds
`nitro-cli` and its runtime libraries from the self-hosted Nitro CLI image, so
its published platforms currently follow the Nitro CLI image's `linux/amd64`
limit.

## How the images are used

Build time:

1. resolve the app image
2. read the Capsule Runtime binary from the Capsule Runtime image
3. amend the app image with:
   - `/etc/capsule/capsule.yaml`
   - `/sbin/capsule-runtime`
4. tag the amended image locally and write a tiny temporary Docker context whose `Dockerfile` is `FROM <local-tag>`
5. run `nitro-cli build-enclave --docker-dir <that-context>` inside the Nitro CLI image to produce `application.eif`
6. append `application.eif` and `capsule.yaml` to the Capsule Shell image

Runtime:

- the final release image is a Capsule Shell image plus `/enclave/application.eif` and `/enclave/capsule.yaml`
- `capsule-shell` reads `/enclave/capsule.yaml` for host-side runtime behavior and uses `nitro-cli` to launch the enclave
- inside the EIF, `capsule-runtime` reads the matching manifest copy at `/etc/capsule/capsule.yaml`

## Local inspection commands

```bash
docker pull public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest
docker pull public.ecr.aws/d4t4u8d2/sparsity-ai/capsule-runtime:latest
docker pull public.ecr.aws/d4t4u8d2/sparsity-ai/capsule-shell:latest

docker image inspect public.ecr.aws/d4t4u8d2/sparsity-ai/capsule-shell:latest
docker history public.ecr.aws/d4t4u8d2/sparsity-ai/capsule-shell:latest

docker run --rm --entrypoint ls \
  public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest \
  -la /usr/bin /lib64
```

After building a release image locally:

```bash
docker inspect my-release:latest
docker history my-release:latest
docker run --rm --entrypoint ls my-release:latest -la /enclave
```

## Related files

- `capsule-cli/src/build.rs`
- `dockerfiles/nitro-cli.dockerfile`
- `dockerfiles/capsule-runtime-dev.dockerfile`
- `dockerfiles/capsule-runtime-release.dockerfile`
- `dockerfiles/capsule-shell-dev.dockerfile`
- `dockerfiles/capsule-shell-release.dockerfile`
- `scripts/build-docker-images.sh`
- `scripts/build-and-publish-nitro-cli.sh`
