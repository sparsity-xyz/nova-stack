# Nova Enclave Capsule CLI Reference

The `capsule-cli` command-line tool is the primary interface for building and running secure applications in Nitro Enclaves.

## Usage

```bash
capsule-cli [OPTIONS] <COMMAND>
```

## Global Options

| Option | Description |
|--------|-------------|
| `-v`, `--verbose` | Increase logging verbosity (can be used multiple times). |
| `-h`, `--help` | Print help information. |
| `-V`, `--version` | Print version information. |

---

## Commands

### `build`

Packages a Docker image into a self-executing Nova Enclave Capsule container image.

#### Options

| Option | Description |
|--------|-------------|
| `-f`, `--file <PATH>` | Path to the Nova Enclave Capsule manifest file (`capsule.yaml`). Defaults to `capsule.yaml` in the current directory. Pass `-` to read from stdin. |
| `--pull` | Always pull the source Docker images to ensure the latest versions are used. |

Without `--pull`, `capsule-cli build` is local-first: it reuses locally available
app, capsule-runtime, capsule-shell, and nitro-cli images when present and pulls only missing refs.

#### Example
```bash
capsule-cli build -f my-service.yaml
```

---

### `run`

Runs a pre-packaged Nova Enclave Capsule container image. This command simplifies the `docker run` process by automatically handling device mapping and privileged mode requirements.

#### Options

| Option | Description |
|--------|-------------|
| `-f`, `--file <PATH>` | Nova Enclave Capsule manifest file. If provided, `capsule-cli` will look up the `target` image name from this file. It also supplies `storage.mounts[]` metadata when `--mount` is used. |
| `image` (positional) | Name of a pre-existing Nova Enclave Capsule image to run. Only used if `-f` is not specified. |
| `-p`, `--publish <PORT_MAP>` | Port to expose on the host machine (e.g., `8080:80`). Can be used multiple times. |
| `-d`, `--debug-mode` | Enable debug mode for the enclave supervisor. |
| `--cpu-count <INT>` | **(New)** Number of vCPUs to assign to the enclave. Overrides the `defaults` section in `capsule.yaml`. |
| `--memory-mb <INT>` | **(New)** Enclave memory in MiB. Overrides the `defaults` section in `capsule.yaml`. |
| `--mount <NAME=HOST_STATE_DIR>` | Prepare or reuse a loopback-image-backed host directory for a manifest-declared `storage.mounts[]` entry and expose it inside the enclave at that mount's `mount_path` through the hostfs file proxy. `mount_path` must live under `/mnt/...`. Reusing the same `HOST_STATE_DIR` preserves contents across runs. Requires manifest lookup via `-f` or the default `capsule.yaml`. |

#### Parameter Priority (CPU/RAM)

When using `capsule-cli run`, the resource allocation is determined by:
1. **Command-line flags** (`--cpu-count`, `--memory-mb`) - **Highest priority**.
2. **Manifest defaults** (the `defaults` section in `capsule.yaml`).
3. **Hardcoded defaults** (CPU: 2, Memory: 4096 MiB).

If neither `-f` nor `image` is provided, `capsule-cli run` falls back to `capsule.yaml` in the current directory.
Providing both `-f` and `image` is an error.

#### Examples

**Run using manifest lookup:**
```bash
sudo capsule-cli run -f capsule.yaml
```

**Run specific image with overrides:**
```bash
sudo capsule-cli run my-service:latest --cpu-count 4 --memory-mb 8192
```

**Publishing ports:**
```bash
sudo capsule-cli run my-service:latest -p 8080:80 -p 9000:9000
```

**Host-backed directory mount:**
```bash
sudo capsule-cli run -f capsule.yaml --mount appdata=/var/lib/my-service/appdata
```

---

## Notes

- **Privileges**: Running enclaves requires Docker/device access to `/dev/nitro_enclaves`. Many setups use `sudo capsule-cli run ...`.
- **Docker Dependency**: `capsule-cli run` requires a running Docker daemon.
- **Multiple instances on one EC2**: separate `capsule-cli run` processes can coexist on the same EC2 because `capsule-shell` derives host-side VSOCK listeners from an automatically managed enclave CID. Docker `-p` host ports still must not overlap.
- **Port Model**: For full details on `ingress` vs `--publish` and the host/container/enclave mapping layers, see [Port Handling](port_handling.md).
- **Host-backed mounts**: `--mount` provisions or reuses a dedicated loopback image under the supplied host state directory, binds it into the Capsule Shell container, and `capsule-runtime` mounts it inside the enclave through the hostfs file proxy before the application starts.
