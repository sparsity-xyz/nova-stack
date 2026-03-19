#!/bin/bash
# ---------------------------------------------------------------------------
# build-docker-images.sh - developer helper to build dev Docker images with
#                          enclave binaries (capsule-runtime, capsule-shell)
# ---------------------------------------------------------------------------

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse command-line arguments
BUILD_MODE="${BUILD_MODE:-debug}"

show_help() {
    echo "Usage: $0 [--release|--debug] [--help]"
    echo ""
    echo "Build development Docker images with enclave binaries (capsule-runtime, capsule-shell)."
    echo ""
    echo "Options:"
    echo "  --release    Build optimized release binaries"
    echo "  --debug      Build debug binaries (default)"
    echo "  --help       Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  BUILD_MODE   Set to 'release' or 'debug' (command-line flag overrides)"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)
            BUILD_MODE="release"
            shift
            ;;
        --debug)
            BUILD_MODE="debug"
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Run '$0 --help' for usage information."
            exit 1
            ;;
    esac
done

local_arch=$(uname -m)
case $local_arch in
    x86_64)
        rust_target="x86_64-unknown-linux-musl"
        docker_target_arch="amd64"
        ;;
    aarch64)
        log_error "scripts/build-docker-images.sh currently requires an x86_64 host."
        echo "The default capsule-shell Dockerfiles copy nitro-cli from our self-hosted nitro-cli image,"
        echo "and that image is currently published only for linux/amd64."
        exit 1
        ;;
    *)
        log_error "Unsupported architecture: $local_arch"
        exit 1
        ;;
esac

capsule_cli_dir="$(dirname "$(dirname "${BASH_SOURCE[0]}")")/capsule-cli"

# Default tags (debug)
capsule_runtime_tag="capsule-runtime-dev:latest"
capsule_shell_tag="capsule-shell-dev:latest"
capsule_runtime_dockerfile="capsule-runtime-dev.dockerfile"
capsule_shell_dockerfile="capsule-shell-dev.dockerfile"

# Set build mode-specific variables
if [ "$BUILD_MODE" = "release" ]; then
    rust_target_dir="./target/${rust_target}/release"
    CROSS_BUILD_FLAGS="--release"
    capsule_runtime_tag="capsule-runtime:latest"
    capsule_shell_tag="capsule-shell:latest"
    capsule_runtime_dockerfile="capsule-runtime-release.dockerfile"
    capsule_shell_dockerfile="capsule-shell-release.dockerfile"
    log_info "Build mode: RELEASE (optimized)"
else
    rust_target_dir="./target/${rust_target}/debug"
    CROSS_BUILD_FLAGS=""
    log_info "Build mode: DEBUG (unoptimized)"
fi

cd "$capsule_cli_dir"

docker_build_dir=$(mktemp -d)
trap "rm --force --recursive ${docker_build_dir}" EXIT

# Check for 'cross'
if ! command -v cross >/dev/null 2>&1; then
    log_error "'cross' is required but not found in PATH."
    echo "Install it with: cargo install cross"
    exit 1
fi

log_info "Building Rust artifacts with 'cross' for target: $rust_target"
cross build --target "$rust_target" ${CROSS_BUILD_FLAGS} --features run_enclave,capsule_runtime

log_info "Copying built artifacts from: ${rust_target_dir}"
artifacts_arch_dir="${docker_build_dir}/${docker_target_arch}"
mkdir -p "${artifacts_arch_dir}"
cp "$rust_target_dir/capsule-runtime" "${artifacts_arch_dir}/"
cp "$rust_target_dir/capsule-shell" "${artifacts_arch_dir}/"

log_info "Building images using Dockerfiles: ${capsule_runtime_dockerfile}, ${capsule_shell_dockerfile}"
DOCKER_BUILDKIT=1 docker build \
    --build-context artifacts="${docker_build_dir}" \
    -f ../dockerfiles/${capsule_runtime_dockerfile} \
    -t "${capsule_runtime_tag}" \
    "${docker_build_dir}"

DOCKER_BUILDKIT=1 docker build \
    --build-context artifacts="${docker_build_dir}" \
    -f ../dockerfiles/${capsule_shell_dockerfile} \
    -t "${capsule_shell_tag}" \
    "${docker_build_dir}"

log_info "Build complete!"
log_info "To use dev images, merge the following into capsule.yaml:"
echo ""
echo "sources:"
echo "   capsule-runtime: \"${capsule_runtime_tag}\""
echo "   capsule-shell: \"${capsule_shell_tag}\""
