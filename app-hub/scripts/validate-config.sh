#!/bin/bash

# Nova App Hub - Configuration Validation Script
# This script validates nova-build.yaml files against the schema

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SCHEMA_FILE="$REPO_ROOT/schemas/nova-build.schema.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_error() {
    echo -e "${RED}ERROR: $1${NC}" >&2
}

print_success() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

# Check if required tools are installed
check_dependencies() {
    local missing_deps=()
    
    if ! command -v yq &> /dev/null; then
        missing_deps+=("yq")
    fi
    
    if ! command -v ajv &> /dev/null; then
        missing_deps+=("ajv-cli")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        echo "Install with:"
        echo "  npm install -g ajv-cli"
        echo "  brew install yq  # or: pip install yq"
        exit 1
    fi
}

# Validate a single nova-build.yaml file
validate_file() {
    local config_file="$1"
    local errors=0
    
    echo "Validating: $config_file"
    
    # Check if file exists
    if [ ! -f "$config_file" ]; then
        print_error "File not found: $config_file"
        return 1
    fi
    
    # Convert YAML to JSON and validate against schema
    local json_content
    json_content=$(yq eval -o=json "$config_file" 2>/dev/null)
    if [ $? -ne 0 ]; then
        print_error "Invalid YAML syntax in $config_file"
        return 1
    fi
    
    # Validate against JSON schema
    echo "$json_content" | ajv validate -s "$SCHEMA_FILE" -d /dev/stdin --strict=false 2>&1
    if [ $? -ne 0 ]; then
        print_error "Schema validation failed for $config_file"
        errors=$((errors + 1))
    fi
    
    # Extract values for additional validation
    local repo=$(echo "$json_content" | jq -r '.repo // ""')
    local name=$(echo "$json_content" | jq -r '.name // ""')
    local branch=$(echo "$json_content" | jq -r '.branch // ""')
    local directory=$(echo "$json_content" | jq -r '.build.directory // "."')
    local dockerfile=$(echo "$json_content" | jq -r '.build.dockerfile // "Dockerfile"')
    
    # Validate repo is public GitHub URL
    if [[ ! "$repo" =~ ^https://github\.com/ ]]; then
        print_error "Repository must be a public GitHub URL (https://github.com/...)"
        errors=$((errors + 1))
    fi
    
    # Check if directory name matches app name
    local dir_name=$(basename "$(dirname "$config_file")")
    if [ "$dir_name" != "$name" ]; then
        print_error "Directory name '$dir_name' must match app name '$name'"
        errors=$((errors + 1))
    fi
    
    # Verify repository is accessible (optional, can be slow)
    if [ "${SKIP_REPO_CHECK:-false}" != "true" ]; then
        echo "  Checking repository accessibility..."
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "$repo")
        if [ "$http_code" != "200" ]; then
            print_error "Repository not accessible or not public: $repo (HTTP $http_code)"
            errors=$((errors + 1))
        fi
    fi
    
    if [ $errors -eq 0 ]; then
        print_success "Validation passed for $config_file"
        return 0
    else
        return 1
    fi
}

# Validate all changed files or specific file
main() {
    check_dependencies
    
    local exit_code=0
    
    if [ $# -eq 0 ]; then
        # Validate all nova-build.yaml files in apps/
        for config_file in "$REPO_ROOT"/apps/*/nova-build.yaml; do
            if [ -f "$config_file" ]; then
                validate_file "$config_file" || exit_code=1
                echo ""
            fi
        done
    else
        # Validate specific files
        for config_file in "$@"; do
            validate_file "$config_file" || exit_code=1
            echo ""
        done
    fi
    
    if [ $exit_code -eq 0 ]; then
        print_success "All validations passed!"
    else
        print_error "Some validations failed"
    fi
    
    exit $exit_code
}

main "$@"
