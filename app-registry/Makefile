include .env

.PHONY: deploy deploy-all deploy-atomic test clean

# Build all contracts
build:
	@echo "Building contracts..."
	forge build

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	forge clean

# Atomic deployment - deploys everything in a single script
deploy-atomic:
	@echo "======================================"
	@echo "Atomic Deployment using unified script"
	@echo "======================================"
	forge script script/Deploy.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

# Deploy SP1 Verifier
deploy-sp1:
	@echo "Deploying SP1 Verifier..."
	forge script script/NitroEnclaveVerifier.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --sig 'deploySP1Verifier()'

# Deploy RISC0 Verifier
deploy-risc0:
	@echo "Deploying RISC0 Verifier..."
	forge script script/NitroEnclaveVerifier.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --sig 'deployRisc0Verifier()'

# Deploy NitroEnclaveVerifier
deploy-verifier:
	@echo "Deploying NitroEnclaveVerifier..."
	forge script script/NitroEnclaveVerifier.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --sig 'deployVerifier()'

# Set root certificate
set-root-cert:
	@echo "Setting root certificate..."
	forge script script/NitroEnclaveVerifier.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --sig 'setRootCert(string)' samples/aws_root.der

# Set SP1 ZK configuration
set-sp1-config:
	@echo "Setting SP1 ZK configuration..."
	forge script script/NitroEnclaveVerifier.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --sig 'setZkVerifier(string)' samples/sp1_program_id.json

# Set RISC0 ZK configuration
set-risc0-config:
	@echo "Setting RISC0 ZK configuration..."
	forge script script/NitroEnclaveVerifier.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --sig 'setZkVerifier(string)' samples/risc0_program_id.json

# Deploy SparsityAppRegistry
deploy-registry:
	@echo "Deploying SparsityAppRegistry..."
	forge script script/SparsityAppRegistry.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --sig 'deployRegistry()'

# Set NitroEnclaveVerifier with SparsityAppRegistry
set-verifier:
	@echo "Setting NitroEnclaveVerifier with SparsityAppRegistry..."
	forge script script/SparsityAppRegistry.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --sig 'setVerifier()'

# Deploy everything (SP1 verifier + NitroEnclaveVerifier + SparsityAppRegistry + configuration + registration)
# Note: 5-second delays between steps prevent nonce synchronization issues on public networks
deploy-all:
	@echo "======================================"
	@echo "Full Deployment Starting..."
	@echo "======================================"
	@echo ""
	@echo "Step 1/6: Deploying SP1 Verifier..."
	@$(MAKE) deploy-sp1
	@echo "Waiting for nonce sync..."
	@sleep 5
	@echo ""
	@echo "Step 2/6: Deploying NitroEnclaveVerifier..."
	@$(MAKE) deploy-verifier
	@echo "Waiting for nonce sync..."
	@sleep 5
	@echo ""
	@echo "Step 3/6: Setting root certificate..."
	@$(MAKE) set-root-cert
	@echo "Waiting for nonce sync..."
	@sleep 5
	@echo ""
	@echo "Step 4/6: Setting SP1 ZK configuration..."
	@$(MAKE) set-sp1-config
	@echo "Waiting for nonce sync..."
	@sleep 5
	@echo ""
	@echo "Step 5/6: Deploying SparsityAppRegistry..."
	@$(MAKE) deploy-registry
	@echo "Waiting for nonce sync..."
	@sleep 5
	@echo ""
	@echo "Step 6/6: Setting verifier with registry..."
	@$(MAKE) set-verifier
	@echo ""
	@echo "======================================"
	@echo "✓ Full Deployment Complete!"
	@echo "======================================"
	@echo ""
	@echo "Deployed contracts saved to: deployments/$$(cast chain-id --rpc-url $(RPC_URL)).json"
	@cat deployments/$$(cast chain-id --rpc-url $(RPC_URL)).json | jq '.'

# Quick deploy for local testing (just deploy everything without detailed steps)
deploy-local:
	@echo "Deploying to local network..."
	forge script script/NitroEnclaveVerifier.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast --sig 'deployAll(string,string,string)' samples/aws_root.der samples/sp1_program_id.json samples/risc0_program_id.json

# Verify proof on-chain using NitroEnclaveVerifier directly
verify-proof:
	@if [ -z "$(PROOF_JSON)" ]; then echo "Error: PROOF_JSON not set"; exit 1; fi
	@echo "Verifying proof: $(PROOF_JSON)"
	forge script script/NitroEnclaveVerifier.s.sol --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --sig 'verify(string)' $(PROOF_JSON)

# Validate and registry app using SparsityAppRegistry
register-app:
	@if [ -z "$(PROOF_JSON)" ]; then echo "Error: PROOF_JSON not set"; exit 1; fi
	@if [ -z "$(APP_URL)" ]; then echo "Error: APP_URL not set"; exit 1; fi
	@if [ -z "$(TEE_ARCH)" ]; then echo "Error: TEE_ARCH not set (e.g., TEE_ARCH=nitro or TEE_ARCH=sgx)"; exit 1; fi
	@# CONTRACT_ADDR is optional, default to address(0) if not set
	@# METADATA_URI is optional, default to empty string if not set
	@CONTRACT_ADDR=$${CONTRACT_ADDR:-0x0000000000000000000000000000000000000000}; \
	METADATA_URI=$${METADATA_URI:-""}; \
	forge script script/SparsityAppRegistry.s.sol \
		--rpc-url $(RPC_URL) \
		--private-key $(PRIVATE_KEY) \
		--broadcast \
		--sig 'registerApp(string,string,string,address,string)' \
		$(PROOF_JSON) \
		$(APP_URL) \
		$(TEE_ARCH) \
		$$CONTRACT_ADDR \
		"$$METADATA_URI"

# Check deployed addresses
check-deployments:
	@echo "Deployed contracts:"
	@cat deployments/$$(cast chain-id --rpc-url $(RPC_URL)).json 2>/dev/null | jq '.' || echo "No deployments found for this chain"

fetch-attestation:
	@echo "Fetching attestation..."
	python script/convert_attestation.py $(AGENT_ATTESTATION_URL) samples/attestation.report

generate-proof:
	@echo "Generating proof..."
	nitro-attest-cli prove --sp1 --report samples/attestation.report --out samples/proof.json

# Verify SP1Verifier on Blockscout (no API key required)
verify-sp1-blockscout:
	@CHAIN_ID=$$(cast chain-id --rpc-url $(RPC_URL)); \
	DEPLOYMENTS_FILE="deployments/$$CHAIN_ID.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at $$DEPLOYMENTS_FILE"; exit 1; fi; \
	CONTRACT_ADDRESS=$$(jq -r '.SP1_VERIFIER' $$DEPLOYMENTS_FILE); \
	if [ "$$CONTRACT_ADDRESS" = "null" ] || [ -z "$$CONTRACT_ADDRESS" ]; then echo "Error: SP1Verifier address not found in deployments"; exit 1; fi; \
	echo "Verifying SP1Verifier at $$CONTRACT_ADDRESS..."; \
	forge verify-contract \
		--rpc-url $(RPC_URL) \
		$$CONTRACT_ADDRESS \
		lib/sp1-contracts/contracts/src/v5.0.0/SP1VerifierGroth16.sol:SP1Verifier \
		--verifier blockscout \
		--verifier-url https://base-sepolia.blockscout.com/api/ \
		--watch

# Verify NitroEnclaveVerifier on Blockscout (no API key required)
verify-verifier-blockscout:
	@CHAIN_ID=$$(cast chain-id --rpc-url $(RPC_URL)); \
	DEPLOYMENTS_FILE="deployments/$$CHAIN_ID.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at $$DEPLOYMENTS_FILE"; exit 1; fi; \
	CONTRACT_ADDRESS=$$(jq -r '.VERIFIER' $$DEPLOYMENTS_FILE); \
	if [ "$$CONTRACT_ADDRESS" = "null" ] || [ -z "$$CONTRACT_ADDRESS" ]; then echo "Error: NitroEnclaveVerifier address not found in deployments"; exit 1; fi; \
	echo "Verifying NitroEnclaveVerifier at $$CONTRACT_ADDRESS..."; \
	forge verify-contract \
		--rpc-url $(RPC_URL) \
		$$CONTRACT_ADDRESS \
		src/NitroEnclaveVerifier.sol:NitroEnclaveVerifier \
		--verifier blockscout \
		--verifier-url https://base-sepolia.blockscout.com/api/ \
		--watch

# Verify SparsityAppRegistry on Blockscout (no API key required)
verify-registry-blockscout:
	@CHAIN_ID=$$(cast chain-id --rpc-url $(RPC_URL)); \
	DEPLOYMENTS_FILE="deployments/$$CHAIN_ID.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at $$DEPLOYMENTS_FILE"; exit 1; fi; \
	CONTRACT_ADDRESS=$$(jq -r '.REGISTRY' $$DEPLOYMENTS_FILE); \
	if [ "$$CONTRACT_ADDRESS" = "null" ] || [ -z "$$CONTRACT_ADDRESS" ]; then echo "Error: SparsityAppRegistry address not found in deployments"; exit 1; fi; \
	echo "Verifying SparsityAppRegistry at $$CONTRACT_ADDRESS..."; \
	forge verify-contract \
		--rpc-url $(RPC_URL) \
		$$CONTRACT_ADDRESS \
		src/SparsityAppRegistry.sol:SparsityAppRegistry \
		--verifier blockscout \
		--verifier-url https://base-sepolia.blockscout.com/api/ \
		--watch

# Verify all deployed contracts (Blockscout - no API key required)
verify-all-blockscout:
	@echo "Verifying all deployed contracts on Blockscout..."
	@$(MAKE) verify-sp1-blockscout
	@echo ""
	@$(MAKE) verify-verifier-blockscout
	@echo ""
	@$(MAKE) verify-registry-blockscout

# ========== Basescan Verification (requires BASESCAN_API_KEY in .env) ==========

# Verify SP1Verifier on Basescan
verify-sp1-basescan:
	@CHAIN_ID=$$(cast chain-id --rpc-url $(RPC_URL)); \
	DEPLOYMENTS_FILE="deployments/$$CHAIN_ID.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at $$DEPLOYMENTS_FILE"; exit 1; fi; \
	CONTRACT_ADDRESS=$$(jq -r '.SP1_VERIFIER' $$DEPLOYMENTS_FILE); \
	if [ "$$CONTRACT_ADDRESS" = "null" ] || [ -z "$$CONTRACT_ADDRESS" ]; then echo "Error: SP1Verifier address not found in deployments"; exit 1; fi; \
	echo "Verifying SP1Verifier at $$CONTRACT_ADDRESS on Basescan..."; \
	forge verify-contract \
		--rpc-url $(RPC_URL) \
		$$CONTRACT_ADDRESS \
		lib/sp1-contracts/contracts/src/v5.0.0/SP1VerifierGroth16.sol:SP1Verifier \
		--etherscan-api-key $(BASESCAN_API_KEY) \
		--watch

# Verify NitroEnclaveVerifier on Basescan
verify-verifier-basescan:
	@CHAIN_ID=$$(cast chain-id --rpc-url $(RPC_URL)); \
	DEPLOYMENTS_FILE="deployments/$$CHAIN_ID.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at $$DEPLOYMENTS_FILE"; exit 1; fi; \
	CONTRACT_ADDRESS=$$(jq -r '.VERIFIER' $$DEPLOYMENTS_FILE); \
	if [ "$$CONTRACT_ADDRESS" = "null" ] || [ -z "$$CONTRACT_ADDRESS" ]; then echo "Error: NitroEnclaveVerifier address not found in deployments"; exit 1; fi; \
	echo "Verifying NitroEnclaveVerifier at $$CONTRACT_ADDRESS on Basescan..."; \
	forge verify-contract \
		--rpc-url $(RPC_URL) \
		$$CONTRACT_ADDRESS \
		src/NitroEnclaveVerifier.sol:NitroEnclaveVerifier \
		--etherscan-api-key $(BASESCAN_API_KEY) \
		--watch

# Verify SparsityAppRegistry on Basescan
verify-registry-basescan:
	@CHAIN_ID=$$(cast chain-id --rpc-url $(RPC_URL)); \
	DEPLOYMENTS_FILE="deployments/$$CHAIN_ID.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at $$DEPLOYMENTS_FILE"; exit 1; fi; \
	CONTRACT_ADDRESS=$$(jq -r '.REGISTRY' $$DEPLOYMENTS_FILE); \
	if [ "$$CONTRACT_ADDRESS" = "null" ] || [ -z "$$CONTRACT_ADDRESS" ]; then echo "Error: SparsityAppRegistry address not found in deployments"; exit 1; fi; \
	echo "Verifying SparsityAppRegistry at $$CONTRACT_ADDRESS on Basescan..."; \
	forge verify-contract \
		--rpc-url $(RPC_URL) \
		$$CONTRACT_ADDRESS \
		src/SparsityAppRegistry.sol:SparsityAppRegistry \
		--etherscan-api-key $(BASESCAN_API_KEY) \
		--watch

# Verify all deployed contracts on Basescan (requires BASESCAN_API_KEY)
verify-all-basescan:
	@echo "Verifying all deployed contracts on Basescan..."
	@$(MAKE) verify-sp1-basescan
	@echo ""
	@$(MAKE) verify-verifier-basescan
	@echo ""
	@$(MAKE) verify-registry-basescan