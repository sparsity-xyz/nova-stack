-include .env

# Support generic ETHERSCAN_API_KEY if BASESCAN_API_KEY is not set
BASESCAN_API_KEY ?= $(ETHERSCAN_API_KEY)

.PHONY: install build clean test deploy deploy-nova upgrade-nova check-deployments \
	verify-all-blockscout verify-sp1-blockscout verify-verifier-blockscout verify-nova-blockscout \
	verify-all-basescan verify-sp1-basescan verify-verifier-basescan verify-nova-basescan

# Install dependencies
install:
	@echo "Installing dependencies..."
	@mkdir -p lib
	@[ -d lib/forge-std ] || forge install foundry-rs/forge-std --no-git
	@[ -d lib/openzeppelin-contracts ] || forge install OpenZeppelin/openzeppelin-contracts@v5.3.0 --no-git
	@[ -d lib/openzeppelin-contracts-upgradeable ] || forge install OpenZeppelin/openzeppelin-contracts-upgradeable@v5.3.0 --no-git
	@[ -d lib/solady ] || forge install Vectorized/solady --no-git
	@[ -d lib/sp1-contracts ] || forge install succinctlabs/sp1-contracts --no-git
	@[ -d lib/risc0-ethereum ] || forge install risc0/risc0-ethereum --no-git

# Build all contracts
build:
	@echo "Building contracts..."
	forge build

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	forge clean

# Deploy Nova (3-layer hierarchy with UUPS proxy)
deploy-nova:
	@echo "======================================"
	@echo "Deploying Nova Platform with UUPS Proxy"
	@echo "======================================"
	forge script script/DeployNova.s.sol --tc DeployNovaScript --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

# Upgrade Nova registry
upgrade-nova:
	@echo "======================================"
	@echo "Upgrading Nova Registry"
	@echo "======================================"
	PROXY=$(PROXY) forge script script/DeployNova.s.sol --tc UpgradeNovaScript --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) --broadcast

# Deploy alias (points to deploy-nova)
deploy: deploy-nova

# Check deployed addresses
check-deployments:
	@echo "Deployed contracts:"
	@cat deployments/$$(cast chain-id --rpc-url $(RPC_URL))_nova.json 2>/dev/null | jq '.' || echo "No deployments found for this chain"

# Verify SP1Verifier on Blockscout (no API key required)
verify-sp1-blockscout:
	@CHAIN_ID=$$(cast chain-id --rpc-url $(RPC_URL)); \
	DEPLOYMENTS_FILE="deployments/$${CHAIN_ID}_nova.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at deployments/$${CHAIN_ID}_nova.json"; exit 1; fi; \
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
	DEPLOYMENTS_FILE="deployments/$${CHAIN_ID}_nova.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at deployments/$${CHAIN_ID}_nova.json"; exit 1; fi; \
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

# Verify NovaAppRegistry on Blockscout (no API key required)
verify-nova-blockscout:
	@CHAIN_ID=$$(cast chain-id --rpc-url $(RPC_URL)); \
	DEPLOYMENTS_FILE="deployments/$${CHAIN_ID}_nova.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at deployments/$${CHAIN_ID}_nova.json"; exit 1; fi; \
	CONTRACT_ADDRESS=$$(jq -r '.REGISTRY_IMPLEMENTATION' $$DEPLOYMENTS_FILE); \
	if [ "$$CONTRACT_ADDRESS" = "null" ] || [ -z "$$CONTRACT_ADDRESS" ]; then echo "Error: NovaAppRegistry implementation address not found in deployments"; exit 1; fi; \
	echo "Verifying NovaAppRegistry implementation at $$CONTRACT_ADDRESS..."; \
	forge verify-contract \
	--rpc-url $(RPC_URL) \
	$$CONTRACT_ADDRESS \
	src/NovaAppRegistry.sol:NovaAppRegistry \
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
	@$(MAKE) verify-nova-blockscout
	@echo ""
	@$(MAKE) verify-proxy-blockscout

# Verify ERC1967Proxy on Blockscout
verify-proxy-blockscout:
	@CHAIN_ID=$$(cast chain-id --rpc-url $(RPC_URL)); \
	DEPLOYMENTS_FILE="deployments/$${CHAIN_ID}_nova.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at deployments/$${CHAIN_ID}_nova.json"; exit 1; fi; \
	CONTRACT_ADDRESS=$$(jq -r '.REGISTRY_PROXY' $$DEPLOYMENTS_FILE); \
	if [ "$$CONTRACT_ADDRESS" = "null" ] || [ -z "$$CONTRACT_ADDRESS" ]; then echo "Error: NovaAppRegistry proxy address not found in deployments"; exit 1; fi; \
	echo "Verifying ERC1967Proxy at $$CONTRACT_ADDRESS on Blockscout..."; \
	forge verify-contract \
	--rpc-url $(RPC_URL) \
	$$CONTRACT_ADDRESS \
	lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
	--constructor-args $$(cast abi-encode "constructor(address,bytes)" $$(jq -r '.REGISTRY_IMPLEMENTATION' $$DEPLOYMENTS_FILE) "0x") \
	--verifier blockscout \
	--verifier-url https://base-sepolia.blockscout.com/api/ \
	--watch

# ========== Basescan Verification (requires BASESCAN_API_KEY in .env) ==========

# Verify SP1Verifier on Basescan
verify-sp1-basescan:
	@CHAIN_ID=$$(cast chain-id --rpc-url $(RPC_URL)); \
	DEPLOYMENTS_FILE="deployments/$${CHAIN_ID}_nova.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at deployments/$${CHAIN_ID}_nova.json"; exit 1; fi; \
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
	DEPLOYMENTS_FILE="deployments/$${CHAIN_ID}_nova.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at deployments/$${CHAIN_ID}_nova.json"; exit 1; fi; \
	CONTRACT_ADDRESS=$$(jq -r '.VERIFIER' $$DEPLOYMENTS_FILE); \
	if [ "$$CONTRACT_ADDRESS" = "null" ] || [ -z "$$CONTRACT_ADDRESS" ]; then echo "Error: NitroEnclaveVerifier address not found in deployments"; exit 1; fi; \
	echo "Verifying NitroEnclaveVerifier at $$CONTRACT_ADDRESS on Basescan..."; \
	forge verify-contract \
	--rpc-url $(RPC_URL) \
	$$CONTRACT_ADDRESS \
	src/NitroEnclaveVerifier.sol:NitroEnclaveVerifier \
	--etherscan-api-key $(BASESCAN_API_KEY) \
	--watch

# Verify NovaAppRegistry on Basescan
verify-nova-basescan:
	@CHAIN_ID=$$(cast chain-id --rpc-url $(RPC_URL)); \
	DEPLOYMENTS_FILE="deployments/$${CHAIN_ID}_nova.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at deployments/$${CHAIN_ID}_nova.json"; exit 1; fi; \
	CONTRACT_ADDRESS=$$(jq -r '.REGISTRY_IMPLEMENTATION' $$DEPLOYMENTS_FILE); \
	if [ "$$CONTRACT_ADDRESS" = "null" ] || [ -z "$$CONTRACT_ADDRESS" ]; then echo "Error: NovaAppRegistry implementation address not found in deployments"; exit 1; fi; \
	echo "Verifying NovaAppRegistry at $$CONTRACT_ADDRESS on Basescan..."; \
	forge verify-contract \
	--rpc-url $(RPC_URL) \
	$$CONTRACT_ADDRESS \
	src/NovaAppRegistry.sol:NovaAppRegistry \
	--etherscan-api-key $(BASESCAN_API_KEY) \
	--watch

# Verify all deployed contracts on Basescan (requires BASESCAN_API_KEY)
verify-all-basescan:
	@echo "Verifying all deployed contracts on Basescan..."
	@$(MAKE) verify-sp1-basescan
	@echo ""
	@$(MAKE) verify-verifier-basescan
	@echo ""
	@$(MAKE) verify-nova-basescan
	@echo ""
	@$(MAKE) verify-proxy-basescan

# Verify ERC1967Proxy on Basescan
verify-proxy-basescan:
	@CHAIN_ID=$$(cast chain-id --rpc-url $(RPC_URL)); \
	DEPLOYMENTS_FILE="deployments/$${CHAIN_ID}_nova.json"; \
	if [ ! -f "$$DEPLOYMENTS_FILE" ]; then echo "Error: No deployments found at deployments/$${CHAIN_ID}_nova.json"; exit 1; fi; \
	CONTRACT_ADDRESS=$$(jq -r '.REGISTRY_PROXY' $$DEPLOYMENTS_FILE); \
	if [ "$$CONTRACT_ADDRESS" = "null" ] || [ -z "$$CONTRACT_ADDRESS" ]; then echo "Error: NovaAppRegistry proxy address not found in deployments"; exit 1; fi; \
	echo "Verifying ERC1967Proxy at $$CONTRACT_ADDRESS on Basescan..."; \
	forge verify-contract \
	--rpc-url $(RPC_URL) \
	$$CONTRACT_ADDRESS \
	lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
	--constructor-args $$(cast abi-encode "constructor(address,bytes)" $$(jq -r '.REGISTRY_IMPLEMENTATION' $$DEPLOYMENTS_FILE) "0x") \
	--etherscan-api-key $(BASESCAN_API_KEY) \
	--watch

# Run tests
test:
	@echo "Running tests..."
	forge test -vvv
