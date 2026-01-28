# BTC Price Oracle Makefile

# Load environment variables from .env
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# EC2 Configuration (from .env)
SSH_CMD = ssh -i $(EC2_KEY) $(EC2_HOST)
SCP_CMD = scp -i $(EC2_KEY)

# Image names
APP_IMAGE = btc-oracle:latest
ENCLAVE_IMAGE = btc-oracle-enclave:latest

# Base Sepolia RPC
RPC_URL = https://sepolia.base.org

.PHONY: all build deploy-enclave get-address fund-info deploy-contract set-contract-address help

help:
	@echo "BTC Price Oracle - Makefile Commands"
	@echo ""
	@echo "  make deploy-contract       - Deploy contract (step 1)"
	@echo "  make deploy-contract-local - Deploy contract to local anvil node"
	@echo "  make set-contract-address  - Update config.json with contract address"
	@echo "  make deploy-enclave        - Deploy enclave to EC2"
	@echo "  make get-address           - Get enclave wallet address"
	@echo "  make fund-enclave          - Fund enclave wallet with 0.01 ETH"
	@echo "  make set-oracle            - Update contract's oracle to enclave address"
	@echo "  make register-tee-wallet   - Register TEE wallet and fund it"
	@echo ""
	@echo "Setup: cp .env.example .env && fill in PRIVATE_KEY and ETHERSCAN_API_KEY"
	@echo ""
	@echo "Workflow:"
	@echo "  1. make deploy-contract"
	@echo "  2. make set-contract-address CONTRACT=<deployed_address>"
	@echo "  3. make deploy-enclave"
	@echo "  4. make fund-enclave"
	@echo "  5. make set-oracle ORACLE=<enclave_address>"

# Build Docker image locally
build:
	@echo "Building Docker image..."
	docker build -t $(APP_IMAGE) .
	@echo "Docker image built: $(APP_IMAGE)"

# Install Foundry dependencies
install-foundry-deps:
	@echo "Installing Foundry dependencies..."
	cd contracts && forge install foundry-rs/forge-std

# Build smart contract
build-contract:
	@echo "Building smart contract..."
	cd contracts && forge build

# Deploy enclave to EC2
deploy-enclave:
	@echo "Transferring source files to EC2..."
	$(SSH_CMD) "mkdir -p ~/btc-oracle"
	$(SCP_CMD) app.py requirements.txt config.json Dockerfile enclaver.yaml $(EC2_HOST):~/btc-oracle/
	@echo "Building Docker image on EC2..."
	$(SSH_CMD) "cd ~/btc-oracle && docker build -t $(APP_IMAGE) ."
	@echo "Building enclave image on EC2..."
	$(SSH_CMD) "cd ~/btc-oracle && ~/enclaver build -f enclaver.yaml"
	@echo "Starting enclave..."
	$(SSH_CMD) "docker stop btc-oracle 2>/dev/null || true && \
		docker rm btc-oracle 2>/dev/null || true && \
		docker run -d --name btc-oracle -p 8000:8000 --privileged --device=/dev/nitro_enclaves:/dev/nitro_enclaves $(ENCLAVE_IMAGE)"
	@EC2_IP=$$(echo $(EC2_HOST) | cut -d'@' -f2); \
	echo "Enclave deployed! Access at http://$$EC2_IP:8000"

# Get enclave wallet address
get-address:
	@echo "Fetching enclave wallet address..."
	@EC2_IP=$$(echo $(EC2_HOST) | cut -d'@' -f2); \
	curl -s http://$$EC2_IP:8000/ | jq -r '.enclave_address'

# Fund enclave wallet with ETH from deployer
fund-enclave:
	@if [ -z "$(PRIVATE_KEY)" ]; then echo "Error: PRIVATE_KEY not set in .env"; exit 1; fi
	@EC2_IP=$$(echo $(EC2_HOST) | cut -d'@' -f2); \
	ENCLAVE_ADDR=$$(curl -s http://$$EC2_IP:8000/ | jq -r '.enclave_address'); \
	if [ "$$ENCLAVE_ADDR" = "null" ] || [ -z "$$ENCLAVE_ADDR" ]; then echo "Error: Could not get enclave address"; exit 1; fi; \
	echo "Funding enclave wallet: $$ENCLAVE_ADDR with 0.001 ETH..."; \
	cast send --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) $$ENCLAVE_ADDR --value 0.001ether

# Deploy smart contract (step 1)
deploy-contract: build-contract
	@if [ -z "$(PRIVATE_KEY)" ]; then echo "Error: PRIVATE_KEY not set in .env"; exit 1; fi
	@if [ -z "$(ETHERSCAN_API_KEY)" ]; then echo "Error: ETHERSCAN_API_KEY not set in .env"; exit 1; fi
	@echo "Deploying BTCPriceOracle contract..."
	cd contracts && forge script script/Deploy.s.sol:DeployScript \
		--rpc-url $(RPC_URL) \
		--private-key $(PRIVATE_KEY) \
		--broadcast \
		--verify \
		--etherscan-api-key $(ETHERSCAN_API_KEY) \
		--verifier-url https://api.etherscan.io/v2/api?chainid=84532 \
		-vvv
	@echo "Updating config.json..."
	@CONTRACT_ADDRESS=$$(python3 -c 'import json; print([t["contractAddress"] for t in json.load(open("contracts/broadcast/Deploy.s.sol/84532/run-latest.json"))["transactions"] if t["contractName"] == "BTCPriceOracle"][0])') && \
	echo "Found contract address: $$CONTRACT_ADDRESS" && \
	python3 -c 'import json; data = json.load(open("config.json")); data["contract_address"] = "'$$CONTRACT_ADDRESS'"; data["rpc_url"] = "$(RPC_URL)"; data["chain_id"] = 84532; json.dump(data, open("config.json", "w"), indent=2); print("config.json updated!")'


# Deploy to local anvil node
deploy-contract-local: build-contract
	@echo "Deploying to local anvil node..."
	cd contracts && forge script script/Deploy.s.sol:DeployScript \
		--rpc-url http://127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --broadcast
	@echo "Updating config.json..."
	@CONTRACT_ADDRESS=$$(python3 -c 'import json; print([t["contractAddress"] for t in json.load(open("contracts/broadcast/Deploy.s.sol/31337/run-latest.json"))["transactions"] if t["contractName"] == "BTCPriceOracle"][0])') && \
	echo "Found contract address: $$CONTRACT_ADDRESS" && \
	python3 -c 'import json; data = json.load(open("backend/config.json")); data["contract_address"] = "'$$CONTRACT_ADDRESS'"; data["rpc_url"] = "http://127.0.0.1:8545"; data["chain_id"] = 31337; json.dump(data, open("backend/config.json", "w"), indent=2); print("config.json updated!")' && \
	echo "Updating frontend/vite.config.ts..." && \
	python3 -c "import sys, re; \
contract_addr = '$$CONTRACT_ADDRESS'; \
config = open('frontend/vite.config.ts').read(); \
config = re.sub(r\"process\.env\.VITE_CONTRACT_ADDRESS \|\| '[^']*'\", f\"process.env.VITE_CONTRACT_ADDRESS || '{contract_addr}'\", config); \
config = re.sub(r\"process\.env\.VITE_CHAIN_ID \|\| '[^']*'\", \"process.env.VITE_CHAIN_ID || '31337'\", config); \
config = re.sub(r\"process\.env\.VITE_CHAIN_NAME \|\| '[^']*'\", \"process.env.VITE_CHAIN_NAME || 'Anvil Local'\", config); \
config = re.sub(r\"process\.env\.VITE_RPC_URL \|\| '[^']*'\", \"process.env.VITE_RPC_URL || 'http://127.0.0.1:8545'\", config); \
config = re.sub(r\"process\.env\.VITE_EXPLORER_URL \|\| '[^']*'\", \"process.env.VITE_EXPLORER_URL || 'http://localhost:8545'\", config); \
open('frontend/vite.config.ts', 'w').write(config); \
print('frontend/vite.config.ts updated!')"

# Set oracle address on contract (after enclave is deployed)
# Usage: make set-oracle ORACLE=0x...
set-oracle:
ifndef ORACLE
	$(error ORACLE is required. Usage: make set-oracle ORACLE=0x...)
endif
	@if [ -z "$(PRIVATE_KEY)" ]; then echo "Error: PRIVATE_KEY not set in .env"; exit 1; fi
	@echo "Setting oracle address to: $(ORACLE)"
	@CONTRACT=$$(jq -r '.contract_address' config.json) && \
	cast send --rpc-url $(RPC_URL) --private-key $(PRIVATE_KEY) \
		$$CONTRACT "setOracle(address)" $(ORACLE)
	@echo "Oracle address updated!"

# Register TEE wallet and fund it
# Usage: make register-tee-wallet TEE_WALLET=0x...
register-tee-wallet:
ifndef TEE_WALLET
	$(error TEE_WALLET is required. Usage: make register-tee-wallet TEE_WALLET=0x...)
endif
	@echo "Registering TEE wallet: $(TEE_WALLET)"
	@CONTRACT=$$(python3 -c 'import json; print(json.load(open("backend/config.json"))["contract_address"])') && \
	REGISTRY=$$(python3 -c 'import json; print(json.load(open("backend/config.json"))["contract_address"])') && \
	RPC=$$(python3 -c 'import json; print(json.load(open("backend/config.json"))["rpc_url"])') && \
	echo "Calling registerTEEWallet on contract $$CONTRACT..." && \
	cast send --rpc-url $$RPC --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
		$$CONTRACT "registerTEEWallet(address)" $(TEE_WALLET)
	@echo "Funding TEE wallet with 0.01 ETH..."
	@RPC=$$(python3 -c 'import json; print(json.load(open("backend/config.json"))["rpc_url"])') && \
	cast send --rpc-url $$RPC --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 $(TEE_WALLET) --value 0.01ether
	@echo "TEE wallet registered and funded!"

# Verify contract on Basescan
verify-contract:
	@if [ -z "$(ETHERSCAN_API_KEY)" ]; then echo "Error: ETHERSCAN_API_KEY not set in .env"; exit 1; fi
	@CONTRACT=$$(jq -r '.contract_address' config.json); \
	if [ "$$CONTRACT" = "null" ] || [ -z "$$CONTRACT" ]; then echo "Error: contract_address not found in config.json"; exit 1; fi; \
	DEPLOYER=$$(cast call --rpc-url $(RPC_URL) $$CONTRACT "owner()(address)"); \
	echo "Verifying BTCPriceOracle at $$CONTRACT..."; \
	cd contracts && forge verify-contract \
		--rpc-url $(RPC_URL) \
		$$CONTRACT \
		src/BTCPriceOracle.sol:BTCPriceOracle \
		--etherscan-api-key $(ETHERSCAN_API_KEY) \
		--verifier-url https://api.etherscan.io/v2/api \
		--chain 84532 \
		--constructor-args $$(cast abi-encode "constructor(address)" $$DEPLOYER) \
		--watch

# Update config.json with contract address
# Usage: make set-contract-address CONTRACT=0x...
set-contract-address:
ifndef CONTRACT
	$(error CONTRACT is required. Usage: make set-contract-address CONTRACT=0x...)
endif
	@echo "Updating config.json with contract address: $(CONTRACT)"
	@jq '.contract_address = "$(CONTRACT)"' config.json > config.json.tmp && mv config.json.tmp config.json
	@echo "Config updated. Rebuild and redeploy enclave:"
	@echo "  make deploy-enclave"

# Check enclave status
status:
	@curl -s http://3.38.153.240:8000/ | jq .

# Trigger manual price update
update-price:
	@curl -s http://3.38.153.240:8000/update | jq .

# Get current BTC price from CoinGecko
get-price:
	@curl -s http://3.38.153.240:8000/price | jq .

# Get price from contract
contract-price:
	@curl -s http://3.38.153.240:8000/contract-price | jq .

# View enclave logs on EC2
logs:
	$(SSH_CMD) "docker logs -f btc-oracle"

# Stop enclave on EC2
stop:
	$(SSH_CMD) "docker stop btc-oracle"

# Clean up
clean:
	rm -f /tmp/enclave.tar.gz
	cd contracts && forge clean
