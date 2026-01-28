#!/usr/bin/env python3
"""
BTC Price Oracle - Fetches BTC price from CoinGecko and updates on-chain.
"""

import json
import os
import time
import threading
import logging
import requests
from flask import Flask, jsonify
from eth_utils import to_checksum_address
from rlp import encode as rlp_encode
from web3 import Web3

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Enclaver odyn API endpoint (internal)
ODYN_API = "http://localhost:18000" if os.getenv("IN_DOCKER", "False").lower() == "true" else "http://odyn.sparsity.cloud:18000"

# Global config
config = {}
w3 = None

# Contract ABI (minimal for setPrice and getPrice)
CONTRACT_ABI = [
    {
        "inputs": [{"name": "_price", "type": "uint256"}],
        "name": "setPrice",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getPrice",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "btcPrice",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "lastUpdated",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }
]

def load_config():
    """Load configuration from config.json."""
    global config, w3
    with open("./config.json", "r") as f:
        config = json.load(f)
    w3 = Web3(Web3.HTTPProvider(config["rpc_url"]))

def get_enclave_address():
    """Get the Ethereum address from the enclave."""
    response = requests.get(f"{ODYN_API}/v1/eth/address")
    response.raise_for_status()
    return response.json()["address"]

def fetch_btc_price():
    """Fetch BTC price from CoinGecko API."""
    response = requests.get(config["coingecko_url"])
    response.raise_for_status()
    data = response.json()
    # Return price in cents (multiply by 100 for 2 decimal precision)
    price_usd = data["bitcoin"]["usd"]
    return int(price_usd * 100)

def get_contract_price():
    """Get current price from the smart contract."""
    if not config.get("contract_address"):
        return None
    contract = w3.eth.contract(
        address=to_checksum_address(config["contract_address"]),
        abi=CONTRACT_ABI
    )
    return contract.functions.getPrice().call()

def sign_and_send_tx(tx_data, to_address, nonce, gas_limit=100000):
    """Sign a transaction using enclave and send it."""
    # Get current gas prices
    base_fee = w3.eth.get_block('latest')['baseFeePerGas']
    max_priority_fee = w3.to_wei(1, 'gwei')
    max_fee = base_fee * 2 + max_priority_fee

    # Build unsigned EIP-1559 transaction
    chain_id = config["chain_id"]
    to = bytes.fromhex(to_address[2:]) if to_address.startswith("0x") else bytes.fromhex(to_address)
    value = 0
    data = bytes.fromhex(tx_data[2:]) if tx_data.startswith("0x") else bytes.fromhex(tx_data)
    access_list = []

    unsigned_tx_fields = [
        chain_id,
        nonce,
        max_priority_fee,
        max_fee,
        gas_limit,
        to,
        value,
        data,
        access_list
    ]

    rlp_encoded = rlp_encode(unsigned_tx_fields)
    raw_payload = "0x02" + rlp_encoded.hex()

    # Sign using enclave
    tx_payload = {
        "include_attestation": False,
        "payload": {
            "kind": "raw_rlp",
            "raw_payload": raw_payload
        }
    }

    response = requests.post(
        f"{ODYN_API}/v1/eth/sign-tx",
        json=tx_payload,
        headers={"Content-Type": "application/json"}
    )
    response.raise_for_status()
    result = response.json()

    # Send signed transaction
    tx_hash = w3.eth.send_raw_transaction(result["raw_transaction"])
    return tx_hash.hex()

def update_price_on_chain():
    """Fetch BTC price and update the smart contract."""
    if not config.get("contract_address"):
        return {"error": "Contract address not configured"}

    # Fetch current BTC price
    price = fetch_btc_price()

    # Get enclave address and nonce
    enclave_address = to_checksum_address(get_enclave_address())
    nonce = w3.eth.get_transaction_count(enclave_address)

    # Build setPrice call data
    contract = w3.eth.contract(
        address=to_checksum_address(config["contract_address"]),
        abi=CONTRACT_ABI
    )
    tx_data = contract.functions.setPrice(price)._encode_transaction_data()

    # Sign and send
    tx_hash = sign_and_send_tx(
        tx_data,
        config["contract_address"],
        nonce
    )

    return {
        "success": True,
        "price_cents": price,
        "price_usd": price / 100,
        "tx_hash": tx_hash
    }

def scheduled_update():
    """Background thread for scheduled price updates."""
    while True:
        time.sleep(config.get("update_interval_seconds", 300))
        try:
            if config.get("contract_address"):
                result = update_price_on_chain()
                logger.info(f"Scheduled update: {result}")
        except Exception as e:
            logger.error(f"Scheduled update error: {e}")

@app.route('/')
def index():
    """Health check endpoint."""
    try:
        address = get_enclave_address()
        return jsonify({
            "status": "ok",
            "message": "BTC Price Oracle",
            "enclave_address": address,
            "balance": f"{Web3.from_wei(w3.eth.get_balance(Web3.to_checksum_address(address)), 'ether')} ETH",
            "contract_address": config.get("contract_address", "not configured"),
            "endpoints": {
                "/price": "Get current BTC price from CoinGecko",
                "/update": "Manually trigger price update to contract",
                "/contract-price": "Read current price from contract"
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/price')
def price():
    """Fetch current BTC price from CoinGecko."""
    try:
        price_cents = fetch_btc_price()
        return jsonify({
            "source": "coingecko",
            "price_cents": price_cents,
            "price_usd": price_cents / 100
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/update')
def update():
    """Manually trigger price update to contract."""
    try:
        result = update_price_on_chain()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/contract-price')
def contract_price():
    """Read current price from the smart contract."""
    try:
        price = get_contract_price()
        if price is None:
            return jsonify({"error": "Contract address not configured"}), 400
        return jsonify({
            "source": "contract",
            "price_cents": price,
            "price_usd": price / 100
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    logger.info("Loading configuration...")
    load_config()

    logger.info("Starting BTC Price Oracle...")
    logger.info("Endpoints:")
    logger.info("  GET  /               - Health check")
    logger.info("  GET  /price          - Get BTC price from CoinGecko")
    logger.info("  GET  /update         - Trigger price update")
    logger.info("  GET  /contract-price - Read price from contract")

    # Start scheduled update thread
    if config.get("contract_address"):
        update_thread = threading.Thread(target=scheduled_update, daemon=True)
        update_thread.start()
        logger.info(f"Scheduled updates every {config.get('update_interval_seconds', 300)} seconds")

    app.run(host='0.0.0.0', port=8000)
