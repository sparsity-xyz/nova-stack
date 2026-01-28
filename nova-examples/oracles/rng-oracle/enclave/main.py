import os
import asyncio
import logging
import random
import requests
from typing import List, Optional

import uvicorn
from web3 import Web3
from web3.contract import Contract
from fastapi import FastAPI, HTTPException
from fastapi.requests import Request
from fastapi.staticfiles import StaticFiles

from config import Config
from odyn import Odyn


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


class RandomNumberGenerator:
    def __init__(self):
        # Web3 connection
        self.w3 = Web3(Web3.HTTPProvider(Config.RPC_URL))

        if not self.w3.is_connected():
            raise ConnectionError(f"Failed to connect to {Config.RPC_URL}")

        self.chain_id = self.w3.eth.chain_id
        logging.info(f"✅ Connected to chain ID: {self.chain_id}")

        # Contract
        self.contract_address = Web3.to_checksum_address(Config.CONTRACT_ADDRESS)
        self.contract: Contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=Config.CONTRACT_ABI,
        )

        self.enclaver = Odyn()

        # Operator account
        self.operator_address = Web3.to_checksum_address(self.enclaver.eth_address())
        logging.info(f"🔑 Operator: {self.operator_address}")

        # Check balance
        balance = self.w3.eth.get_balance(self.operator_address)
        logging.info(f"💰 Operator balance: {Web3.from_wei(balance, 'ether')} ETH")

        if balance == 0:
            logging.warning("⚠️  Operator has zero balance!")

        # Verify operator permission
        self.is_operator = self.contract.functions.isOperator(self.operator_address).call()
        if self.is_operator:
            logging.info("✅ Operator is authorized")
        else:
            logging.info("❌ Operator is not authorized")

        # Processed requests (prevent duplicates)
        self.processed_requests = set()

        self.app = FastAPI(
            title="RNG Oracle Service",
            description="Off-chain service for generating and fulfilling random numbers",
            version="1.0.0"
        )

        # Mount consumer frontend (built from consumer project)
        self.consumer_mounted = False
        consumer_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "consumer-dist"))
        if os.path.exists(consumer_path):
            self.app.mount("/consumer", StaticFiles(directory=consumer_path, html=True), name="consumer")
            logging.info(f"✅ Mounted consumer at /consumer from {consumer_path}")
            self.consumer_mounted = True
        else:
            logging.warning(f"⚠️ Consumer path not found: {consumer_path}")

        self.init_router()

    def init_router(self):
        self.app.add_api_route("/", self.status, methods=["GET"])
        self.app.add_api_route("/request/{request_id}", self.request_info, methods=["GET"])

        self.app.add_event_handler("startup", self.run)

    async def status(self, req: Request):
        return {
            "service": "RNG Oracle",
            "version": "1.0.0",
            "status": "running",
            "is_operator": self.is_operator,
            "contract_address": self.contract_address,
            "operator": self.operator_address,
            "operator_balance": round(self.w3.eth.get_balance(self.operator_address) / 1e18, 6),
            "processed_requests": len(self.processed_requests),
            "explorer": f"https://sepolia.basescan.org/address/{self.contract_address}",
            "consumer": f"{req.base_url}consumer" if self.consumer_mounted else None,
        }

    async def request_info(self, request_id):
        return self.get_request_info(int(request_id))

    def get_request_info(self, request_id: int) -> dict:
        """Get request information from contract"""
        try:
            request = self.contract.functions.getRequest(request_id).call()

            status_names = ["Pending", "Fulfilled", "Cancelled"]

            return {
                "request_id": request_id,
                "status": status_names[request[0]],
                "random_numbers": request[1],
                "requester": request[2],
                "timestamp": request[3],
                "fulfilled_at": request[4],
                "callback_contract": request[5] if request[5] != '0x0000000000000000000000000000000000000000' else None,
                "callback_executed": request[6],
                "min_val": request[7],
                "max_val": request[8],
                "count": request[9]
            }
        except Exception as e:
            raise HTTPException(status_code=404, detail=f"Request not found: {e}")

    def estimate_priority_from_fee_history(self, blocks: int = 5, percentile: float = 50):
        try:
            hist = self.w3.eth.fee_history(blocks, 'pending', [percentile / 100])
            reward = hist['reward'][-1][0]  # 单位 wei
            return int(reward)
        except Exception:
            return self.w3.to_wei(2, 'gwei')

    @staticmethod
    def tx_to_payload(tx: dict) -> dict:
        """Convert web3.py transaction dict to enclaver payload format."""
        return {
            "kind": "structured",
            "chain_id": hex(tx["chainId"]),
            "nonce": hex(tx["nonce"]),
            "max_priority_fee_per_gas": hex(tx["maxPriorityFeePerGas"]),
            "max_fee_per_gas": hex(tx["maxFeePerGas"]),
            "gas_limit": hex(tx["gas"]),
            "to": Web3.to_checksum_address(tx["to"]),
            "value": hex(tx.get("value", 0)),
            "data": tx["data"],
        }

    def sign_tx(self, transaction_dict: dict) -> str:
        """
        Sign transaction using enclaver's /v1/eth/sign-tx endpoint.
        
        Args:
            transaction_dict: Transaction dictionary with web3.py format
            
        Returns:
            Signed raw transaction hex string
        """
        res = requests.post(
            f"{self.enclaver.endpoint}/v1/eth/sign-tx",
            json={
                "payload": self.tx_to_payload(transaction_dict),
                "include_attestation": False
            },
            timeout=10
        )
        res.raise_for_status()
        return res.json()["raw_transaction"]

    def generate_random_numbers(self, min_val: int, max_val: int, count: int) -> List[int]:
        """
        Generate cryptographically secure random numbers using enclave's random source.

        Args:
            min_val: Minimum value (inclusive)
            max_val: Maximum value (exclusive)
            count: Number of random numbers

        Returns:
            List of random numbers
        """
        # Get random seed from enclave
        seed = self.enclaver.get_random_bytes(32)
        random.seed(seed)
        
        random_numbers = []
        range_size = max_val - min_val

        for _ in range(count):
            # [min, max)
            random_num = min_val + random.randint(0, range_size - 1)
            random_numbers.append(random_num)

        return random_numbers

    async def fulfill_random_number(
            self,
            request_id: int,
            random_numbers: List[int]
    ) -> Optional[str]:
        """
        Fulfill random number to contract

        Args:
            request_id: Request ID
            random_numbers: List of random numbers

        Returns:
            Transaction hash
        """
        try:
            # Get nonce
            nonce = self.w3.eth.get_transaction_count(self.operator_address)

            # Build transaction function
            function = self.contract.functions.fulfillRandomNumber(
                request_id,
                random_numbers
            )

            # Estimate gas
            try:
                gas_estimate = function.estimate_gas({"from": self.operator_address})
                gas_limit = int(gas_estimate * 1.2)  # Add 20% buffer
            except Exception as e:
                logging.warning(f"⚠️  Gas estimation failed: {e}, using default")
                gas_limit = 300000

            # Get gas
            priority_from_hist = self.estimate_priority_from_fee_history(blocks=5, percentile=50)
            base_fee = self.w3.eth.get_block('pending')['baseFeePerGas']
            max_fee = base_fee * 2 + priority_from_hist

            # Build transaction
            transaction = function.build_transaction({
                "nonce": nonce,
                "gas": gas_limit,
                "maxPriorityFeePerGas": priority_from_hist,
                "maxFeePerGas": max_fee,
                "chainId": self.chain_id,
            })

            # Sign transaction using local helper (calls enclaver endpoint)
            signed_txn = self.sign_tx(transaction)

            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn)
            tx_hash_hex = tx_hash.hex()

            logging.info(f"📤 Fulfilling request {request_id}, tx: {tx_hash_hex}")

            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            if receipt.status == 1:
                logging.info(f"✅ Request {request_id} fulfilled successfully!")
                logging.info(f"   Gas used: {receipt.gasUsed}")
            else:
                logging.error(f"❌ Transaction failed for request {request_id}")

            return tx_hash_hex

        except Exception as e:
            logging.error(f"❌ Error fulfilling request {request_id}: {e}")
            raise

    async def handle_random_requested_event(self, event: dict):
        """
        Handle RandomNumberRequested event

        Args:
            event: Event data
        """
        args = event['args']
        request_id = args['requestId']
        requester = args['requester']
        min_val = args['min']
        max_val = args['max']
        count = args['count']
        callback_contract = args['callbackContract']
        timestamp = args['timestamp']

        logging.info("=" * 70)
        logging.info(f"📥 New Random Request Detected!")
        logging.info(f"   Request ID:       {request_id}")
        logging.info(f"   Requester:        {requester}")
        logging.info(f"   Range:            [{min_val}, {max_val})")
        logging.info(f"   Count:            {count}")
        logging.info(
            f"   Callback:         {callback_contract if callback_contract != '0x0000000000000000000000000000000000000000' else 'None'}")
        logging.info(f"   Timestamp:        {timestamp}")

        # Check if already processed
        if request_id in self.processed_requests:
            logging.warning(f"⚠️  Request {request_id} already processed, skipping")
            return

        # Check request status
        try:
            request = self.contract.functions.getRequest(request_id).call()
            status = request[0]  # RequestStatus

            if status != 0:  # 0 = Pending
                logging.warning(f"⚠️  Request {request_id} is not pending (status={status}), skipping")
                return
        except Exception as e:
            logging.error(f"❌ Error checking request status: {e}")
            return

        # Generate random numbers using enclave's secure random source
        random_numbers = self.generate_random_numbers(min_val, max_val, count)
        # Fulfill to contract
        try:
            tx_hash = await self.fulfill_random_number(request_id, random_numbers)

            # Mark as processed
            self.processed_requests.add(request_id)

            logging.info(f"   Random Numbers:   {random_numbers}")
            logging.info(f"   Tx Hash:          {tx_hash}")

        except Exception as e:
            logging.error(f"❌ Failed to fulfill request {request_id}: {e}")

        logging.info("=" * 70)

    async def listen_for_events(self, poll_interval: int = 2):
        """
        Listen for RandomNumberRequested events

        Args:
            poll_interval: Polling interval (seconds)
        """
        logging.info("👂 Starting to listen for RandomNumberRequested events...")
        logging.info(f"   Contract: {self.contract_address}")
        logging.info(f"   Poll Interval: {poll_interval}s")

        # Create event filter (from specified block)
        event_filter = self.contract.events.RandomNumberRequested.create_filter(
            from_block=Config.FROM_BLOCK
        )

        while True:
            if not self.is_operator:
                self.is_operator = self.contract.functions.isOperator(self.operator_address).call()
                logging.info("Wait for register operator...")
                await asyncio.sleep(poll_interval)
            else:
                break

        logging.info("✅ Event filter created, listening for events...\n")

        while True:
            try:
                # Get new events
                events = event_filter.get_new_entries()

                for event in events:
                    await self.handle_random_requested_event(event)

                # Wait before checking again
                await asyncio.sleep(poll_interval)

            except Exception as e:
                logging.error(f"❌ Error in event loop: {e}")
                await asyncio.sleep(poll_interval * 2)

    async def run(self):
        """Run service"""
        logging.info("\n" + "=" * 70)
        logging.info("🚀 RNG Off-Chain Service Starting...")
        logging.info("=" * 70)
        logging.info(f"Contract:  {self.contract_address}")
        logging.info(f"Operator:  {self.operator_address}")
        logging.info(f"Chain ID:  {self.chain_id}")
        logging.info("=" * 70 + "\n")

        # Start listening for events
        asyncio.create_task(self.listen_for_events())


def main():
    # Create RNG service
    try:
        rng_service = RandomNumberGenerator()

        # Run service
        uvicorn.run(
            rng_service.app,
            host="0.0.0.0",
            port=8000,
            log_level="info",
            workers=1
        )

    except KeyboardInterrupt:
        logging.info("\n👋 Shutting down gracefully...")
    except Exception as e:
        logging.error(f"❌ Fatal error: {e}")
        raise


if __name__ == "__main__":
    main()
