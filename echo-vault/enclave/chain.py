from web3 import Web3
import time
import logging
import os
from typing import Optional

class Chain:
    """Helper for interacting with the blockchain via Helios RPC."""
    
    DEFAULT_MOCK_RPC = "http://odyn.sparsity.cloud:8545"
    DEFAULT_HELIOS_RPC = "http://127.0.0.1:8545"

    def __init__(self, rpc_url: Optional[str] = None):
        if rpc_url:
            self.endpoint = rpc_url
        else:
            is_enclave = os.getenv("IN_ENCLAVE", "False").lower() == "true"
            self.endpoint = self.DEFAULT_HELIOS_RPC if is_enclave else self.DEFAULT_MOCK_RPC
            
        self.w3 = Web3(Web3.HTTPProvider(self.endpoint))
        self.logger = logging.getLogger(__name__)

    def wait_for_helios(self, timeout: int = 300):
        """Wait for RPC to be ready."""
        is_enclave = os.getenv("IN_ENCLAVE", "False").lower() == "true"
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                if self.w3.is_connected():
                    if not is_enclave:
                        self.logger.info("Mock RPC connected")
                        return True
                        
                    # Helios-specific sync check
                    syncing = self.w3.eth.syncing
                    if not syncing:
                        block = self.w3.eth.block_number
                        if block > 0:
                            self.logger.info(f"Helios ready at block {block}")
                            return True
                self.logger.info(f"Waiting for {'Helios' if is_enclave else 'Mock'} RPC...")
            except Exception:
                pass
            time.sleep(5)
        raise TimeoutError(f"{'Helios' if is_enclave else 'Mock'} RPC failed to connect in time")

    def get_balance(self, address: str) -> int:
        return self.w3.eth.get_balance(Web3.to_checksum_address(address))

    def get_nonce(self, address: str) -> int:
        return self.w3.eth.get_transaction_count(Web3.to_checksum_address(address))

    def get_latest_block(self) -> int:
        return self.w3.eth.block_number

    def get_block_transactions(self, block_number: int):
        block = self.w3.eth.get_block(block_number, full_transactions=True)
        return block.get('transactions', [])

    def estimate_fees(self):
        """Estimate EIP-1559 fees."""
        # Base Sepolia often has very low priority fees
        priority_fee = self.w3.eth.max_priority_fee
        base_fee = self.w3.eth.get_block('latest')['baseFeePerGas']
        
        # Max fee = (2 * base fee) + priority fee
        max_fee = (base_fee * 2) + priority_fee
        return priority_fee, max_fee

    def send_raw_transaction(self, signed_hex: str) -> str:
        tx_hash = self.w3.eth.send_raw_transaction(signed_hex)
        res = tx_hash.hex()
        return res if res.startswith("0x") else f"0x{res}"
