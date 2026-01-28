import json
import logging
import threading
import time
from typing import List, Dict, Any, Optional
from odyn import Odyn
from chain import Chain

logger = logging.getLogger(__name__)

class HistoryLimitExceeded(Exception):
    """Raised when the requested block is beyond the light client's historical buffer."""
    pass

class EchoTask:
    """Background task to poll for transfers and echo them back."""
    
    def __init__(self, odyn: Odyn, chain: Chain):
        self.odyn = odyn
        self.chain = chain
        self.address = odyn.eth_address()
        self.history: List[Dict[str, Any]] = []
        self.is_running = False
        self.last_block = 0
        self.persisted_block = 0
        self.processed_count = 0
        self.pending_hashes: List[str] = [] # Hashes currently in 'received' or 'failed' state

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        
        # 1. Load last block from S3
        saved_block = self.odyn.s3_get("last_block")
        if saved_block:
            self.last_block = int(saved_block.decode())
            self.persisted_block = self.last_block
            logger.info(f"Resuming from block {self.last_block}")
        else:
            self.last_block = self.chain.get_latest_block()
            logger.info(f"Starting from current block {self.last_block}")

        # 2. Recover history and pending hashes from S3
        self._recover_state_from_s3()

        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()

    def _recover_state_from_s3(self):
        """Rebuild history and pending list by scanning S3 for transaction records."""
        try:
            logger.info("Recovering state from S3...")
            res = self.odyn.s3_list(prefix="echoes/")
            keys = res.get("keys", [])
            
            temp_history = []
            new_pending = []
            success_count = 0
            
            for key in keys:
                data = self.odyn.s3_get(key)
                if data:
                    try:
                        tx_data = json.loads(data.decode())
                        temp_history.append(tx_data)
                        if tx_data.get("status") in ["received", "failed"]:
                            new_pending.append(tx_data["incoming_hash"])
                        if tx_data.get("status") == "success":
                            success_count += 1
                    except Exception as e:
                        logger.error(f"Failed to parse transaction data for {key}: {e}")

            # Sort history by timestamp descending
            temp_history.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
            self.history = temp_history[:100]
            self.pending_hashes = new_pending
            self.processed_count = success_count
            logger.info(f"Recovered {len(self.history)} history items and {len(self.pending_hashes)} pending transactions")
            
        except Exception as e:
            logger.error(f"Failed to recover state: {e}")

    def _save_transaction(self, tx_data: Dict[str, Any]):
        """Persist individual transaction status to S3."""
        try:
            tx_hash = tx_data["incoming_hash"]
            data = json.dumps(tx_data).encode()
            self.odyn.s3_put(f"echoes/{tx_hash}.json", data)
        except Exception as e:
            logger.error(f"Failed to save transaction {tx_data.get('incoming_hash')} to S3: {e}")

    def _clear_pending(self) -> bool:
        """Attempt to clear all pending echoes. Returns True if all cleared."""
        if not self.pending_hashes:
            return True
            
        logger.info(f"Attempting to clear {len(self.pending_hashes)} pending echoes")
        
        # Get base nonce once for batch processing
        try:
            current_nonce = self.chain.get_nonce(self.address)
        except Exception as e:
            logger.error(f"Failed to get nonce: {e}")
            return False

        # We process a copy so we can modify the original list
        for tx_hash in list(self.pending_hashes):
            # Find the transaction data in history or load from S3
            tx_data = next((h for h in self.history if h["incoming_hash"] == tx_hash), None)
            if not tx_data:
                data = self.odyn.s3_get(f"echoes/{tx_hash}.json")
                if data:
                    tx_data = json.loads(data.decode())
                else:
                    logger.warning(f"Pending hash {tx_hash} not found in S3, skipping")
                    self.pending_hashes.remove(tx_hash)
                    continue

            # Update status to 'processing' before attempting the echo
            tx_data.update({
                "status": "processing",
                "echo_value": "Preparing echo transaction...",
                "timestamp": int(time.time())
            })
            self._save_transaction(tx_data)

            success = self._echo_transfer(tx_data, current_nonce)
            if success:
                # If was successful (including non-retryable skips), remove from pending
                if tx_hash in self.pending_hashes:
                    self.pending_hashes.remove(tx_hash)
                # Increment nonce if we actually signed and sent a tx
                if tx_data.get("status") == "success":
                    current_nonce += 1
            else:
                # Failed (retryable)
                return False
        return True

    def _run(self):
        while self.is_running:
            try:
                # 1. Always try to clear pending echoes first
                if not self._clear_pending():
                    logger.warning("Some echoes failed, will retry in 10s")
                    time.sleep(10)
                    continue

                # 2. Advance blocks
                current_block = self.chain.get_latest_block()
                
                if current_block > self.last_block:
                    for b in range(self.last_block + 1, current_block + 1):
                        # 3. Identify and stage transfers for block b
                        try:
                            if self._process_block(b):
                                # Advance block only if all transfers in it were handled
                                self.last_block = b
                                if self.odyn.s3_put("last_block", str(b).encode()):
                                    self.persisted_block = b
                            else:
                                # Non-critical failure in process_block (e.g. transient RPC error)
                                logger.warning(f"Failed to fully process block {b}, stopping advancement")
                                break
                        except HistoryLimitExceeded:
                            logger.warning(f"Block {b} is too old for light client buffer. Jumping to latest block {current_block}.")
                            self.last_block = current_block
                            self.odyn.s3_put("last_block", str(current_block).encode())
                            self.persisted_block = current_block
                            break # Restart loop from new last_block
                
                time.sleep(2) # Poll every 2 seconds
            except Exception as e:
                logger.error(f"Error in background task: {e}")
                time.sleep(2)

    def _process_block(self, block_number: int) -> bool:
        """Identifies transfers in a block and adds them to the pending queue."""
        logger.info(f"Scanning block {block_number}")
        try:
            txs = self.chain.get_block_transactions(block_number)
        except Exception as e:
            err_msg = str(e)
            if "outside eip-2935 ring buffer range" in err_msg.lower():
                raise HistoryLimitExceeded(err_msg)
                
            logger.error(f"Failed to fetch block {block_number}: {e}")
            return False
            
        for tx in txs:
            # Check if transaction is to the enclave address and has value
            if tx.get('to') and tx['to'].lower() == self.address.lower() and tx['value'] > 0:
                # Skip if the sender is the enclave itself to avoid loops
                if tx.get('from') and tx['from'].lower() == self.address.lower():
                    logger.info("Skipping self-transfer")
                    continue
                
                # Prepare pending item
                raw_hash = tx['hash']
                tx_hash = raw_hash.hex() if hasattr(raw_hash, 'hex') else str(raw_hash)
                if not tx_hash.startswith("0x"):
                    tx_hash = f"0x{tx_hash}"
                
                # Check if already handled (exists in history or S3)
                if any(h['incoming_hash'] == tx_hash for h in self.history):
                    continue
                if self.odyn.s3_get(f"echoes/{tx_hash}.json"):
                    continue
                    
                tx_data = {
                    "incoming_hash": tx_hash,
                    "from": str(tx['from']),
                    "value": str(tx['value']), # Use string for JSON safety of large ints
                    "block_number": block_number,
                    "timestamp": int(time.time()),
                    "status": "received",
                    "echo_hash": None,
                    "echo_value": "Transfer detected",
                    "gas_fee": None
                }
                
                # Save to S3 first
                self._save_transaction(tx_data)
                self.pending_hashes.append(tx_hash)
                self.history.insert(0, tx_data)
                if len(self.history) > 100:
                    self.history.pop()

        # Try to clear immediately
        return self._clear_pending()

    def _echo_transfer(self, incoming_tx: Dict[str, Any], nonce: int) -> bool:
        """Performs the actual echo. Returns True if handled (success or non-retryable skip)."""
        try:
            from_address = str(incoming_tx['from'])
            received_value = int(incoming_tx['value'])
            tx_hash = incoming_tx['incoming_hash']
            
            logger.info(f"Echoing transfer: {received_value} wei from {from_address} (hash: {tx_hash})")

            # Get current balance to ensure we have enough funds
            current_balance = self.chain.get_balance(self.address)
            
            # Estimate fees
            priority_fee, max_fee = self.chain.estimate_fees()
            gas_limit = 21000 # Standard transfer
            
            # Use a 10% safety buffer for gas cost to prevent "insufficient funds" during fluctuations
            estimated_gas_cost = gas_limit * max_fee
            safe_gas_cost = int(estimated_gas_cost * 1.1)
            
            # Calculate available funds for echo (min of received or current balance)
            # If current_balance is less than gas but received_value is sufficient, 
            # we should wait (retry) instead of skipping.
            
            if received_value <= safe_gas_cost:
                logger.warning(f"Received value {received_value} <= safe gas cost {safe_gas_cost}, skipping permanently")
                incoming_tx.update({
                    "status": "skipped",
                    "echo_value": "Value less than gas cost",
                    "gas_fee": str(safe_gas_cost),
                    "timestamp": int(time.time())
                })
                self._save_transaction(incoming_tx)
                return True

            if current_balance < safe_gas_cost:
                logger.warning(f"RPC balance {current_balance} < gas cost {safe_gas_cost} but received {received_value}, waiting for balance sync...")
                # Return False to trigger a retry in the main loop
                return False

            available_funds = min(received_value, current_balance)
            echo_value = available_funds - safe_gas_cost
            
            tx_params = {
                "kind": "structured",
                "chain_id": hex(self.chain.w3.eth.chain_id),
                "nonce": hex(nonce),
                "max_priority_fee_per_gas": hex(priority_fee),
                "max_fee_per_gas": hex(max_fee),
                "gas_limit": hex(gas_limit),
                "to": from_address,
                "value": hex(echo_value),
                "data": "0x"
            }
            
            logger.info(f"Signing (nonce={nonce}): to={from_address}, value={echo_value}")
            signed_tx = self.odyn.sign_tx(tx_params)
            
            # Broadcast
            echo_hash = self.chain.send_raw_transaction(signed_tx["raw_transaction"])
            logger.info(f"Echoed! Hash: {echo_hash}")

            incoming_tx.update({
                "status": "success",
                "echo_hash": echo_hash,
                "echo_value": str(echo_value),
                "gas_fee": str(safe_gas_cost),
                "timestamp": int(time.time())
            })
            self._save_transaction(incoming_tx)
            self.processed_count += 1
            return True
            
        except Exception as e:
            error_msg = str(e)
            if "already known" in error_msg.lower():
                logger.info("Transaction already known, treating as success")
                incoming_tx.update({
                    "status": "success",
                    "echo_value": "Already submitted",
                    "timestamp": int(time.time())
                })
                self._save_transaction(incoming_tx)
                return True
                
            logger.error(f"Failed to echo transfer {tx_hash}: {error_msg}")
            incoming_tx.update({
                "status": "failed",
                "echo_value": error_msg,
                "timestamp": int(time.time())
            })
            self._save_transaction(incoming_tx)
            return False
