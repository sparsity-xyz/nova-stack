import requests
from web3 import Web3

from enclave import Enclave


def estimate_priority_from_fee_history(w3: Web3, blocks: int = 5, percentile: float = 50):
    try:
        hist = w3.eth.fee_history(blocks, 'pending', [percentile/100])
        reward = hist['reward'][-1][0]  # 单位 wei
        return int(reward)
    except Exception:
        return w3.to_wei(2, 'gwei')


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


def sign_tx(enclave: Enclave, transaction_dict: dict) -> str:
    """
    Sign transaction using enclaver's /v1/eth/sign-tx endpoint.
    
    Args:
        enclave: Enclave instance
        transaction_dict: Transaction dictionary with web3.py format
        
    Returns:
        Signed raw transaction hex string
    """
    res = requests.post(
        f"{enclave.endpoint}/v1/eth/sign-tx",
        json={
            "payload": tx_to_payload(transaction_dict),
            "include_attestation": False
        },
        timeout=10
    )
    res.raise_for_status()
    return res.json()["raw_transaction"]


def test_transaction():
    en = Enclave()
    address = Web3.to_checksum_address("0x358081769cdfc309e95de8942e388f095cd1bc7c")
    w3 = Web3()

    priority_from_hist = estimate_priority_from_fee_history(w3, blocks=5, percentile=50)
    base_fee = w3.eth.get_block('pending')['baseFeePerGas']
    max_fee = base_fee * 2 + priority_from_hist

    tx = {
        "chainId": w3.eth.chain_id,
        "nonce": w3.eth.get_transaction_count(address),
        "maxPriorityFeePerGas": priority_from_hist,
        "maxFeePerGas": max_fee,
        "gas": 300000,
        "to": Web3.to_checksum_address("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
        "value": int(1e18),
        "data": "0x",
    }
    print(tx)
    raw_tx = sign_tx(en, tx)
    print(raw_tx)

    tx_hash = w3.eth.send_raw_transaction(raw_tx)
    print(tx_hash)


if __name__ == '__main__':
    test_transaction()
