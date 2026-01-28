import json
from pathlib import Path


class Config:
    RPC_URL = "https://base-sepolia-public.nodies.app"
    CONTRACT_ADDRESS = "0xd5083A6e0006Eb9eF16c0b179f5ee486ef50cF9a"

    POLL_INTERVAL = 10  # second
    FROM_BLOCK = "latest"

    @staticmethod
    def load_abi():
        abi_path = Path(__file__).parent / "abi.json"
        with open(abi_path, "r") as f:
            return json.load(f)

    CONTRACT_ABI = load_abi.__func__()

    LOG_LEVEL = "INFO"


if __name__ == '__main__':
    print(Config)
