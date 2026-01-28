/**
 * Application constants
 */

// Default RNG contract address (can be updated by user)
export const DEFAULT_RNG_ADDRESS = "0xd5083A6e0006Eb9eF16c0b179f5ee486ef50cF9a";

// Base Sepolia chain configuration
export const BASE_SEPOLIA_CHAIN_ID = 84532;
export const BASE_SEPOLIA_CONFIG = {
    chainId: `0x${BASE_SEPOLIA_CHAIN_ID.toString(16)}`,
    chainName: "Base Sepolia",
    nativeCurrency: {
        name: "ETH",
        symbol: "ETH",
        decimals: 18
    },
    rpcUrls: ["https://sepolia.base.org"],
    blockExplorerUrls: ["https://sepolia.basescan.org"]
};

// Polling interval for checking request status (ms)
export const POLL_INTERVAL = 3000;

// Maximum number of events to display
export const MAX_EVENTS_DISPLAY = 50;
