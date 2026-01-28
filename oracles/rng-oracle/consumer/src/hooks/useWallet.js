import { useState, useEffect, useCallback } from 'react';
import { ethers } from 'ethers';
import { BASE_SEPOLIA_CHAIN_ID, BASE_SEPOLIA_CONFIG } from '../utils/constants';

/**
 * Custom hook for wallet connection and management
 */
export function useWallet() {
    const [provider, setProvider] = useState(null);
    const [signer, setSigner] = useState(null);
    const [address, setAddress] = useState(null);
    const [chainId, setChainId] = useState(null);
    const [isConnecting, setIsConnecting] = useState(false);
    const [error, setError] = useState(null);

    // Check if wallet is on correct network
    const isCorrectNetwork = chainId === BASE_SEPOLIA_CHAIN_ID;

    // Initialize provider and check existing connection
    useEffect(() => {
        if (typeof window.ethereum === 'undefined') return;

        const web3Provider = new ethers.providers.Web3Provider(window.ethereum);
        setProvider(web3Provider);

        // Check if already connected
        const checkConnection = async () => {
            try {
                const accounts = await web3Provider.listAccounts();
                if (accounts.length > 0) {
                    const network = await web3Provider.getNetwork();
                    setAddress(accounts[0]);
                    setChainId(network.chainId);
                    setSigner(web3Provider.getSigner());
                }
            } catch (err) {
                console.error('Error checking wallet connection:', err);
            }
        };

        checkConnection();

        // Listen for account changes
        const handleAccountsChanged = (accounts) => {
            if (accounts.length === 0) {
                setAddress(null);
                setSigner(null);
            } else {
                setAddress(accounts[0]);
                setSigner(web3Provider.getSigner());
            }
        };

        // Listen for chain changes
        const handleChainChanged = (chainIdHex) => {
            const newChainId = parseInt(chainIdHex, 16);
            setChainId(newChainId);
        };

        window.ethereum.on('accountsChanged', handleAccountsChanged);
        window.ethereum.on('chainChanged', handleChainChanged);

        return () => {
            window.ethereum.removeListener('accountsChanged', handleAccountsChanged);
            window.ethereum.removeListener('chainChanged', handleChainChanged);
        };
    }, []);

    // Connect wallet
    const connect = useCallback(async () => {
        if (typeof window.ethereum === 'undefined') {
            setError('Please install MetaMask or another Web3 wallet');
            return;
        }

        setIsConnecting(true);
        setError(null);

        try {
            const web3Provider = new ethers.providers.Web3Provider(window.ethereum);
            const accounts = await web3Provider.send('eth_requestAccounts', []);
            const network = await web3Provider.getNetwork();

            setProvider(web3Provider);
            setAddress(accounts[0]);
            setChainId(network.chainId);
            setSigner(web3Provider.getSigner());
        } catch (err) {
            console.error('Failed to connect wallet:', err);
            setError(err.message || 'Failed to connect wallet');
        } finally {
            setIsConnecting(false);
        }
    }, []);

    // Disconnect wallet (just clear local state, can't truly disconnect)
    const disconnect = useCallback(() => {
        setAddress(null);
        setSigner(null);
    }, []);

    // Switch to Base Sepolia network
    const switchNetwork = useCallback(async () => {
        if (!window.ethereum) return;

        try {
            await window.ethereum.request({
                method: 'wallet_switchEthereumChain',
                params: [{ chainId: BASE_SEPOLIA_CONFIG.chainId }]
            });
        } catch (switchError) {
            // Chain doesn't exist, add it
            if (switchError.code === 4902) {
                try {
                    await window.ethereum.request({
                        method: 'wallet_addEthereumChain',
                        params: [BASE_SEPOLIA_CONFIG]
                    });
                } catch (addError) {
                    console.error('Failed to add network:', addError);
                    setError('Failed to add Base Sepolia network');
                }
            } else {
                console.error('Failed to switch network:', switchError);
                setError('Failed to switch to Base Sepolia network');
            }
        }
    }, []);

    // Format address for display
    const shortenedAddress = address
        ? `${address.slice(0, 6)}...${address.slice(-4)}`
        : null;

    return {
        provider,
        signer,
        address,
        shortenedAddress,
        chainId,
        isConnected: !!address,
        isConnecting,
        isCorrectNetwork,
        error,
        connect,
        disconnect,
        switchNetwork
    };
}
