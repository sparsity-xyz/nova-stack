import { useState, useEffect, useCallback, useRef } from 'react';
import { ethers } from 'ethers';
import { RNG_ABI, RequestStatus } from '../utils/abi';
import { MAX_EVENTS_DISPLAY } from '../utils/constants';

/**
 * Custom hook for RNG contract interaction
 */
export function useRngContract(contractAddress, provider, signer) {
    const [contract, setContract] = useState(null);
    const [events, setEvents] = useState([]);
    const [userRequests, setUserRequests] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    const eventListenerRef = useRef(null);

    // Initialize contract instance
    useEffect(() => {
        if (!contractAddress || !ethers.utils.isAddress(contractAddress)) {
            setContract(null);
            return;
        }

        // Only create contract if we have a provider
        if (!provider) {
            setContract(null);
            return;
        }

        try {
            const contractInstance = new ethers.Contract(
                contractAddress,
                RNG_ABI,
                signer || provider
            );
            setContract(contractInstance);
            setError(null);
        } catch (err) {
            console.error('Failed to create contract instance:', err);
            setContract(null);
            setError('Invalid contract address');
        }
    }, [contractAddress, provider, signer]);

    // Fetch historical events when contract is initialized
    useEffect(() => {
        if (!contract || !provider) return;

        const fetchHistoricalEvents = async () => {
            try {
                // Query the last 1000 blocks for events (adjust as needed)
                const currentBlock = await provider.getBlockNumber();
                const fromBlock = Math.max(0, currentBlock - 1000);

                // Fetch RandomNumberRequested events
                const requestedFilter = contract.filters.RandomNumberRequested();
                const requestedEvents = await contract.queryFilter(requestedFilter, fromBlock, currentBlock);

                // Fetch RandomNumberFulfilled events
                const fulfilledFilter = contract.filters.RandomNumberFulfilled();
                const fulfilledEvents = await contract.queryFilter(fulfilledFilter, fromBlock, currentBlock);

                // Process and combine events
                const processedEvents = [];

                for (const event of requestedEvents) {
                    const block = await event.getBlock();
                    processedEvents.push({
                        id: `requested-${event.args.requestId.toString()}-${event.blockNumber}`,
                        type: 'RandomNumberRequested',
                        requestId: event.args.requestId.toString(),
                        requester: event.args.requester,
                        min: event.args.min.toString(),
                        max: event.args.max.toString(),
                        count: event.args.count.toString(),
                        callbackContract: event.args.callbackContract,
                        timestamp: new Date(block.timestamp * 1000).toLocaleTimeString(),
                        blockNumber: event.blockNumber,
                        logIndex: event.logIndex,
                        txHash: event.transactionHash
                    });
                }

                for (const event of fulfilledEvents) {
                    const block = await event.getBlock();
                    processedEvents.push({
                        id: `fulfilled-${event.args.requestId.toString()}-${event.blockNumber}`,
                        type: 'RandomNumberFulfilled',
                        requestId: event.args.requestId.toString(),
                        requester: event.args.requester,
                        randomNumbers: event.args.randomNumbers.map(n => n.toString()),
                        timestamp: new Date(block.timestamp * 1000).toLocaleTimeString(),
                        blockNumber: event.blockNumber,
                        logIndex: event.logIndex,
                        txHash: event.transactionHash
                    });
                }

                // Sort by block number descending, then by log index descending (newest first)
                processedEvents.sort((a, b) => {
                    if (a.blockNumber !== b.blockNumber) {
                        return b.blockNumber - a.blockNumber;
                    }
                    return b.logIndex - a.logIndex;
                });

                // Update events state
                setEvents(processedEvents.slice(0, MAX_EVENTS_DISPLAY));
            } catch (err) {
                console.error('Failed to fetch historical events:', err);
            }
        };

        fetchHistoricalEvents();
    }, [contract, provider]);

    // Subscribe to contract events
    useEffect(() => {
        // Only set up listeners if contract exists and has a provider
        if (!contract || !provider) return;

        // Check that the contract actually has a provider attached
        if (!contract.provider) {
            console.warn('Contract has no provider, skipping event listeners');
            return;
        }

        // Clear previous listeners
        if (eventListenerRef.current) {
            try {
                contract.removeAllListeners();
            } catch (e) {
                console.warn('Error removing listeners:', e);
            }
        }

        // Listen for RandomNumberRequested events
        const handleRequested = (requestId, requester, min, max, count, callbackContract, timestamp, event) => {
            const newEvent = {
                id: `requested-${requestId.toString()}-${Date.now()}`,
                type: 'RandomNumberRequested',
                requestId: requestId.toString(),
                requester,
                min: min.toString(),
                max: max.toString(),
                count: count.toString(),
                callbackContract,
                timestamp: new Date(timestamp.toNumber() * 1000).toLocaleTimeString(),
                blockNumber: event.blockNumber,
                txHash: event.transactionHash
            };

            setEvents(prev => [newEvent, ...prev].slice(0, MAX_EVENTS_DISPLAY));
        };

        // Listen for RandomNumberFulfilled events
        const handleFulfilled = (requestId, requester, randomNumbers, timestamp, event) => {
            const newEvent = {
                id: `fulfilled-${requestId.toString()}-${Date.now()}`,
                type: 'RandomNumberFulfilled',
                requestId: requestId.toString(),
                requester,
                randomNumbers: randomNumbers.map(n => n.toString()),
                timestamp: new Date(timestamp.toNumber() * 1000).toLocaleTimeString(),
                blockNumber: event.blockNumber,
                txHash: event.transactionHash
            };

            setEvents(prev => [newEvent, ...prev].slice(0, MAX_EVENTS_DISPLAY));

            // Update user requests if this is one of theirs
            setUserRequests(prev =>
                prev.map(req =>
                    req.requestId === requestId.toString()
                        ? { ...req, status: 'fulfilled', randomNumbers: randomNumbers.map(n => n.toString()) }
                        : req
                )
            );
        };

        try {
            contract.on('RandomNumberRequested', handleRequested);
            contract.on('RandomNumberFulfilled', handleFulfilled);
            eventListenerRef.current = true;
        } catch (err) {
            console.error('Failed to set up event listeners:', err);
        }

        return () => {
            try {
                contract.removeAllListeners('RandomNumberRequested');
                contract.removeAllListeners('RandomNumberFulfilled');
            } catch (e) {
                console.warn('Error cleaning up listeners:', e);
            }
            eventListenerRef.current = null;
        };
    }, [contract, provider]);

    // Request random number
    const requestRandom = useCallback(async (min, max, userAddress) => {
        if (!contract || !signer) {
            setError('Contract or wallet not connected');
            return null;
        }

        setIsLoading(true);
        setError(null);

        try {
            // Always request 1 random number
            const tx = await contract.requestRandomRange(min, max, 1);
            const receipt = await tx.wait();

            // Extract requestId from events
            let requestId = null;
            const iface = new ethers.utils.Interface(RNG_ABI);

            for (const log of receipt.logs) {
                try {
                    const parsed = iface.parseLog(log);
                    if (parsed.name === 'RandomNumberRequested') {
                        requestId = parsed.args.requestId.toString();
                        break;
                    }
                } catch (e) {
                    // Not our event, continue
                }
            }

            if (requestId) {
                // Add to user requests
                const newRequest = {
                    requestId,
                    min: min.toString(),
                    max: max.toString(),
                    status: 'pending',
                    randomNumbers: [],
                    timestamp: new Date().toLocaleTimeString(),
                    txHash: receipt.transactionHash
                };
                setUserRequests(prev => [newRequest, ...prev]);
            }

            return requestId;
        } catch (err) {
            console.error('Failed to request random number:', err);
            setError(err.reason || err.message || 'Transaction failed');
            return null;
        } finally {
            setIsLoading(false);
        }
    }, [contract, signer]);

    // Check request status manually
    const checkRequestStatus = useCallback(async (requestId) => {
        if (!contract) return null;

        try {
            const result = await contract.getRequest(requestId);
            return {
                status: result.status,
                randomNumbers: result.randomNumbers.map(n => n.toString()),
                requester: result.requester,
                min: result.min.toString(),
                max: result.max.toString()
            };
        } catch (err) {
            console.error('Failed to check request status:', err);
            return null;
        }
    }, [contract]);

    // Clear events
    const clearEvents = useCallback(() => {
        setEvents([]);
    }, []);

    return {
        contract,
        events,
        userRequests,
        isLoading,
        error,
        requestRandom,
        checkRequestStatus,
        clearEvents
    };
}
