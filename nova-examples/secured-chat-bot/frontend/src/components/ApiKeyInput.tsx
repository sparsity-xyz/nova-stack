'use client';

import { useState, useEffect, useCallback } from 'react';
import { enclaveClient } from '@/lib/crypto';

interface ApiKeyInputProps {
    isConnected: boolean;
    onApiKeySet: () => void;
}

// Only support OpenAI
const DEFAULT_PLATFORM = 'openai';

export default function ApiKeyInput({ isConnected, onApiKeySet }: ApiKeyInputProps) {
    const [apiKey, setApiKey] = useState('');
    const [platform, setPlatform] = useState('openai');
    const [showKey, setShowKey] = useState(false);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [isSet, setIsSet] = useState(false);
    const [isChecking, setIsChecking] = useState(false);
    const [countdown, setCountdown] = useState<number | null>(null);
    const [cachedPlatform, setCachedPlatform] = useState<string | null>(null);

    // Check API key status when connected
    const checkApiKeyStatus = useCallback(async () => {
        if (!isConnected) return;

        setIsChecking(true);
        setError(null);

        try {
            const health = await enclaveClient.checkHealth();
            console.log('Health check result:', health);

            if (health.api_key_available) {
                setIsSet(true);
                setCachedPlatform((health as any).cached_platform || DEFAULT_PLATFORM);
                // Start countdown
                setCountdown(3);
            }
        } catch (err) {
            console.error('Error checking health:', err);
            // Don't show error, just proceed to API key input
        } finally {
            setIsChecking(false);
        }
    }, [isConnected]);

    // Check API key status when connection changes
    useEffect(() => {
        if (isConnected) {
            checkApiKeyStatus();
        }
    }, [isConnected, checkApiKeyStatus]);

    // Countdown timer for auto-proceed
    useEffect(() => {
        if (countdown === null) return;

        if (countdown <= 0) {
            onApiKeySet();
            return;
        }

        const timer = setTimeout(() => {
            setCountdown(countdown - 1);
        }, 1000);

        return () => clearTimeout(timer);
    }, [countdown, onApiKeySet]);

    const handleSubmit = async () => {
        if (!apiKey.trim()) {
            setError('Please enter an API key');
            return;
        }

        if (!isConnected) {
            setError('Please connect to enclave first');
            return;
        }

        setIsSubmitting(true);
        setError(null);

        try {
            const result = await enclaveClient.setApiKey(apiKey.trim(), platform);
            console.log('API key set result:', result);
            setIsSet(true);
            setCachedPlatform(platform);
            setApiKey(''); // Clear the input for security
            onApiKeySet();
        } catch (err) {
            console.error('Error setting API key:', err);
            setError(err instanceof Error ? err.message : 'Failed to set API key');
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleUpdateKey = () => {
        setIsSet(false);
        setCountdown(null);
    };

    return (
        <div className="bg-[#1a1a1a] rounded-lg border border-gray-800 p-6">
            <h2 className="text-xl font-semibold text-white mb-4">
                Set API Key
            </h2>

            {!isConnected ? (
                <p className="text-gray-400">Connect to enclave first to set API key.</p>
            ) : isChecking ? (
                <div className="flex items-center gap-3">
                    <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                    <span className="text-gray-400">Checking API key status...</span>
                </div>
            ) : isSet ? (
                <div className="space-y-3">
                    <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full bg-green-500" />
                        <span className="text-green-400 font-medium">API Key Already Configured</span>
                    </div>
                    {cachedPlatform && (
                        <p className="text-sm text-gray-400">
                            Platform: <span className="text-white">{cachedPlatform === 'openai' ? 'OpenAI' : cachedPlatform}</span>
                        </p>
                    )}
                    {countdown !== null && countdown > 0 && (
                        <p className="text-sm text-gray-400">
                            Proceeding to chat in <span className="text-primary font-medium">{countdown}</span> seconds...
                        </p>
                    )}
                    <button
                        onClick={handleUpdateKey}
                        className="text-sm text-primary hover:underline"
                    >
                        Update API Key
                    </button>
                </div>
            ) : (
                <div className="space-y-4">

                    <div>
                        <label htmlFor="apiKey" className="block text-sm font-medium text-gray-300 mb-2">
                            API Key
                        </label>
                        <div className="relative">
                            <input
                                id="apiKey"
                                type={showKey ? 'text' : 'password'}
                                value={apiKey}
                                onChange={(e) => setApiKey(e.target.value)}
                                placeholder="sk-..."
                                className="w-full px-4 py-3 pr-12 bg-[#0a0a0a] border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-primary"
                                disabled={isSubmitting}
                            />
                            <button
                                type="button"
                                onClick={() => setShowKey(!showKey)}
                                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
                            >
                                {showKey ? '🙈' : '👁️'}
                            </button>
                        </div>
                        <p className="mt-2 text-xs text-gray-500">
                            Your API key is encrypted and sent securely to the enclave.
                        </p>
                    </div>

                    {error && (
                        <div className="p-3 bg-red-900/50 border border-red-800 rounded-lg text-red-400 text-sm">
                            {error}
                        </div>
                    )}

                    <button
                        onClick={handleSubmit}
                        disabled={isSubmitting || !apiKey.trim()}
                        className="w-full py-3 px-4 bg-primary text-black font-medium rounded-lg hover:bg-primary/90 disabled:bg-primary/50 disabled:cursor-not-allowed transition-colors"
                    >
                        {isSubmitting ? (
                            <span className="flex items-center justify-center gap-2">
                                <span className="w-2 h-2 rounded-full bg-black animate-bounce" style={{ animationDelay: '0ms' }} />
                                <span className="w-2 h-2 rounded-full bg-black animate-bounce" style={{ animationDelay: '150ms' }} />
                                <span className="w-2 h-2 rounded-full bg-black animate-bounce" style={{ animationDelay: '300ms' }} />
                            </span>
                        ) : (
                            'Set API Key'
                        )}
                    </button>
                </div>
            )}
        </div>
    );
}
