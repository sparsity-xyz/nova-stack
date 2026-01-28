'use client';

import { useState } from 'react';
import { enclaveClient } from '@/lib/crypto';

interface EnclaveConfigProps {
    onConnected: (address: string) => void;
}

export default function EnclaveConfig({ onConnected }: EnclaveConfigProps) {
    const [baseUrl, setBaseUrl] = useState('https://108.app.sparsity.cloud');
    const [isConnecting, setIsConnecting] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [enclaveAddress, setEnclaveAddress] = useState<string | null>(null);

    const handleConnect = async () => {
        if (!baseUrl.trim()) {
            setError('Please enter the enclave base URL');
            return;
        }

        setIsConnecting(true);
        setError(null);

        try {
            // Connect to enclave (fetches attestation and initializes crypto)
            await enclaveClient.connect(baseUrl.trim());

            // Get health status to check enclave address
            const health = await enclaveClient.checkHealth();
            setEnclaveAddress(health.enclave_address);
            onConnected(health.enclave_address);
        } catch (err) {
            console.error('Connection error:', err);
            setError(err instanceof Error ? err.message : 'Failed to connect to enclave');
        } finally {
            setIsConnecting(false);
        }
    };

    return (
        <div className="bg-[#1a1a1a] rounded-lg border border-gray-800 p-6">
            <h2 className="text-xl font-semibold text-white mb-4">
                Connect to Enclave
            </h2>

            {!enclaveAddress ? (
                <div className="space-y-4">
                    <div>
                        <label htmlFor="baseUrl" className="block text-sm font-medium text-gray-300 mb-2">
                            Enclave Base URL
                        </label>
                        <input
                            id="baseUrl"
                            type="text"
                            value={baseUrl}
                            onChange={(e) => setBaseUrl(e.target.value)}
                            placeholder="https://your-enclave.nova.sparsity.io"
                            className="w-full px-4 py-3 bg-[#0a0a0a] border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-primary"
                            disabled={isConnecting}
                        />
                        <p className="mt-2 text-xs text-gray-500">
                            The enclave provides attestation at /.well-known/attestation
                        </p>
                    </div>

                    {error && (
                        <div className="p-3 bg-red-900/50 border border-red-800 rounded-lg text-red-400 text-sm">
                            {error}
                        </div>
                    )}

                    <button
                        onClick={handleConnect}
                        disabled={isConnecting}
                        className="w-full py-3 px-4 bg-primary text-black font-medium rounded-lg hover:bg-primary/90 disabled:bg-primary/50 disabled:cursor-not-allowed transition-colors"
                    >
                        {isConnecting ? (
                            <span className="flex items-center justify-center gap-2">
                                <span className="w-2 h-2 rounded-full bg-black animate-bounce" style={{ animationDelay: '0ms' }} />
                                <span className="w-2 h-2 rounded-full bg-black animate-bounce" style={{ animationDelay: '150ms' }} />
                                <span className="w-2 h-2 rounded-full bg-black animate-bounce" style={{ animationDelay: '300ms' }} />
                            </span>
                        ) : (
                            'Connect'
                        )}
                    </button>
                </div>
            ) : (
                <div className="space-y-3">
                    <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full bg-green-500" />
                        <span className="text-green-400 font-medium">Connected</span>
                    </div>

                    <div>
                        <span className="text-sm text-gray-400">Base URL:</span>
                        <p className="text-white font-mono text-sm break-all">{enclaveClient.baseUrl}</p>
                    </div>

                    <div>
                        <span className="text-sm text-gray-400">Enclave Address:</span>
                        <p className="text-primary font-mono text-sm break-all">{enclaveAddress}</p>
                    </div>
                </div>
            )}
        </div>
    );
}
