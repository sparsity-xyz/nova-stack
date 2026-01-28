'use client';

import { useState } from 'react';
import EnclaveConfig from '@/components/EnclaveConfig';
import ApiKeyInput from '@/components/ApiKeyInput';
import Chat from '@/components/Chat';

const AVAILABLE_MODELS = [
    { value: 'gpt-5.1', label: 'GPT-5.1' },
    { value: 'gpt-5', label: 'GPT-5' },
    { value: 'gpt-5-mini', label: 'GPT-5 Mini' },
    { value: 'gpt-4.1', label: 'GPT-4.1' },
    { value: 'gpt-4.1-mini', label: 'GPT-4.1 Mini' },
    { value: 'gpt-4o', label: 'GPT-4o' },
    { value: 'gpt-4o-mini', label: 'GPT-4o Mini' },
    { value: 'gpt-4', label: 'GPT-4' },
];

export default function Home() {
    const [isConnected, setIsConnected] = useState(false);
    const [isApiKeySet, setIsApiKeySet] = useState(false);
    const [enclaveAddress, setEnclaveAddress] = useState<string | null>(null);
    const [selectedModel, setSelectedModel] = useState('gpt-5.1');

    const handleConnected = (address: string) => {
        setIsConnected(true);
        setEnclaveAddress(address);
    };

    const handleApiKeySet = () => {
        setIsApiKeySet(true);
    };

    const isReady = isConnected && isApiKeySet;

    return (
        <div className="min-h-screen bg-[#0a0a0a]">
            {/* Header */}
            <header className="border-b border-gray-800 px-6 py-4">
                <div className="max-w-7xl mx-auto flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <img src="/frontend/logo.png" alt="Sparsity" className="w-10 h-10" />
                        <div>
                            <h1 className="text-xl font-bold text-white">Fully Secured Chat Bot</h1>
                            <p className="text-sm text-gray-400">Powered by Sparsity Nova Platform</p>
                        </div>
                    </div>

                    <div className="flex items-center gap-4">
                        {/* Model Selector - Only show when chat is ready */}
                        {isReady && (
                            <div className="flex items-center gap-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="w-4 h-4 text-gray-400">
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904 9 18.75l-.813-2.846a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 0 0-3.09 3.09ZM18.259 8.715 18 9.75l-.259-1.035a3.375 3.375 0 0 0-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 0 0 2.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 0 0 2.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 0 0-2.456 2.456Z" />
                                </svg>
                                <select
                                    value={selectedModel}
                                    onChange={(e) => setSelectedModel(e.target.value)}
                                    className="bg-[#1a1a1a] border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-primary cursor-pointer"
                                >
                                    {AVAILABLE_MODELS.map((model) => (
                                        <option key={model.value} value={model.value}>{model.label}</option>
                                    ))}
                                </select>
                            </div>
                        )}

                        {isConnected && (
                            <div className="flex items-center gap-2 text-sm">
                                <div className={`w-2 h-2 rounded-full ${isApiKeySet ? 'bg-green-500' : 'bg-yellow-500'}`} />
                                <span className="text-gray-400">
                                    {isApiKeySet ? 'Ready' : 'API Key Required'}
                                </span>
                            </div>
                        )}
                    </div>
                </div>
            </header>

            {/* Main Content */}
            <main className="max-w-7xl mx-auto p-6">
                {!isReady ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl mx-auto">
                        <EnclaveConfig onConnected={handleConnected} />
                        <ApiKeyInput isConnected={isConnected} onApiKeySet={handleApiKeySet} />
                    </div>
                ) : (
                    <div className="h-[calc(100vh-10rem)] bg-[#111] rounded-lg border border-gray-800">
                        <Chat isReady={isReady} selectedModel={selectedModel} />
                    </div>
                )}
            </main>

            {/* Footer */}
            <footer className="fixed bottom-0 left-0 right-0 border-t border-gray-800 bg-[#0a0a0a] px-6 py-3">
                <div className="max-w-7xl mx-auto flex items-center justify-between text-sm text-gray-500">
                    <span>End-to-end encrypted • Verifiable AI responses</span>
                    {enclaveAddress && (
                        <span className="font-mono text-xs text-gray-600">
                            Enclave: {enclaveAddress.slice(0, 10)}...{enclaveAddress.slice(-8)}
                        </span>
                    )}
                </div>
            </footer>
        </div>
    );
}
