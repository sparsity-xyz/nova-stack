'use client';

import { useEffect, useState, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { decodeAttestationDoc, fetchAttestation } from '@/lib/attestation';

interface VerificationData {
    message: string;
    response: string;
    signature: string;
    platform?: string;
    ai_model?: string;
    timestamp?: number;
    enclave_url?: string;
}

function VerificationContent() {
    const searchParams = useSearchParams();
    const [data, setData] = useState<VerificationData | null>(null);
    const [attestation, setAttestation] = useState<any>(null);
    const [isLoadingAttestation, setIsLoadingAttestation] = useState(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const id = searchParams.get('id');
        if (!id) {
            setError('Missing verification ID');
            return;
        }

        try {
            const storedData = localStorage.getItem(`verification_${id}`);
            if (storedData) {
                setData(JSON.parse(storedData));
            } else {
                setError('Verification data not found');
            }
        } catch (err) {
            setError('Failed to load verification data');
        }
    }, [searchParams]);

    const handleGetAttestation = async () => {
        if (!data?.enclave_url) {
            setError('Enclave URL not available');
            return;
        }

        setIsLoadingAttestation(true);
        try {
            const attestationData = await fetchAttestation(data.enclave_url);
            setAttestation(attestationData);
        } catch (err) {
            console.error('Attestation error:', err);
            setError('Failed to fetch attestation');
        } finally {
            setIsLoadingAttestation(false);
        }
    };

    const formatTimestamp = (timestamp?: number) => {
        if (!timestamp) return 'Unknown';
        return new Date(timestamp * 1000).toLocaleString();
    };

    if (error) {
        return (
            <div className="min-h-screen bg-[#0a0a0a] p-8">
                <div className="max-w-4xl mx-auto">
                    <div className="p-4 bg-red-900/50 border border-red-800 rounded-lg text-red-400">
                        {error}
                    </div>
                </div>
            </div>
        );
    }

    if (!data) {
        return (
            <div className="min-h-screen bg-[#0a0a0a] p-8">
                <div className="max-w-4xl mx-auto text-gray-400">
                    Loading verification data...
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-[#0a0a0a] p-8">
            <div className="max-w-4xl mx-auto">
                <h1 className="text-2xl font-bold text-white mb-6">Message Verification</h1>

                <div className="space-y-6">
                    {/* Request */}
                    <div className="bg-[#1a1a1a] rounded-lg border border-gray-800 p-4">
                        <h2 className="text-lg font-medium text-gray-300 mb-2">Request</h2>
                        <pre className="text-white whitespace-pre-wrap break-words">{data.message}</pre>
                    </div>

                    {/* Response */}
                    <div className="bg-[#1a1a1a] rounded-lg border border-gray-800 p-4">
                        <h2 className="text-lg font-medium text-gray-300 mb-2">Response</h2>
                        <pre className="text-white whitespace-pre-wrap break-words">{data.response}</pre>
                    </div>

                    {/* Metadata */}
                    <div className="bg-[#1a1a1a] rounded-lg border border-gray-800 p-4">
                        <h2 className="text-lg font-medium text-gray-300 mb-2">Metadata</h2>
                        <div className="space-y-2 text-sm">
                            <div><span className="text-gray-400">Platform:</span> <span className="text-white">{data.platform || 'Unknown'}</span></div>
                            <div><span className="text-gray-400">Model:</span> <span className="text-white">{data.ai_model || 'Unknown'}</span></div>
                            <div><span className="text-gray-400">Timestamp:</span> <span className="text-white">{formatTimestamp(data.timestamp)}</span></div>
                        </div>
                    </div>

                    {/* Signature */}
                    <div className="bg-[#1a1a1a] rounded-lg border border-gray-800 p-4">
                        <h2 className="text-lg font-medium text-gray-300 mb-2">Signature</h2>
                        <div className="p-3 bg-primary/10 rounded text-primary font-mono text-sm break-all">
                            {data.signature}
                        </div>
                    </div>

                    {/* Attestation */}
                    <div className="bg-[#1a1a1a] rounded-lg border border-gray-800 p-4">
                        <div className="flex items-center justify-between mb-4">
                            <h2 className="text-lg font-medium text-gray-300">Attestation</h2>
                            <button
                                onClick={handleGetAttestation}
                                disabled={isLoadingAttestation}
                                className="px-4 py-2 bg-gray-800 text-white rounded-lg hover:bg-gray-700 disabled:opacity-50"
                            >
                                {isLoadingAttestation ? 'Loading...' : attestation ? 'Refresh' : 'Get Attestation'}
                            </button>
                        </div>

                        {attestation && (
                            <div className="space-y-3 text-xs">
                                <div><span className="text-gray-400">Module ID:</span> <code className="text-white break-all">{attestation.attestation_document.module_id}</code></div>
                                <div><span className="text-gray-400">Digest:</span> <code className="text-white">{attestation.attestation_document.digest}</code></div>
                                <div><span className="text-gray-400">Timestamp:</span> <span className="text-white">{new Date(attestation.attestation_document.timestamp).toLocaleString()}</span></div>

                                <div>
                                    <span className="text-gray-400">PCRs:</span>
                                    <div className="mt-1 space-y-1">
                                        {Object.entries(attestation.attestation_document.pcrs).map(([key, value]) => (
                                            <div key={key} className="text-white">
                                                <span className="text-gray-500">PCR {key}:</span> <code className="break-all">{String(value)}</code>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                <div>
                                    <span className="text-gray-400">Public Key (hex):</span>
                                    <pre className="mt-1 p-2 bg-[#0a0a0a] rounded text-white break-all">{attestation.attestation_document.public_key}</pre>
                                </div>

                                <div>
                                    <span className="text-gray-400">User Data:</span>
                                    <div className="mt-1 p-2 bg-[#0a0a0a] rounded text-white overflow-auto max-h-40">
                                        {typeof attestation.attestation_document.user_data === 'object' ? (
                                            <pre>{JSON.stringify(attestation.attestation_document.user_data, null, 2)}</pre>
                                        ) : (
                                            <code className="break-all">{attestation.attestation_document.user_data}</code>
                                        )}
                                    </div>
                                </div>

                                {attestation.signature && (
                                    <div>
                                        <span className="text-gray-400">Attestation Signature:</span>
                                        <div className="mt-1 p-2 bg-[#0a0a0a] rounded text-white break-all font-mono">
                                            {attestation.signature}
                                        </div>
                                    </div>
                                )}

                                {attestation.attestation_document.certificate && (
                                    <div>
                                        <span className="text-gray-400">Enclave Certificate (PEM):</span>
                                        <pre className="mt-1 p-2 bg-[#0a0a0a] rounded text-white overflow-auto max-h-32 font-mono scrollbar-hide">
                                            {attestation.attestation_document.certificate}
                                        </pre>
                                    </div>
                                )}

                                {attestation.attestation_document.cabundle && attestation.attestation_document.cabundle.length > 0 && (
                                    <div>
                                        <span className="text-gray-400">CA Bundle ({attestation.attestation_document.cabundle.length} certs):</span>
                                        <div className="mt-1 space-y-2">
                                            {attestation.attestation_document.cabundle.map((cert: string, i: number) => (
                                                <pre key={i} className="p-2 bg-[#0a0a0a] rounded text-white overflow-auto max-h-32 font-mono scrollbar-hide">
                                                    {cert}
                                                </pre>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                <div className="flex gap-4 mt-2">
                                    <div className="flex items-center gap-1">
                                        <span className={`w-2 h-2 rounded-full ${attestation.attestation_document.certificate ? 'bg-green-500' : 'bg-red-500'}`}></span>
                                        <span className="text-gray-400">Certificate: {attestation.attestation_document.certificate ? 'Present' : 'Missing'}</span>
                                    </div>
                                    <div className="flex items-center gap-1">
                                        <span className={`w-2 h-2 rounded-full ${attestation.attestation_document.cabundle?.length > 0 ? 'bg-green-500' : 'bg-red-500'}`}></span>
                                        <span className="text-gray-400">CA Bundle: {attestation.attestation_document.cabundle?.length > 0 ? 'Present' : 'Missing'}</span>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}

export default function VerifyPage() {
    return (
        <Suspense fallback={<div className="min-h-screen bg-[#0a0a0a] p-8 text-gray-400">Loading...</div>}>
            <VerificationContent />
        </Suspense>
    );
}
