'use client';

import { useState, useEffect } from 'react';
import { decodeAttestationDoc, parseUserData, DecodedAttestation } from '@/lib/attestation';

export interface VerificationData {
    attestation: string;
    publicKey: string;
    ethAddr: string;
    encryptedRequest: string;
    decryptedRequest: string;
    rawResponse: string;  // The original { sig, data } response
    encryptedResponse: string;
    decryptedResponse: string;
    signature: string;
}

interface VerificationDialogProps {
    isOpen: boolean;
    onClose: () => void;
    data: VerificationData | null;
}

export default function VerificationDialog({ isOpen, onClose, data }: VerificationDialogProps) {
    const [activeTab, setActiveTab] = useState<'attestation' | 'request' | 'response'>('attestation');
    const [decodedAttestation, setDecodedAttestation] = useState<DecodedAttestation | null>(null);
    const [attestationLoading, setAttestationLoading] = useState(false);
    const [attestationError, setAttestationError] = useState<string | null>(null);

    useEffect(() => {
        if (isOpen && data?.attestation && !decodedAttestation) {
            decodeAttestation();
        }
    }, [isOpen, data?.attestation]);

    const decodeAttestation = async () => {
        if (!data?.attestation) return;
        setAttestationLoading(true);
        setAttestationError(null);
        try {
            // First try to parse as JSON (lottery-frontend format)
            try {
                const jsonData = JSON.parse(data.attestation);
                // Check if it's the attestation_document format
                const attestationData = jsonData.attestation_document || jsonData;

                // Parse user_data - it can be string or object
                let userData: Record<string, unknown> | null = null;
                if (attestationData.user_data) {
                    if (typeof attestationData.user_data === 'string') {
                        try {
                            userData = JSON.parse(attestationData.user_data);
                        } catch {
                            // Not JSON string, might be base64
                        }
                    } else if (typeof attestationData.user_data === 'object') {
                        userData = attestationData.user_data;
                    }
                }

                // Convert to DecodedAttestation format
                const decoded: DecodedAttestation = {
                    attestation_document: {
                        module_id: attestationData.module_id || '',
                        digest: attestationData.digest || '',
                        timestamp: attestationData.timestamp || 0,
                        pcrs: attestationData.pcrs || {},
                        certificate: attestationData.has_certificate ? '[present]' : '',
                        cabundle: attestationData.has_cabundle ? ['[present]'] : [],
                        public_key: attestationData.public_key || '',
                        user_data: userData ? JSON.stringify(userData) : '',
                        nonce: attestationData.nonce || '',
                    },
                    module_id: attestationData.module_id || '',
                    digest: attestationData.digest || '',
                    timestamp: attestationData.timestamp || 0,
                    pcrs: attestationData.pcrs || {},
                    certificate: attestationData.has_certificate ? '[present]' : '',
                    cabundle: attestationData.has_cabundle ? ['[present]'] : [],
                    public_key: attestationData.public_key || '',
                    user_data: userData ? JSON.stringify(userData) : '',
                    nonce: attestationData.nonce || '',
                };
                setDecodedAttestation(decoded);
                return;
            } catch {
                // Not valid JSON, try CBOR decoding
            }

            // Fallback to CBOR decoding
            const decoded = await decodeAttestationDoc(data.attestation);
            setDecodedAttestation(decoded);
        } catch (err) {
            console.error('Failed to decode attestation:', err);
            setAttestationError(err instanceof Error ? err.message : 'Failed to decode attestation');
        } finally {
            setAttestationLoading(false);
        }
    };

    if (!isOpen || !data) return null;

    const tabs = [
        { id: 'attestation', label: 'Attestation' },
        { id: 'request', label: 'Request' },
        { id: 'response', label: 'Response' },
    ] as const;

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    const formatJson = (str: string) => {
        try {
            return JSON.stringify(JSON.parse(str), null, 2);
        } catch {
            return str;
        }
    };

    // Parse user_data to get eth_addr
    const parsedUserData = decodedAttestation?.user_data ? parseUserData(decodedAttestation.user_data) : null;
    const ethAddr = data.ethAddr || parsedUserData?.ethAddr || 'Unknown';

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
            {/* Backdrop */}
            <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />

            {/* Dialog */}
            <div className="relative bg-[#0a0a0a] border border-gray-800 rounded-xl shadow-2xl w-full max-w-4xl max-h-[85vh] overflow-hidden mx-4">
                {/* Header */}
                <div className="flex items-center justify-between p-4 border-b border-gray-800">
                    <div className="flex items-center gap-2">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="h-5 w-5 text-primary">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />
                        </svg>
                        <h2 className="text-lg font-semibold text-white">Verification Details</h2>
                    </div>
                    <button onClick={onClose} className="text-gray-400 hover:text-white transition-colors">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="h-5 w-5">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                {/* Tabs */}
                <div className="flex border-b border-gray-800">
                    {tabs.map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`flex-1 px-4 py-3 text-sm font-medium transition-colors ${activeTab === tab.id
                                ? 'text-primary border-b-2 border-primary bg-primary/5'
                                : 'text-gray-400 hover:text-white'
                                }`}
                        >
                            {tab.label}
                        </button>
                    ))}
                </div>

                {/* Content */}
                <div className="p-4 overflow-y-auto max-h-[calc(85vh-140px)]">
                    {/* Attestation Tab */}
                    {activeTab === 'attestation' && (
                        <div className="space-y-4">
                            {attestationLoading ? (
                                <div className="flex items-center justify-center py-8">
                                    <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                                    <span className="ml-2 text-gray-400">Decoding attestation...</span>
                                </div>
                            ) : attestationError ? (
                                <div className="p-4 bg-red-900/30 border border-red-800 rounded-lg text-red-400 text-sm">
                                    {attestationError}
                                </div>
                            ) : decodedAttestation ? (
                                <>
                                    {/* ETH Address */}
                                    <div className="p-4 bg-primary/10 border border-primary/30 rounded-lg">
                                        <div className="flex items-center justify-between">
                                            <span className="text-sm text-gray-400">ETH Address</span>
                                            <button onClick={() => copyToClipboard(ethAddr)} className="text-xs text-gray-500 hover:text-white">Copy</button>
                                        </div>
                                        <p className="mt-1 font-mono text-primary text-sm break-all">{ethAddr}</p>
                                    </div>

                                    {/* Public Key */}
                                    <div>
                                        <div className="flex items-center justify-between mb-1">
                                            <label className="text-sm font-medium text-gray-300">Public Key</label>
                                            <button onClick={() => copyToClipboard(data.publicKey)} className="text-xs text-gray-500 hover:text-white">Copy</button>
                                        </div>
                                        <p className="p-2 bg-[#1a1a1a] rounded border border-gray-800 font-mono text-xs text-primary break-all max-h-20 overflow-y-auto">{data.publicKey}</p>
                                    </div>

                                    {/* PCR0-3 Values */}
                                    <div>
                                        <div className="flex items-center justify-between mb-2">
                                            <label className="text-sm font-medium text-gray-300">PCR Values (Code Measurement)</label>
                                        </div>
                                        <div className="p-3 bg-[#1a1a1a] rounded border border-gray-800 space-y-1">
                                            {decodedAttestation.pcrs && Object.entries(decodedAttestation.pcrs)
                                                .filter(([key]) => ['0', '1', '2', '3'].includes(String(key)))
                                                .sort(([a], [b]) => parseInt(a) - parseInt(b))
                                                .map(([key, value]) => (
                                                    <div key={key} className="flex gap-2 text-xs">
                                                        <span className="text-gray-500 w-12 flex-shrink-0">PCR{key}:</span>
                                                        <span className="font-mono text-gray-300 break-all">{value}</span>
                                                    </div>
                                                ))}
                                        </div>
                                    </div>

                                    {/* Full Attestation - Expandable */}
                                    <div className="border border-gray-800 rounded-lg overflow-hidden">
                                        <details className="group">
                                            <summary className="px-4 py-3 bg-[#1a1a1a] cursor-pointer flex items-center justify-between hover:bg-[#252525] transition-colors">
                                                <span className="text-sm font-medium text-gray-300">Full Attestation</span>
                                                <svg
                                                    xmlns="http://www.w3.org/2000/svg"
                                                    fill="none"
                                                    viewBox="0 0 24 24"
                                                    strokeWidth="1.5"
                                                    stroke="currentColor"
                                                    className="h-4 w-4 text-gray-500 group-open:rotate-180 transition-transform"
                                                >
                                                    <path strokeLinecap="round" strokeLinejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
                                                </svg>
                                            </summary>
                                            <div className="p-4 bg-[#0a0a0a] space-y-3">
                                                {/* Module ID */}
                                                <div>
                                                    <label className="text-xs font-medium text-gray-400">Module ID</label>
                                                    <p className="mt-1 p-2 bg-[#1a1a1a] rounded border border-gray-800 font-mono text-xs text-white">{decodedAttestation.module_id || 'N/A'}</p>
                                                </div>

                                                {/* Digest */}
                                                <div>
                                                    <label className="text-xs font-medium text-gray-400">Digest</label>
                                                    <p className="mt-1 p-2 bg-[#1a1a1a] rounded border border-gray-800 font-mono text-xs text-white">{decodedAttestation.digest || 'N/A'}</p>
                                                </div>

                                                {/* Timestamp */}
                                                <div>
                                                    <label className="text-xs font-medium text-gray-400">Timestamp</label>
                                                    <p className="mt-1 p-2 bg-[#1a1a1a] rounded border border-gray-800 font-mono text-xs text-white">
                                                        {decodedAttestation.timestamp ? `${new Date(decodedAttestation.timestamp).toLocaleString()} (${decodedAttestation.timestamp})` : 'N/A'}
                                                    </p>
                                                </div>

                                                {/* All PCRs */}
                                                <div>
                                                    <label className="text-xs font-medium text-gray-400">All PCR Values</label>
                                                    <div className="mt-1 p-2 bg-[#1a1a1a] rounded border border-gray-800 space-y-1 max-h-40 overflow-y-auto">
                                                        {decodedAttestation.pcrs && Object.keys(decodedAttestation.pcrs).length > 0 ? (
                                                            Object.entries(decodedAttestation.pcrs)
                                                                .sort(([a], [b]) => parseInt(a) - parseInt(b))
                                                                .map(([key, value]) => (
                                                                    <div key={key} className="flex gap-2 text-xs">
                                                                        <span className="text-gray-500 w-12 flex-shrink-0">PCR{key}:</span>
                                                                        <span className="font-mono text-gray-300 break-all">{value || 'N/A'}</span>
                                                                    </div>
                                                                ))
                                                        ) : (
                                                            <span className="text-gray-500 text-xs">N/A</span>
                                                        )}
                                                    </div>
                                                </div>

                                                {/* Public Key */}
                                                <div>
                                                    <label className="text-xs font-medium text-gray-400">Public Key</label>
                                                    <p className="mt-1 p-2 bg-[#1a1a1a] rounded border border-gray-800 font-mono text-xs text-primary break-all max-h-20 overflow-y-auto">
                                                        {decodedAttestation.public_key || 'N/A'}
                                                    </p>
                                                </div>

                                                {/* Certificate */}
                                                <div>
                                                    <label className="text-xs font-medium text-gray-400">Certificate</label>
                                                    <p className="mt-1 p-2 bg-[#1a1a1a] rounded border border-gray-800 font-mono text-xs text-gray-400 break-all max-h-24 overflow-y-auto">
                                                        {decodedAttestation.certificate || 'N/A'}
                                                    </p>
                                                </div>

                                                {/* CA Bundle */}
                                                <div>
                                                    <label className="text-xs font-medium text-gray-400">CA Bundle ({decodedAttestation.cabundle?.length || 0} certs)</label>
                                                    <div className="mt-1 p-2 bg-[#1a1a1a] rounded border border-gray-800 space-y-1 max-h-32 overflow-y-auto">
                                                        {decodedAttestation.cabundle && decodedAttestation.cabundle.length > 0 ? (
                                                            decodedAttestation.cabundle.map((cert, idx) => (
                                                                <div key={idx} className="text-xs">
                                                                    <span className="text-gray-500">Cert {idx + 1}:</span>
                                                                    <span className="font-mono text-gray-400 break-all ml-2">{cert.substring(0, 60)}...</span>
                                                                </div>
                                                            ))
                                                        ) : (
                                                            <span className="text-gray-500 text-xs">N/A</span>
                                                        )}
                                                    </div>
                                                </div>

                                                {/* Nonce */}
                                                <div>
                                                    <label className="text-xs font-medium text-gray-400">Nonce</label>
                                                    <p className="mt-1 p-2 bg-[#1a1a1a] rounded border border-gray-800 font-mono text-xs text-gray-400 break-all">
                                                        {decodedAttestation.nonce || 'N/A'}
                                                    </p>
                                                </div>

                                                {/* User Data */}
                                                <div>
                                                    <label className="text-xs font-medium text-gray-400">User Data</label>
                                                    <pre className="mt-1 p-2 bg-[#1a1a1a] rounded border border-gray-800 font-mono text-xs text-gray-400 break-all whitespace-pre-wrap max-h-32 overflow-y-auto">
                                                        {decodedAttestation.user_data
                                                            ? (parsedUserData?.isJson && parsedUserData.jsonData
                                                                ? JSON.stringify(parsedUserData.jsonData, null, 2)
                                                                : parsedUserData?.ethAddr || decodedAttestation.user_data)
                                                            : 'N/A'}
                                                    </pre>
                                                </div>

                                            </div>
                                        </details>
                                    </div>
                                </>
                            ) : (
                                <p className="text-gray-500 text-center py-8">No attestation data available</p>
                            )}
                        </div>
                    )}

                    {/* Request Tab */}
                    {activeTab === 'request' && (
                        <div className="space-y-4">
                            <div>
                                <div className="flex items-center justify-between mb-2">
                                    <label className="text-sm font-medium text-gray-300">Original Request (Plaintext)</label>
                                </div>
                                <pre className="p-3 bg-[#1a1a1a] rounded border border-gray-800 font-mono text-xs text-white overflow-auto max-h-32">
                                    {formatJson(data.decryptedRequest)}
                                </pre>
                            </div>
                            <div>
                                <div className="flex items-center justify-between mb-2">
                                    <label className="text-sm font-medium text-gray-300">Encrypted Request (Sent to Enclave)</label>
                                    <button onClick={() => copyToClipboard(data.encryptedRequest)} className="text-xs text-gray-500 hover:text-white">Copy</button>
                                </div>
                                <pre className="p-3 bg-[#1a1a1a] rounded border border-gray-800 font-mono text-xs text-gray-400 overflow-auto max-h-40 break-all">
                                    {formatJson(data.encryptedRequest)}
                                </pre>
                            </div>
                        </div>
                    )}

                    {/* Response Tab */}
                    {activeTab === 'response' && (
                        <div className="space-y-6">
                            {/* Step 1: Signature Verification */}
                            <div className="border border-gray-800 rounded-lg overflow-hidden">
                                <div className="bg-[#1a1a1a] px-4 py-2 border-b border-gray-800">
                                    <h3 className="text-sm font-medium text-white flex items-center gap-2">
                                        <span className="w-5 h-5 rounded-full bg-primary/20 text-primary text-xs flex items-center justify-center">1</span>
                                        Signature Verification
                                    </h3>
                                </div>
                                <div className="p-4 space-y-3">
                                    <div>
                                        <label className="text-xs font-medium text-gray-400">Raw Response from Enclave</label>
                                        <pre className="mt-1 p-2 bg-[#0a0a0a] rounded font-mono text-xs text-gray-300 overflow-auto max-h-32">
                                            {`{
  "sig": "${data.signature?.substring(0, 32)}...",
  "data": { ... encrypted_envelope }
}`}
                                        </pre>
                                    </div>
                                    <div>
                                        <label className="text-xs font-medium text-gray-400">Signature (EIP-191)</label>
                                        <div className="mt-1 p-2 bg-[#0a0a0a] rounded font-mono text-xs text-primary break-all max-h-20 overflow-y-auto">
                                            {data.signature}
                                        </div>
                                    </div>
                                    <div className="p-3 bg-primary/10 border border-primary/30 rounded-lg flex items-start gap-2">
                                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="h-5 w-5 text-primary flex-shrink-0 mt-0.5">
                                            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                                        </svg>
                                        <div>
                                            <p className="text-sm font-medium text-primary">Signature Verified</p>
                                            <p className="text-xs text-gray-400 mt-0.5">
                                                This signature was created by TEE wallet: <span className="text-primary font-mono">{ethAddr?.substring(0, 10)}...{ethAddr?.substring(ethAddr.length - 8)}</span>
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Step 2: Data Decryption */}
                            <div className="border border-gray-800 rounded-lg overflow-hidden">
                                <div className="bg-[#1a1a1a] px-4 py-2 border-b border-gray-800">
                                    <h3 className="text-sm font-medium text-white flex items-center gap-2">
                                        <span className="w-5 h-5 rounded-full bg-primary/20 text-primary text-xs flex items-center justify-center">2</span>
                                        Data Decryption
                                    </h3>
                                </div>
                                <div className="p-4 space-y-3">
                                    <div>
                                        <div className="flex items-center justify-between">
                                            <label className="text-xs font-medium text-gray-400">Encrypted Data (from enclave)</label>
                                            <button onClick={() => copyToClipboard(data.encryptedResponse)} className="text-xs text-gray-500 hover:text-white">Copy</button>
                                        </div>
                                        <pre className="mt-1 p-2 bg-[#0a0a0a] rounded font-mono text-xs text-gray-400 overflow-auto max-h-24 break-all">
                                            {formatJson(data.encryptedResponse)}
                                        </pre>
                                    </div>
                                    <div className="flex items-center justify-center py-2">
                                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor" className="h-5 w-5 text-gray-600">
                                            <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 13.5 12 21m0 0-7.5-7.5M12 21V3" />
                                        </svg>
                                        <span className="ml-2 text-xs text-gray-600">AES-256-GCM Decryption</span>
                                    </div>
                                    <div>
                                        <label className="text-xs font-medium text-gray-400">Decrypted Response</label>
                                        <pre className="mt-1 p-2 bg-[#0a0a0a] rounded font-mono text-xs text-white overflow-auto max-h-40">
                                            {formatJson(data.decryptedResponse)}
                                        </pre>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
