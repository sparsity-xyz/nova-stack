import React, { useState, useEffect } from 'react';
import { decodeAttestationDoc, parseUserData } from '../lib/attestation';
import { ShieldCheck, Copy, X, ExternalLink, Calendar, Cpu, Key, FileText, ChevronDown } from 'lucide-react';

export default function VerificationDialog({ isOpen, onClose, data }) {
    const [decodedAttestation, setDecodedAttestation] = useState(null);
    const [attestationLoading, setAttestationLoading] = useState(false);
    const [attestationError, setAttestationError] = useState(null);

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

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
    };

    // Parse user_data to get eth_addr
    const parsedUserData = decodedAttestation?.user_data ? parseUserData(decodedAttestation.user_data) : null;
    const ethAddr = data.ethAddr || parsedUserData?.ethAddr || 'Unknown';

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            {/* Backdrop */}
            <div className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm" onClick={onClose} />

            {/* Dialog */}
            <div className="relative bg-slate-900 border border-slate-800 rounded-3xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b border-slate-800">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-blue-600/20 rounded-lg">
                            <ShieldCheck className="h-6 w-6 text-blue-500" />
                        </div>
                        <div>
                            <h2 className="text-xl font-bold text-white">TEE Verification Details</h2>
                            <p className="text-sm text-slate-400">Cryptographic proof of enclave authenticity</p>
                        </div>
                    </div>
                    <button onClick={onClose} className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-xl transition-all">
                        <X className="h-6 w-6" />
                    </button>
                </div>

                {/* Content */}
                <div className="p-6 overflow-y-auto custom-scrollbar">
                    {attestationLoading ? (
                        <div className="flex flex-col items-center justify-center py-12">
                            <div className="w-10 h-10 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
                            <span className="mt-4 text-slate-400 font-medium">Decoding attestation document...</span>
                        </div>
                    ) : attestationError ? (
                        <div className="p-4 bg-red-900/20 border border-red-500/50 rounded-2xl text-red-400 text-sm flex items-center gap-3">
                            <div className="p-2 bg-red-500/20 rounded-lg">
                                <X className="h-5 w-5" />
                            </div>
                            {attestationError}
                        </div>
                    ) : decodedAttestation ? (
                        <div className="space-y-6">
                            {/* Key Identity Info */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div className="p-4 bg-slate-800/50 border border-slate-700/50 rounded-2xl">
                                    <div className="flex items-center gap-2 text-slate-400 text-xs font-mono uppercase tracking-widest mb-2">
                                        <Key className="h-3 w-3" />
                                        Enclave ETH Address
                                    </div>
                                    <div className="flex items-center justify-between gap-2">
                                        <span className="font-mono text-blue-400 text-sm break-all">{ethAddr}</span>
                                        <button onClick={() => copyToClipboard(ethAddr)} className="p-1.5 hover:bg-white/10 rounded-lg transition-colors text-slate-500 hover:text-white">
                                            <Copy className="h-4 w-4" />
                                        </button>
                                    </div>
                                </div>
                                <div className="p-4 bg-slate-800/50 border border-slate-700/50 rounded-2xl">
                                    <div className="flex items-center gap-2 text-slate-400 text-xs font-mono uppercase tracking-widest mb-2">
                                        <Calendar className="h-3 w-3" />
                                        Attestation Time
                                    </div>
                                    <div className="text-white font-medium">
                                        {decodedAttestation.timestamp ? new Date(decodedAttestation.timestamp).toLocaleString() : 'N/A'}
                                    </div>
                                </div>
                            </div>

                            {/* PCR Values */}
                            <div className="p-6 bg-slate-950/50 border border-slate-800 rounded-2xl">
                                <h3 className="text-sm font-bold text-slate-300 flex items-center gap-2 mb-4">
                                    <Cpu className="h-4 w-4 text-blue-500" />
                                    Security Measurements (PCRs)
                                </h3>
                                <div className="space-y-3">
                                    {[0, 1, 2, 3, 4].map(idx => (
                                        <div key={idx} className="flex flex-col gap-1">
                                            <div className="flex items-center justify-between">
                                                <span className="text-[10px] font-black text-slate-500 uppercase tracking-tighter">PCR {idx}</span>
                                                <span className="text-[10px] text-slate-600 font-mono">
                                                    {idx === 0 ? 'Image Hash' : idx === 1 ? 'Kernel' : idx === 2 ? 'App' : idx === 3 ? 'IAM Role' : 'Instance ID'}
                                                </span>
                                            </div>
                                            <div className="p-2 bg-black/40 rounded-lg border border-white/5 font-mono text-[11px] text-slate-300 break-all leading-relaxed">
                                                {decodedAttestation.pcrs?.[idx] || '0'.repeat(96)}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Technical Details Accordion */}
                            <div className="border border-slate-800 rounded-2xl overflow-hidden">
                                <details className="group">
                                    <summary className="p-4 bg-slate-800/30 cursor-pointer flex items-center justify-between hover:bg-slate-800/50 transition-colors list-none">
                                        <div className="flex items-center gap-2">
                                            <FileText className="h-4 w-4 text-slate-400" />
                                            <span className="text-sm font-bold text-slate-300">Raw Attestation Details</span>
                                        </div>
                                        <ChevronDown className="h-4 w-4 text-slate-500 group-open:rotate-180 transition-transform" />
                                    </summary>
                                    <div className="p-4 bg-slate-950/30 space-y-4">
                                        <div className="grid grid-cols-1 gap-4">
                                            <div>
                                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-tighter block mb-1">Public Key (Enclaver Internal)</label>
                                                <div className="p-2 bg-black/40 rounded-lg font-mono text-[10px] text-blue-400 break-all max-h-24 overflow-y-auto">
                                                    {decodedAttestation.public_key || 'N/A'}
                                                </div>
                                            </div>
                                            <div>
                                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-tighter block mb-1">User Data (Internal State)</label>
                                                <div className="p-2 bg-black/40 rounded-lg font-mono text-[10px] text-slate-400 break-all">
                                                    {decodedAttestation.user_data || 'N/A'}
                                                </div>
                                            </div>
                                            <div>
                                                <label className="text-[10px] font-black text-slate-500 uppercase tracking-tighter block mb-1">Signature</label>
                                                <div className="p-2 bg-black/40 rounded-lg font-mono text-[10px] text-slate-500 break-all">
                                                    {decodedAttestation.signature || 'N/A'}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </details>
                            </div>
                        </div>
                    ) : (
                        <div className="flex flex-col items-center justify-center py-12 text-slate-500">
                            <ShieldCheck className="h-12 w-12 opacity-20 mb-4" />
                            <p>No attestation data available</p>
                        </div>
                    )}
                </div>

                {/* Footer */}
                <div className="p-6 border-t border-slate-800 bg-slate-900/50 flex justify-between items-center">
                    <a
                        href="https://docs.aws.amazon.com/enclaves/latest/userguide/set-up-attestation.html"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-blue-500 hover:text-blue-400 flex items-center gap-1 font-medium"
                    >
                        What is Nitro Attestation?
                        <ExternalLink className="h-3 w-3" />
                    </a>
                    <button
                        onClick={onClose}
                        className="px-6 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-sm font-bold transition-all"
                    >
                        Close
                    </button>
                </div>
            </div>
        </div>
    );
}
