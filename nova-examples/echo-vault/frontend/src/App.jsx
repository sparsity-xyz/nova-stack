import React, { useState, useEffect } from 'react'
import {
  ShieldCheck,
  Wallet,
  ArrowLeftRight,
  RotateCcw,
  ExternalLink,
  Lock,
  Zap,
  Copy,
  Check
} from 'lucide-react'
import clsx from 'clsx'
import VerificationDialog from './components/VerificationDialog'

const POLL_INTERVAL = 5000 // 5 seconds

// Support overriding API base URL for local development (e.g. VITE_API_URL=http://localhost:8000)
// For TEE deployment, relative paths are preferred as the domain is dynamic.
const API_BASE = import.meta.env.VITE_API_URL || '';

const getUrl = (path) => `${API_BASE}${path}`;

function App() {
  const [status, setStatus] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showAttestation, setShowAttestation] = useState(false)
  const [attestationData, setAttestationData] = useState(null)
  const [copied, setCopied] = useState(false)

  const copyToClipboard = () => {
    if (!status?.address) return
    navigator.clipboard.writeText(status.address)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const fetchData = async () => {
    try {
      const [statusRes, historyRes] = await Promise.all([
        fetch(getUrl('/api/status')),
        fetch(getUrl('/api/history'))
      ])

      if (!statusRes.ok || !historyRes.ok) throw new Error('Failed to fetch data')

      const statusData = await statusRes.json()
      const historyData = await historyRes.json()

      setStatus(statusData)
      setHistory(historyData)
      setError(null)
    } catch (err) {
      console.error(err)
      setError('Enclave API unreachable. Is the enclave running?')
    } finally {
      setLoading(false)
    }
  }

  const fetchAttestation = async () => {
    try {
      // Try local dev port first, fallback to app endpoint
      // In production, Caddy might handle port 80/.well-known/attestation
      let res;
      try {
        res = await fetch(getUrl('/.well-known/attestation'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({})
        })
      } catch (e) {
        // Fallback or retry logic if needed
        throw e;
      }

      if (!res.ok) throw new Error('Failed to fetch attestation')

      const buffer = await res.arrayBuffer()
      const base64Attestation = btoa(
        new Uint8Array(buffer).reduce((data, byte) => data + String.fromCharCode(byte), '')
      )

      setAttestationData({
        attestation: base64Attestation,
        ethAddr: status?.address,
        publicKey: 'Enclaver Internal' // Placeholder or fetch if available
      })
      setShowAttestation(true)
    } catch (err) {
      console.error(err)
      alert('Failed to fetch attestation. Ensure you are running in an environment that supports it.')
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, POLL_INTERVAL)
    return () => clearInterval(interval)
  }, [])

  const formatEth = (wei) => {
    if (!wei) return '0.00'
    return (parseFloat(wei) / 1e18).toFixed(6)
  }

  const shortenAddr = (addr) => {
    if (!addr) return '...'
    return `${addr.slice(0, 6)}...${addr.slice(-4)}`
  }

  const formatTime = (ts) => {
    if (!ts) return '...'
    return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  }

  if (loading && !status) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-slate-950 text-white">
        <div className="flex flex-col items-center gap-4">
          <RotateCcw className="w-10 h-10 animate-spin text-blue-500" />
          <p className="text-slate-400 font-medium font-mono">Initializing Echo Vault Enclave...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="w-full max-w-5xl px-6 py-12 mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-12">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-blue-600 rounded-2xl shadow-lg shadow-blue-900/20">
            <Lock className="w-8 h-8 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white tracking-tight">Echo Vault</h1>
            <p className="text-slate-400 font-medium">Deterministic TEE-Backed ETH Echo Service</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="px-4 py-2 bg-slate-900 border border-slate-800 rounded-full flex items-center gap-2">
            <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
            <span className="text-sm font-semibold text-slate-300 font-mono">Base Sepolia</span>
          </div>
          <button
            onClick={fetchAttestation}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-full text-sm font-bold transition-all transform active:scale-95 shadow-lg shadow-blue-900/20"
          >
            <ShieldCheck className="w-4 h-4" />
            Verify TEE
          </button>
        </div>
      </div>

      {error && (
        <div className="mb-8 p-4 bg-red-900/20 border border-red-500/50 rounded-xl text-red-400 flex items-center gap-3">
          <Zap className="w-5 h-5" />
          <p className="font-medium">{error}</p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
        {/* Wallet Card */}
        <div className="lg:col-span-2 bg-slate-900/50 border border-slate-800 rounded-3xl p-8 backdrop-blur-xl relative overflow-hidden group">
          <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-10 transition-opacity">
            <Wallet className="w-32 h-32 text-white" />
          </div>

          <div className="relative">
            <div className="flex items-center gap-2 text-slate-400 mb-2 font-mono text-sm uppercase tracking-widest">
              <Wallet className="w-4 h-4" />
              Vault Wallet Address
            </div>
            <div className="flex items-center gap-3 mb-8">
              <div className="text-xl font-bold text-white font-mono break-all leading-tight">
                {status?.address}
              </div>
              <button
                onClick={copyToClipboard}
                className="p-2 hover:bg-white/10 rounded-lg transition-colors text-slate-500 hover:text-white"
                title="Copy Address"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>

            <div className="flex flex-col md:flex-row gap-8">
              <div>
                <div className="text-slate-400 text-sm font-mono uppercase tracking-widest mb-1">Current Balance</div>
                <div className="text-4xl font-black text-white flex items-baseline gap-2">
                  {formatEth(status?.balance)} <span className="text-xl text-slate-500 font-bold uppercase">ETH</span>
                </div>
              </div>
              <div className="md:border-l md:border-slate-800 md:pl-8">
                <div className="text-slate-400 text-sm font-mono uppercase tracking-widest mb-1">Processed</div>
                <div className="text-4xl font-black text-white">
                  {status?.processed_count || 0}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Sync Status Card */}
        <div className="bg-gradient-to-br from-blue-600 to-indigo-700 rounded-3xl p-8 text-white shadow-2xl shadow-blue-900/40 relative overflow-hidden">
          <div className="absolute bottom-0 left-0 w-full h-1/2 bg-white/5 skew-y-12 translate-y-8" />
          <div className="relative">
            <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
              <RotateCcw className="w-5 h-5" />
              Sync Status
            </h3>
            <div className="space-y-4">
              <div>
                <div className="text-blue-100/60 text-xs font-mono uppercase tracking-widest mb-1">Last Polled Block</div>
                <div className="text-2xl font-bold font-mono tracking-wider">{status?.last_block || '...'}</div>
              </div>
              <div>
                <div className="text-blue-100/60 text-xs font-mono uppercase tracking-widest mb-1 flex items-center justify-between">
                  <span>Persisted Block (S3)</span>
                  {status?.last_block === status?.persisted_block && status?.last_block > 0 && (
                    <span className="text-[10px] bg-emerald-400 text-emerald-950 px-1.5 py-0.5 rounded font-black uppercase tracking-tighter">Synced</span>
                  )}
                </div>
                <div className="text-2xl font-bold font-mono tracking-wider">{status?.persisted_block || '...'}</div>
              </div>
              <div>
                <div className="text-blue-100/60 text-xs font-mono uppercase tracking-widest mb-1">Pending Echoes</div>
                <div className={clsx(
                  "text-2xl font-bold font-mono tracking-wider",
                  status?.pending_count > 0 ? "text-yellow-400" : "text-white"
                )}>
                  {status?.pending_count || 0}
                </div>
              </div>
              <div>
                <div className="text-blue-100/60 text-xs font-mono uppercase tracking-widest mb-1">Network State</div>
                <div className="px-3 py-1 bg-white/10 rounded-lg inline-block text-sm font-bold border border-white/10 uppercase tracking-widest">
                  Trustless (Helios)
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* History */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-3xl overflow-hidden backdrop-blur-xl">
        <div className="px-8 py-6 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
          <h2 className="text-xl font-bold text-white flex items-center gap-3">
            <ArrowLeftRight className="w-6 h-6 text-blue-500" />
            Echo Activity Log
          </h2>
          <span className="text-slate-500 font-mono text-sm tracking-widest">REAL-TIME</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="text-slate-500 font-mono text-xs uppercase tracking-widest">
              <tr>
                <th className="px-8 py-4 font-bold border-b border-slate-800/50">Incoming Tx</th>
                <th className="px-8 py-4 font-bold border-b border-slate-800/50">Time</th>
                <th className="px-8 py-4 font-bold border-b border-slate-800/50">Amount Received</th>
                <th className="px-8 py-4 font-bold border-b border-slate-800/50">Echo Tx</th>
                <th className="px-8 py-4 font-bold border-b border-slate-800/50">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {history.length === 0 ? (
                <tr>
                  <td colSpan="5" className="px-8 py-12 text-center text-slate-500 font-medium">
                    No transactions detected yet. Send some ETH to the vault!
                  </td>
                </tr>
              ) : (
                history.map((event, i) => (
                  <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-8 py-6">
                      <div className="font-mono text-blue-400 font-bold flex items-center gap-2">
                        {shortenAddr(event.incoming_hash)}
                        <a href={`https://sepolia.basescan.org/tx/${event.incoming_hash}`} target="_blank" className="hover:text-white">
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                      <div className="text-xs text-slate-500 font-medium">From: {shortenAddr(event.from)}</div>
                    </td>
                    <td className="px-8 py-6">
                      <div className="text-white font-mono text-sm">{formatTime(event.timestamp)}</div>
                    </td>
                    <td className="px-8 py-6">
                      <div className="text-white font-black">{formatEth(event.value)} <span className="text-slate-500">ETH</span></div>
                    </td>
                    <td className="px-8 py-6">
                      {event.echo_hash ? (
                        <div className="font-mono text-emerald-400 font-bold flex items-center gap-2">
                          {shortenAddr(event.echo_hash)}
                          <a href={`https://sepolia.basescan.org/tx/${event.echo_hash}`} target="_blank" className="hover:text-white">
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        </div>
                      ) : (
                        <span className="text-slate-600">---</span>
                      )}
                      <div className="text-xs text-slate-500 font-medium">
                        {event.status === 'success' ? (
                          <div className="flex flex-col">
                            <span>Sent: {formatEth(event.echo_value)} ETH</span>
                            {event.gas_fee && (
                              <span className="text-[10px] text-slate-500 font-medium">
                                Fee: {formatEth(event.gas_fee)} ETH
                              </span>
                            )}
                          </div>
                        ) : (
                          <div className="flex flex-col">
                            <span>{event.echo_value}</span>
                            {event.status === 'skipped' && event.gas_fee && (
                              <span className="text-[10px] text-slate-500 font-medium">
                                Est. Fee: {formatEth(event.gas_fee)} ETH
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-8 py-6">
                      <span className={clsx(
                        "px-3 py-1 rounded-full text-xs font-bold tracking-widest uppercase",
                        event.status === 'success' && "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20",
                        event.status === 'failed' && "bg-red-500/10 text-red-500 border border-red-500/20",
                        event.status === 'received' && "bg-blue-500/10 text-blue-500 border border-blue-500/20",
                        event.status === 'processing' && "bg-amber-500/10 text-amber-500 border border-amber-500/20 animate-pulse",
                        event.status === 'skipped' && "bg-slate-500/10 text-slate-500 border border-slate-500/20"
                      )}>
                        {event.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <VerificationDialog
        isOpen={showAttestation}
        onClose={() => setShowAttestation(false)}
        data={attestationData}
      />
    </div>
  )
}

export default App
