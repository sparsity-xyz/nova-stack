import { useState, useEffect } from 'react'
import { ethers } from 'ethers'
import { CONTRACT_ADDRESS, CONTRACT_ABI, RPC_URL, EXPLORER_URL } from '../config/contract'
import { FileText, ExternalLink, Shield, User } from 'lucide-react'
import { format } from 'date-fns'

interface ContractInfoProps {
  price: number | null
  lastUpdated: number | null
}

export default function ContractInfo({ price, lastUpdated }: ContractInfoProps) {
  const [owner, setOwner] = useState<string>('')
  const [oracle, setOracle] = useState<string>('')

  useEffect(() => {
    async function fetchContractInfo() {
      try {
        const provider = new ethers.JsonRpcProvider(RPC_URL)
        const contract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, provider)

        const [ownerAddr, oracleAddr] = await Promise.all([
          contract.owner(),
          contract.oracle(),
        ])

        setOwner(ownerAddr)
        setOracle(oracleAddr)
      } catch (error) {
        console.error('Error fetching contract info:', error)
      }
    }

    fetchContractInfo()
  }, [])

  const explorerUrl = `${EXPLORER_URL}/address/${CONTRACT_ADDRESS}`

  return (
    <div className="space-y-6">
      {/* Contract Details */}
      <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-gray-700 shadow-xl">
        <div className="flex items-center space-x-2 mb-4">
          <FileText className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-semibold text-gray-200">Contract Details</h3>
        </div>

        <div className="space-y-4">
          <div>
            <p className="text-xs text-gray-400 mb-1">Contract Address</p>
            <div className="flex items-center justify-between bg-slate-900/50 rounded-lg p-3 gap-2">
              <span className="text-xs text-white font-mono break-all">{CONTRACT_ADDRESS}</span>
              <a
                href={explorerUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:text-primary/80 transition-colors flex-shrink-0"
              >
                <ExternalLink className="w-4 h-4" />
              </a>
            </div>
          </div>

          {owner && (
            <div>
              <div className="flex items-center space-x-1 mb-1">
                <User className="w-3 h-3 text-gray-400" />
                <p className="text-xs text-gray-400">Owner</p>
              </div>
              <div className="bg-slate-900/50 rounded-lg p-3">
                <span className="text-xs text-white font-mono break-all">{owner}</span>
              </div>
            </div>
          )}

          {oracle && (
            <div>
              <div className="flex items-center space-x-1 mb-1">
                <Shield className="w-3 h-3 text-gray-400" />
                <p className="text-xs text-gray-400">Oracle</p>
              </div>
              <div className="bg-slate-900/50 rounded-lg p-3">
                <span className="text-xs text-white font-mono break-all">{oracle}</span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Stats Card */}
      <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-gray-700 shadow-xl">
        <h3 className="text-lg font-semibold text-gray-200 mb-4">Statistics</h3>
        
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <span className="text-gray-400 text-sm">Current Price</span>
            <span className="text-white font-semibold">
              {price !== null 
                ? new Intl.NumberFormat('en-US', {
                    style: 'currency',
                    currency: 'USD',
                  }).format(price)
                : 'N/A'}
            </span>
          </div>

          <div className="flex justify-between items-center">
            <span className="text-gray-400 text-sm">Last Update</span>
            <span className="text-white font-semibold">
              {lastUpdated 
                ? format(new Date(lastUpdated * 1000), 'MMM dd, HH:mm')
                : 'N/A'}
            </span>
          </div>

          <div className="flex justify-between items-center">
            <span className="text-gray-400 text-sm">Data Source</span>
            <span className="text-primary font-semibold">
              CoinGecko
            </span>
          </div>
        </div>
      </div>

      {/* Info Card - 与 Price History 对齐 */}
      <div className="bg-gradient-to-br from-primary/10 to-purple-500/10 backdrop-blur-sm rounded-2xl p-6 border border-primary/20 shadow-xl">
        <h3 className="text-lg font-semibold text-white mb-3">About</h3>
        <p className="text-gray-300 text-sm leading-relaxed">
          This price oracle is powered by Sparsity Nova, a TEE-based execution environment. 
          The BTC price is fetched from CoinGecko and updated on-chain every 5 minutes, 
          ensuring reliable and tamper-proof price data.
        </p>
      </div>
    </div>
  )
}
