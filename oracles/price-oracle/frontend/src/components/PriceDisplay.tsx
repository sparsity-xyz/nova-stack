import { formatDistanceToNow } from 'date-fns'
import { TrendingUp, Clock, RefreshCw } from 'lucide-react'
import { CHAIN_NAME, CHAIN_ID } from '../config/contract'

interface PriceDisplayProps {
  price: number | null
  lastUpdated: number | null
  loading: boolean
}

export default function PriceDisplay({ price, lastUpdated, loading }: PriceDisplayProps) {
  const formatPrice = (price: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(price)
  }

  const getTimeAgo = (timestamp: number) => {
    if (!timestamp) return 'Never'
    return formatDistanceToNow(new Date(timestamp * 1000), { addSuffix: true })
  }

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-8 border border-gray-700 shadow-xl">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-2">
          <TrendingUp className="w-6 h-6 text-primary" />
          <h2 className="text-xl font-semibold text-gray-200">Current BTC Price</h2>
        </div>
        {loading && <RefreshCw className="w-5 h-5 text-primary animate-spin" />}
      </div>

      <div className="space-y-6">
        <div>
          {loading && price === null ? (
            <div className="flex items-center space-x-2">
              <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin" />
              <span className="text-gray-400">Loading price...</span>
            </div>
          ) : (
            <div className="text-4xl font-bold text-white">
              {price !== null ? formatPrice(price) : '$0.00'}
            </div>
          )}
        </div>

        <div className="flex items-center space-x-2 text-gray-400">
          <Clock className="w-4 h-4" />
          <span className="text-sm">
            Last updated: {lastUpdated ? getTimeAgo(lastUpdated) : 'Never'}
          </span>
        </div>

        <div className="pt-4 border-t border-gray-700">
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <p className="text-gray-400">Network</p>
              <p className="text-white font-semibold">{CHAIN_NAME}</p>
            </div>
            <div>
              <p className="text-gray-400">Chain ID</p>
              <p className="text-white font-semibold">{CHAIN_ID}</p>
            </div>
            <div>
              <p className="text-gray-400">Source</p>
              <p className="text-white font-semibold">CoinGecko</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
