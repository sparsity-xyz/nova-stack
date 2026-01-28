import { useEffect } from 'react'
import PriceDisplay from './components/PriceDisplay'
import PriceChart from './components/PriceChart'
import ContractInfo from './components/ContractInfo'
import { usePriceOracle } from './hooks/usePriceOracle'
import { Bitcoin } from 'lucide-react'

function App() {
  const { price, lastUpdated, loading, refetch } = usePriceOracle()

  useEffect(() => {
    // 每30秒自动刷新价格
    const interval = setInterval(() => {
      refetch()
    }, 30000)

    return () => clearInterval(interval)
  }, [refetch])

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Header */}
      <header className="border-b border-gray-800 bg-slate-900/50 backdrop-blur-sm">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-center">
            <div className="flex items-center space-x-3">
              <Bitcoin className="w-8 h-8 text-primary" />
              <h1 className="text-2xl font-bold text-white">
                BTC Price Oracle
              </h1>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Price Display */}
          <div className="lg:col-span-2 space-y-6">
            <PriceDisplay 
              price={price} 
              lastUpdated={lastUpdated} 
              loading={loading}
            />
            <PriceChart />
          </div>

          {/* Right Column - Contract Info & Stats */}
          <div className="space-y-6">
            <ContractInfo 
              price={price}
              lastUpdated={lastUpdated}
            />
          </div>
        </div>

        {/* Footer Info */}
        <div className="mt-12 text-center">
          <div className="inline-block bg-slate-800/50 backdrop-blur-sm rounded-lg px-6 py-4 border border-gray-700">
            <p className="text-gray-400 text-sm">
              Powered by{' '}
              <span className="text-primary font-semibold">Sparsity Nova</span>
              {' '}• Price data from{' '}
              <span className="text-primary font-semibold">CoinGecko</span>
            </p>
          </div>
        </div>
      </main>
    </div>
  )
}

export default App
