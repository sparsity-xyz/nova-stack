import { usePriceOracle } from '../hooks/usePriceOracle'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { format } from 'date-fns'
import { BarChart3 } from 'lucide-react'

export default function PriceChart() {
  const { priceHistory } = usePriceOracle()

  const chartData = priceHistory.map(({ price, timestamp }) => ({
    time: format(new Date(timestamp * 1000), 'HH:mm:ss'),
    price: price,
  }))

  return (
    <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-8 border border-gray-700 shadow-xl">
      <div className="flex items-center space-x-2 mb-6">
        <BarChart3 className="w-6 h-6 text-primary" />
        <h2 className="text-xl font-semibold text-gray-200">Price History</h2>
      </div>

      {chartData.length > 0 ? (
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis 
              dataKey="time" 
              stroke="#9ca3af"
              style={{ fontSize: '12px' }}
            />
            <YAxis 
              stroke="#9ca3af"
              style={{ fontSize: '12px' }}
              domain={['auto', 'auto']}
              tickFormatter={(value) => `$${value.toLocaleString()}`}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1e293b',
                border: '1px solid #374151',
                borderRadius: '8px',
                color: '#fff',
              }}
              formatter={(value: number) => [`$${value.toLocaleString()}`, 'Price']}
            />
            <Line
              type="monotone"
              dataKey="price"
              stroke="#f7931a"
              strokeWidth={2}
              dot={{ fill: '#f7931a', r: 4 }}
              activeDot={{ r: 6 }}
            />
          </LineChart>
        </ResponsiveContainer>
      ) : (
        <div className="h-[300px] flex items-center justify-center text-gray-400">
          <p>No price history available yet</p>
        </div>
      )}
    </div>
  )
}
