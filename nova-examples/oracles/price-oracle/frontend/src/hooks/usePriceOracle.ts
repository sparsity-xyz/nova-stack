import { useState, useEffect, useCallback } from 'react'
import { ethers } from 'ethers'
import { CONTRACT_ADDRESS, CONTRACT_ABI, RPC_URL } from '../config/contract'

export interface PriceData {
  price: number
  timestamp: number
}

export function usePriceOracle() {
  const [price, setPrice] = useState<number | null>(null)
  const [lastUpdated, setLastUpdated] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [priceHistory, setPriceHistory] = useState<PriceData[]>([])

  const fetchPrice = useCallback(async () => {
    try {
      setLoading(true)
      
      // 创建只读的 provider
      const provider = new ethers.JsonRpcProvider(RPC_URL)
      const contract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, provider)

      // 读取价格和最后更新时间
      const [btcPrice, timestamp] = await Promise.all([
        contract.btcPrice(),
        contract.lastUpdated(),
      ])

      const priceValue = Number(btcPrice) / 100 // Convert from cents to dollars
      const timestampValue = Number(timestamp)

      setPrice(priceValue)
      setLastUpdated(timestampValue)

      // Add to history if price changed
      if (priceValue > 0) {
        setPriceHistory((prev: PriceData[]) => {
          const newHistory = [...prev, { price: priceValue, timestamp: timestampValue }]
          // Keep only last 50 entries
          return newHistory.slice(-50)
        })
      }
    } catch (error) {
      console.error('Error fetching price:', error)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchPrice()
    
    // 监听 PriceUpdated 事件
    const provider = new ethers.JsonRpcProvider(RPC_URL)
    const contract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, provider)
    
    const handlePriceUpdate = (newPrice: bigint, timestamp: bigint) => {
      console.log('New price update event:', newPrice, timestamp)
      fetchPrice()
    }
    
    contract.on('PriceUpdated', handlePriceUpdate)
    
    return () => {
      contract.off('PriceUpdated', handlePriceUpdate)
    }
  }, [fetchPrice])

  return {
    price,
    lastUpdated,
    loading,
    priceHistory,
    refetch: fetchPrice,
  }
}
