// 从环境变量读取配置，如果没有则使用默认值
export const CONTRACT_ADDRESS = import.meta.env.VITE_CONTRACT_ADDRESS || '0x00061d46a5d05f1abdec7ea05894e602083682e9'
export const CHAIN_ID = parseInt(import.meta.env.VITE_CHAIN_ID || '84532')
export const CHAIN_NAME = import.meta.env.VITE_CHAIN_NAME || 'Base Sepolia'
export const RPC_URL = import.meta.env.VITE_RPC_URL || 'https://sepolia.base.org'
export const EXPLORER_URL = import.meta.env.VITE_EXPLORER_URL || 'https://sepolia.basescan.org'

export const CONTRACT_ABI = [
  {
    inputs: [{ name: '_price', type: 'uint256' }],
    name: 'setPrice',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [],
    name: 'getPrice',
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'btcPrice',
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'lastUpdated',
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'oracle',
    outputs: [{ name: '', type: 'address' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    inputs: [],
    name: 'owner',
    outputs: [{ name: '', type: 'address' }],
    stateMutability: 'view',
    type: 'function',
  },
  {
    anonymous: false,
    inputs: [
      { indexed: false, name: 'newPrice', type: 'uint256' },
      { indexed: false, name: 'timestamp', type: 'uint256' },
    ],
    name: 'PriceUpdated',
    type: 'event',
  },
] as const
