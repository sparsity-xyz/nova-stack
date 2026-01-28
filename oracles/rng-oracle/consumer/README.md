# Sparsity RNG Frontend

A React.js frontend application for interacting with the Random Number Generator smart contract on the Sparsity Nova Platform.

## Features

- **Wallet Connection**: Connect with MetaMask or any Web3 wallet
- **Configurable Contract**: Set custom RNG contract address
- **Random Number Requests**: Request random numbers with configurable min/max range
- **Real-time Events**: Live monitoring of all contract events
- **Result Display**: Track your requests and view fulfilled random numbers

## Quick Start

### Install Dependencies

```bash
npm install
```

### Development

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Build for Production

```bash
npm run build
```

## Usage

1. **Connect Wallet**: Click "Connect Wallet" and approve in MetaMask
2. **Switch Network**: If prompted, switch to Base Sepolia network
3. **Set Contract Address**: Enter the RNG contract address (or use default)
4. **Request Random Number**: Set min/max values and click "Request Random Number"
5. **View Results**: See your request in "Your Results" and watch for fulfillment
6. **Monitor Events**: All contract events appear in the "RNG Contract Events" section

## Project Structure

```
src/
├── components/
│   ├── WalletConnect.jsx    # Wallet connection UI
│   ├── RequestForm.jsx      # Random number request form
│   ├── EventLog.jsx         # Real-time event display
│   └── ResultDisplay.jsx    # User's request results
├── hooks/
│   ├── useWallet.js         # Wallet connection hook
│   └── useRngContract.js    # Contract interaction hook
├── utils/
│   ├── abi.js               # Contract ABI definitions
│   └── constants.js         # App constants
├── App.jsx                  # Main application
├── App.css                  # Main styles
└── index.css                # Global styles
```

## Technology Stack

- **React 18** - UI framework
- **Vite** - Build tool
- **ethers.js v5** - Ethereum interaction
- **CSS3** - Styling with CSS variables

## Contract Interface

The app interacts with `RandomNumberGenerator` contract using:

- `requestRandomRange(min, max, count)` - Request random numbers
- `getRequest(requestId)` - Query request status
- `RandomNumberRequested` event - Emitted on new requests
- `RandomNumberFulfilled` event - Emitted when random numbers are generated

## License

Apache-2.0
