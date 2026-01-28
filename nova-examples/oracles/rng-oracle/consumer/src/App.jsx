import { useState, useCallback } from 'react';
import { useWallet } from './hooks/useWallet';
import { useRngContract } from './hooks/useRngContract';
import { WalletConnect } from './components/WalletConnect';
import { RequestForm } from './components/RequestForm';
import { EventLog } from './components/EventLog';
import { ResultDisplay } from './components/ResultDisplay';
import { DEFAULT_RNG_ADDRESS } from './utils/constants';
import './App.css';

function App() {
  const [rngAddress, setRngAddress] = useState(
    localStorage.getItem('rngAddress') || DEFAULT_RNG_ADDRESS
  );
  const [addressInput, setAddressInput] = useState(rngAddress);
  const [statusMessage, setStatusMessage] = useState(null);

  const {
    provider,
    signer,
    address,
    shortenedAddress,
    isConnected,
    isConnecting,
    isCorrectNetwork,
    connect,
    disconnect,
    switchNetwork
  } = useWallet();

  const {
    events,
    userRequests,
    isLoading,
    error: contractError,
    requestRandom,
    clearEvents
  } = useRngContract(rngAddress, provider, signer);

  // Handle address save
  const handleSaveAddress = useCallback(() => {
    setRngAddress(addressInput);
    localStorage.setItem('rngAddress', addressInput);
    setStatusMessage({ type: 'success', text: 'Contract address saved!' });
    setTimeout(() => setStatusMessage(null), 3000);
  }, [addressInput]);

  // Handle random number request
  const handleRequest = useCallback(async (min, max) => {
    setStatusMessage(null);
    const requestId = await requestRandom(min, max, address);

    if (requestId) {
      setStatusMessage({
        type: 'success',
        text: `Request #${requestId} submitted! Waiting for random number...`
      });
    }
  }, [requestRandom, address]);

  // Show contract error in status
  const displayMessage = statusMessage || (contractError ? { type: 'error', text: contractError } : null);

  return (
    <div className="app">
      {/* Background gradient */}
      <div className="bg-gradient"></div>

      {/* Header */}
      <header className="header">
        <div className="header-content">
          <div className="logo">
            <span className="logo-icon">🎲</span>
            <h1>Sparsity RNG Demo Consumer</h1>
          </div>
          <WalletConnect
            isConnected={isConnected}
            isConnecting={isConnecting}
            isCorrectNetwork={isCorrectNetwork}
            shortenedAddress={shortenedAddress}
            onConnect={connect}
            onDisconnect={disconnect}
            onSwitchNetwork={switchNetwork}
          />
        </div>
      </header>

      {/* Main content */}
      <main className="main">
        {/* Contract address section */}
        <section className="address-section">
          <div className="address-card">
            <label htmlFor="rng-address">RNG Contract Address</label>
            <div className="address-input-group">
              <input
                id="rng-address"
                type="text"
                value={addressInput}
                onChange={(e) => setAddressInput(e.target.value)}
                placeholder="0x..."
                className="address-input"
              />
              <button
                className="save-btn"
                onClick={handleSaveAddress}
                disabled={addressInput === rngAddress}
              >
                Save
              </button>
              <a
                className="view-btn"
                href={`https://sepolia.basescan.org/address/${rngAddress}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                View Contract ↗
              </a>
            </div>
          </div>
        </section>

        {/* Status message */}
        {displayMessage && (
          <div className={`status-message ${displayMessage.type}`}>
            {displayMessage.type === 'success' ? '✅' : '❌'} {displayMessage.text}
          </div>
        )}

        {/* Request form and Results row */}
        <section className="grid-section">
          <div className="grid-column">
            <RequestForm
              isConnected={isConnected}
              isCorrectNetwork={isCorrectNetwork}
              isLoading={isLoading}
              onSubmit={handleRequest}
            />
          </div>
          <div className="grid-column">
            <ResultDisplay
              requests={userRequests}
              isConnected={isConnected}
            />
          </div>
        </section>

        {/* Events section */}
        <section className="events-section">
          <EventLog
            events={events}
            onClear={clearEvents}
          />
        </section>
      </main>

      {/* Footer */}
      <footer className="footer">
        <p>Powered by Sparsity Nova Platform</p>
      </footer>
    </div>
  );
}

export default App;
