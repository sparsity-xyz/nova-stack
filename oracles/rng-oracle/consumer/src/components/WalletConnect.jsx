import './WalletConnect.css';

/**
 * Wallet connection component
 * Displays connect button or connected wallet info
 */
export function WalletConnect({
    isConnected,
    isConnecting,
    isCorrectNetwork,
    shortenedAddress,
    onConnect,
    onDisconnect,
    onSwitchNetwork
}) {
    if (isConnected) {
        return (
            <div className="wallet-info">
                {!isCorrectNetwork && (
                    <button className="switch-network-btn" onClick={onSwitchNetwork}>
                        Switch to Base Sepolia
                    </button>
                )}
                <div className="wallet-address">
                    <span className="address-icon">🔗</span>
                    <span className="address-text">{shortenedAddress}</span>
                </div>
                <button className="disconnect-btn" onClick={onDisconnect}>
                    Disconnect
                </button>
            </div>
        );
    }

    return (
        <button
            className="connect-btn"
            onClick={onConnect}
            disabled={isConnecting}
        >
            {isConnecting ? (
                <>
                    <span className="spinner"></span>
                    Connecting...
                </>
            ) : (
                <>
                    <span className="wallet-icon">💳</span>
                    Connect Wallet
                </>
            )}
        </button>
    );
}
