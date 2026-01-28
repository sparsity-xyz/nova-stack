import './ResultDisplay.css';

/**
 * Result display component showing user's random number requests
 */
export function ResultDisplay({ requests, isConnected }) {
    if (!isConnected) {
        return (
            <div className="result-card">
                <div className="card-header">
                    <span className="card-icon">✨</span>
                    <h2>Your Results</h2>
                </div>
                <div className="empty-state">
                    <span className="empty-icon">🔗</span>
                    <p>Connect your wallet to see your requests</p>
                </div>
            </div>
        );
    }

    return (
        <div className="result-card">
            <div className="card-header">
                <span className="card-icon">✨</span>
                <h2>Your Results</h2>
                {requests.length > 0 && (
                    <span className="count-badge">{requests.length}</span>
                )}
            </div>

            <div className="result-list">
                {requests.length === 0 ? (
                    <div className="empty-state">
                        <span className="empty-icon">🎲</span>
                        <p>No requests yet</p>
                        <p className="empty-hint">Submit a request to get random numbers</p>
                    </div>
                ) : (
                    requests.map((request) => (
                        <div
                            key={request.requestId}
                            className={`result-item ${request.status}`}
                        >
                            <div className="result-header">
                                <span className="request-id">Request #{request.requestId}</span>
                                <span className={`status-badge ${request.status}`}>
                                    {request.status === 'fulfilled' ? '✅ Fulfilled' : '⏳ Pending'}
                                </span>
                            </div>

                            <div className="result-body">
                                <div className="result-range">
                                    Range: [{request.min}, {request.max})
                                </div>

                                {request.status === 'fulfilled' ? (
                                    <div className="result-numbers">
                                        <span className="number-label">Result:</span>
                                        <span className="number-value">
                                            🎲 {request.randomNumbers.join(', ')}
                                        </span>
                                    </div>
                                ) : (
                                    <div className="result-pending">
                                        <span className="pending-spinner"></span>
                                        Waiting for random number...
                                    </div>
                                )}
                            </div>

                            <div className="result-footer">
                                <span className="result-time">{request.timestamp}</span>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
