import { useState } from 'react';
import './RequestForm.css';

/**
 * Request form component for submitting random number requests
 */
export function RequestForm({
    isConnected,
    isCorrectNetwork,
    isLoading,
    onSubmit
}) {
    const [min, setMin] = useState(0);
    const [max, setMax] = useState(100);
    const [error, setError] = useState(null);

    const handleSubmit = (e) => {
        e.preventDefault();
        setError(null);

        // Validation
        const minVal = parseInt(min);
        const maxVal = parseInt(max);

        if (isNaN(minVal) || isNaN(maxVal)) {
            setError('Please enter valid numbers');
            return;
        }

        if (maxVal <= minVal) {
            setError('Max must be greater than min');
            return;
        }

        onSubmit(minVal, maxVal);
    };

    const isDisabled = !isConnected || !isCorrectNetwork || isLoading;

    return (
        <div className="request-form-card">
            <div className="card-header">
                <span className="card-icon">🎲</span>
                <h2>Request Random Number</h2>
            </div>

            <form onSubmit={handleSubmit} className="request-form">
                <div className="form-row">
                    <div className="form-group">
                        <label htmlFor="min">Min Value (inclusive)</label>
                        <input
                            id="min"
                            type="number"
                            value={min}
                            onChange={(e) => setMin(e.target.value)}
                            disabled={isDisabled}
                            placeholder="0"
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="max">Max Value (exclusive)</label>
                        <input
                            id="max"
                            type="number"
                            value={max}
                            onChange={(e) => setMax(e.target.value)}
                            disabled={isDisabled}
                            placeholder="100"
                        />
                    </div>
                </div>

                {error && <div className="form-error">{error}</div>}

                <button
                    type="submit"
                    className="submit-btn"
                    disabled={isDisabled}
                >
                    {isLoading ? (
                        <>
                            <span className="spinner"></span>
                            Processing...
                        </>
                    ) : (
                        <>
                            <span className="btn-icon">🎲</span>
                            Request Random Number
                        </>
                    )}
                </button>

                {!isConnected && (
                    <p className="form-hint">Connect your wallet to request random numbers</p>
                )}
                {isConnected && !isCorrectNetwork && (
                    <p className="form-hint warning">Please switch to Base Sepolia network</p>
                )}
            </form>
        </div>
    );
}
