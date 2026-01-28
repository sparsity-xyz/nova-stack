import { useRef, useEffect } from 'react';
import './EventLog.css';

/**
 * Event log component for displaying real-time contract events
 */
export function EventLog({ events, onClear }) {
    const listRef = useRef(null);

    // Auto-scroll to top when new events arrive
    useEffect(() => {
        if (listRef.current) {
            listRef.current.scrollTop = 0;
        }
    }, [events.length]);



    return (
        <div className="event-log-card">
            <div className="card-header">
                <div className="header-left">
                    <span className="card-icon">📡</span>
                    <h2>RNG Contract Events</h2>
                    <span className="live-badge">
                        <span className="live-dot"></span>
                        Live
                    </span>
                </div>
                {events.length > 0 && (
                    <button className="clear-btn" onClick={onClear}>
                        Clear
                    </button>
                )}
            </div>

            <div className="event-list" ref={listRef}>
                {events.length === 0 ? (
                    <div className="empty-state">
                        <span className="empty-icon">📭</span>
                        <p>No events yet</p>
                        <p className="empty-hint">Events will appear here when they are emitted by the contract</p>
                    </div>
                ) : (
                    events.map((event) => (
                        <div
                            key={event.id}
                            className={`event-item ${event.type === 'RandomNumberFulfilled' ? 'fulfilled' : 'requested'}`}
                        >
                            <div className="event-header">
                                <span className="event-type">
                                    {event.type === 'RandomNumberFulfilled' ? '✅' : '📤'}
                                    {event.type === 'RandomNumberFulfilled' ? 'Fulfilled' : 'Requested'}
                                </span>
                                <span className="event-time">{event.timestamp}</span>
                            </div>

                            <div className="event-details">
                                <div className="detail-row">
                                    <span className="detail-label">Request ID:</span>
                                    <span className="detail-value highlight">#{event.requestId}</span>
                                </div>
                                <div className="detail-row">
                                    <span className="detail-label">Requester:</span>
                                    <span className="detail-value mono">{event.requester}</span>
                                </div>

                                {event.type === 'RandomNumberRequested' && (
                                    <div className="detail-row">
                                        <span className="detail-label">Range:</span>
                                        <span className="detail-value">[{event.min}, {event.max})</span>
                                    </div>
                                )}

                                {event.type === 'RandomNumberFulfilled' && (
                                    <div className="detail-row">
                                        <span className="detail-label">Result:</span>
                                        <span className="detail-value result">
                                            🎲 {event.randomNumbers.join(', ')}
                                        </span>
                                    </div>
                                )}

                                <div className="detail-row">
                                    <span className="detail-label">Tx:</span>
                                    <a
                                        className="detail-value mono tx-link"
                                        href={`https://sepolia.basescan.org/tx/${event.txHash}`}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                    >
                                        {event.txHash} ↗
                                    </a>
                                </div>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}
