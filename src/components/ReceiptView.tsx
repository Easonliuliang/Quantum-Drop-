import React, { useState } from "react";
import { TransitionReceipt } from "../lib/types";

interface ReceiptViewProps {
    receipt: TransitionReceipt;
    onClose?: () => void;
}

const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
};

const formatTime = (isoString: string): string => {
    const d = new Date(isoString);
    return d.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
};

export const ReceiptView: React.FC<ReceiptViewProps> = ({ receipt, onClose }) => {
    const [expanded, setExpanded] = useState(false);
    const isVerified = !!receipt.receiver_signature;

    return (
        <div className="glass-panel receipt-view animate-collapse">
            <div className="receipt-header">
                <div className={`status-badge ${isVerified ? "verified" : "pending"}`}>
                    {isVerified ? "✓ VERIFIED" : "⏳ PENDING"}
                </div>
                <h2 className="text-gradient">Proof of Transition</h2>
                {onClose && (
                    <button className="glass-button" onClick={onClose} style={{ padding: "4px 8px", minWidth: "auto" }}>
                        ×
                    </button>
                )}
            </div>

            <div className="receipt-content">
                {/* Transfer ID */}
                <div className="receipt-row">
                    <label>Transfer ID</label>
                    <code className="mono">{receipt.transfer_id}</code>
                </div>

                {/* Parties */}
                <div className="receipt-row">
                    <label>From</label>
                    <code className="mono identity-code">{receipt.sender_identity}</code>
                </div>
                <div className="receipt-row">
                    <label>To</label>
                    <code className="mono identity-code">{receipt.receiver_identity}</code>
                </div>

                {/* Time */}
                <div className="receipt-row">
                    <label>Time</label>
                    <span>{formatTime(receipt.timestamp_start)}</span>
                </div>

                {/* Files */}
                <div className="files-list-section">
                    <label>Files</label>
                    <ul className="attested-files">
                        {receipt.files.map((f, i) => (
                            <li key={i}>
                                <div className="file-info">
                                    <span className="file-name">{f.name}</span>
                                    <span className="file-size">{formatFileSize(f.size)}</span>
                                </div>
                                <span className="file-cid" title={f.merkle_root}>
                                    {f.merkle_root.substring(0, 18)}...
                                </span>
                            </li>
                        ))}
                    </ul>
                </div>

                <button
                    className="glass-button"
                    onClick={() => setExpanded(!expanded)}
                    style={{ width: "100%", marginTop: "16px", justifyContent: "center" }}
                >
                    {expanded ? "Hide Details" : "Show Details"}
                </button>

                {expanded && (
                    <div className="technical-details">
                        <div className="detail-group">
                            <label>Route</label>
                            <span className="route-tag">{receipt.route_type.toUpperCase()}</span>
                        </div>
                        <div className="detail-group">
                            <label>Sender Signature</label>
                            <code className="mono small">{receipt.sender_signature || "N/A"}</code>
                        </div>
                        <div className="detail-group">
                            <label>Receiver Signature</label>
                            <code className="mono small">{receipt.receiver_signature || "N/A"}</code>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};
