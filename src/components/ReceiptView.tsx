import React, { useState } from "react";
import { TransitionReceipt } from "../lib/types";
import { formatAbsoluteTime } from "../lib/format";

interface ReceiptViewProps {
    receipt: TransitionReceipt;
    onClose?: () => void;
}

export const ReceiptView: React.FC<ReceiptViewProps> = ({ receipt, onClose }) => {
    const [expanded, setExpanded] = useState(false);
    const isVerified = !!receipt.receiver_signature;

    return (
        <div className="glass-panel receipt-view">
            <div className="receipt-header">
                <div className={`status-badge ${isVerified ? "verified" : "pending"}`}>
                    {isVerified ? "✓ VERIFIED" : "⚠ PENDING"}
                </div>
                <h2 className="text-gradient">Proof of Transition</h2>
                {onClose && (
                    <button className="glass-button" onClick={onClose} style={{ padding: "4px 8px", minWidth: "auto" }}>
                        ×
                    </button>
                )}
            </div>

            <div className="receipt-content">
                <div className="receipt-row">
                    <label>Transfer ID</label>
                    <code className="mono">{receipt.transfer_id}</code>
                </div>
                <div className="receipt-row">
                    <label>Route</label>
                    <span className="route-tag">{receipt.route_type}</span>
                </div>
                <div className="receipt-row">
                    <label>Timestamp</label>
                    <span>{formatAbsoluteTime(new Date(receipt.timestamp_start).getTime())}</span>
                </div>

                <div className="files-list-section">
                    <label>Attested Files</label>
                    <ul className="attested-files">
                        {receipt.files.map((f, i) => (
                            <li key={i}>
                                <span className="file-name">{f.name}</span>
                                <span className="file-cid" title={f.cid}>CID: {f.cid.substring(0, 16)}...</span>
                            </li>
                        ))}
                    </ul>
                </div>

                <button className="glass-button" onClick={() => setExpanded(!expanded)} style={{ width: "100%", marginTop: "16px", justifyContent: "center" }}>
                    {expanded ? "Hide Cryptographic Details" : "Show Cryptographic Details"}
                </button>

                {expanded && (
                    <div className="technical-details">
                        <div className="detail-group">
                            <label>Sender Identity</label>
                            <code className="mono small">{receipt.sender_identity}</code>
                        </div>
                        <div className="detail-group">
                            <label>Receiver Identity</label>
                            <code className="mono small">{receipt.receiver_identity}</code>
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
