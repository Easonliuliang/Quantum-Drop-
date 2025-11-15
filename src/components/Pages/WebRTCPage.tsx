import { useI18n } from "../../lib/i18n";

interface WebRTCPageProps {
  onStartSender: () => void;
  canStartSender: boolean;
  isSending: boolean;
}

export function WebRTCPage({ onStartSender, canStartSender, isSending }: WebRTCPageProps) {
  const { t } = useI18n();
  return (
    <div className="webrtc-page">
      <div className="webrtc-panel" aria-live="polite">
        <h3>{t("webrtc.heading", "WebRTC Lab (Phase III)")}</h3>
        <p className="hint">
          {t(
            "webrtc.hint",
            "If no pairing code is supplied, the sender generates a random 6-digit code. The receiver reuses the code and save directory from the Receive panel. This is an experimental feature validating the P2P signaling path.",
          )}
        </p>
        <p className="hint">
          {t(
            "webrtc.receiverDisabled",
            "WebRTC receive testing is disabled in this build. Use the Control Panel logs to fetch delivered files instead.",
          )}
        </p>
        <div className="actions-row">
          <button type="button" className="secondary" onClick={onStartSender} disabled={!canStartSender || isSending}>
            {isSending ? t("webrtc.senderStarting", "Starting WebRTC sender…") : t("webrtc.startSender", "Start WebRTC Sender")}
          </button>
        </div>
      </div>
    </div>
  );
}
