import { useEffect, useRef, useState } from 'react';
import { useI18n } from '../../lib/i18n';
import './ReceivePanel.css';

export interface BleDevice {
  deviceId: string;
  rssi: number;
  matched: boolean;
}

interface ReceivePanelProps {
  isOpen: boolean;
  onClose: () => void;
  onConnectByCode: (code: string) => void;
  bleDevices: BleDevice[];
  isConnecting?: boolean;
  status?: { type: 'connecting' | 'error' | 'success'; message: string } | null;
}

export const ReceivePanel = ({
  isOpen,
  onClose,
  onConnectByCode,
  bleDevices,
  isConnecting = false,
  status,
}: ReceivePanelProps) => {
  const panelRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const { t } = useI18n();
  const [code, setCode] = useState('');

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        onClose();
      }
    };

    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      document.addEventListener('keydown', handleEscape);
      // Auto-focus input when panel opens
      setTimeout(() => inputRef.current?.focus(), 300);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const canConnect = code.length === 6 && !isConnecting;

  const handleConnect = () => {
    if (canConnect) {
      onConnectByCode(code);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && canConnect) {
      handleConnect();
    }
  };

  return (
    <div className="receive-overlay">
      <div ref={panelRef} className="receive-panel">
        <div className="receive-header">
          <h2>{t('receive.panel.title', '接收文件')}</h2>
          <button className="receive-close-btn" onClick={onClose}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="receive-content">
          {/* Code Input Section */}
          <div className="receive-section">
            <div className="receive-section-title">
              {t('receive.panel.codeSection', '配对码')}
            </div>
            <div className="receive-code-row">
              <input
                ref={inputRef}
                className="receive-code-input"
                type="text"
                maxLength={6}
                placeholder="000000"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/[^a-zA-Z0-9]/g, '').slice(0, 6))}
                onKeyDown={handleKeyDown}
                disabled={isConnecting}
              />
              <button
                className="receive-connect-btn"
                onClick={handleConnect}
                disabled={!canConnect}
              >
                {isConnecting
                  ? t('receive.panel.connecting', '连接中…')
                  : t('receive.panel.connect', '连接')}
              </button>
            </div>
          </div>

          {/* Status */}
          {status && (
            <div className="receive-section">
              <div className={`receive-status ${status.type}`}>
                {status.message}
              </div>
            </div>
          )}

          {/* BLE Nearby Devices */}
          <div className="receive-section">
            <div className="receive-section-title">
              {t('receive.panel.nearby', '附近设备')}
            </div>
            {bleDevices.length > 0 ? (
              <div className="receive-device-list">
                {bleDevices.map((device) => (
                  <div
                    key={device.deviceId}
                    className="receive-device-item"
                    onClick={() => {
                      // BLE device selected — auto-trigger connect via backend
                      onConnectByCode(`ble:${device.deviceId}`);
                    }}
                  >
                    <div className="receive-device-info">
                      <span className="receive-device-name">
                        {t('receive.panel.bleDevice', 'BLE 设备')}
                      </span>
                      <span className="receive-device-id">
                        {device.deviceId.slice(0, 12)}…
                      </span>
                    </div>
                    <span className="receive-device-rssi">
                      {device.rssi} dBm
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="receive-empty-hint">
                {t('receive.panel.noDevices', '暂无发现附近 BLE 设备')}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReceivePanel;
