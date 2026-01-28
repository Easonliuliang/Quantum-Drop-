import { useEffect, useRef, useState } from 'react';
import { Html5Qrcode } from 'html5-qrcode';
import './QRScanner.css';

interface QRScannerProps {
  onScan: (result: string) => void;
  onClose: () => void;
}

export const QRScanner = ({ onScan, onClose }: QRScannerProps) => {
  const scannerRef = useRef<Html5Qrcode | null>(null);
  const [error, setError] = useState<string>('');
  const [isStarting, setIsStarting] = useState(true);

  useEffect(() => {
    const scannerId = 'qr-scanner-container';
    const scanner = new Html5Qrcode(scannerId);
    scannerRef.current = scanner;

    const startScanner = async () => {
      try {
        setIsStarting(true);
        setError('');

        await scanner.start(
          { facingMode: 'environment' },
          {
            fps: 10,
            qrbox: { width: 200, height: 200 },
          },
          (decodedText) => {
            // Successfully scanned
            onScan(decodedText);
            void scanner.stop();
          },
          () => {
            // Scan error (no QR found in frame) - ignore
          }
        );
        setIsStarting(false);
      } catch (err) {
        setIsStarting(false);
        if (err instanceof Error) {
          if (err.message.includes('Permission')) {
            setError('Camera permission denied');
          } else if (err.message.includes('NotFoundError')) {
            setError('No camera found');
          } else {
            setError(err.message);
          }
        } else {
          setError('Failed to start camera');
        }
      }
    };

    void startScanner();

    return () => {
      if (scannerRef.current?.isScanning) {
        void scannerRef.current.stop();
      }
    };
  }, [onScan]);

  return (
    <div className="qr-scanner-overlay">
      <div className="qr-scanner-modal">
        <div className="qr-scanner-header">
          <h3>Scan QR Code</h3>
          <button className="qr-scanner-close" onClick={onClose}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>

        <div className="qr-scanner-body">
          {isStarting && (
            <div className="qr-scanner-loading">
              Starting camera...
            </div>
          )}

          {error && (
            <div className="qr-scanner-error">
              {error}
            </div>
          )}

          <div id="qr-scanner-container" className="qr-scanner-view" />

          <div className="qr-scanner-hint">
            Point camera at a friend&apos;s QR code
          </div>
        </div>
      </div>
    </div>
  );
};

export default QRScanner;
