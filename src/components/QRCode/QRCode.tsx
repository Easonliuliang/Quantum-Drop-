import { useEffect, useRef, useState } from 'react';

interface QRCodeProps {
  value: string;
  size?: number;
  bgColor?: string;
  fgColor?: string;
}

export const QRCode = ({
  value,
  size = 160,
  bgColor = '#00000000',
  fgColor = '#00C896'
}: QRCodeProps) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !value) return;

    // Dynamic import to handle CommonJS module properly
    import('qrcode').then((QRCodeLib) => {
      const toCanvas = QRCodeLib.default?.toCanvas || QRCodeLib.toCanvas;
      if (!toCanvas) {
        console.warn('QRCode toCanvas not found');
        return;
      }
      toCanvas(canvas, value, {
        width: size,
        margin: 1,
        color: {
          dark: fgColor,
          light: bgColor,
        },
        errorCorrectionLevel: 'M',
      }).then(() => {
        setLoaded(true);
      }).catch((err: Error) => {
        console.warn('QR code generation failed:', err);
      });
    }).catch((err) => {
      console.warn('QRCode library load failed:', err);
    });
  }, [value, size, bgColor, fgColor]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        width: size,
        height: size,
        borderRadius: 12,
        opacity: loaded ? 1 : 0.5,
      }}
    />
  );
};

export default QRCode;
