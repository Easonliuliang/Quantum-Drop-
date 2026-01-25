import { useEffect, useRef } from 'react';
import QRCodeLib from 'qrcode';

interface QRCodeProps {
  value: string;
  size?: number;
  bgColor?: string;
  fgColor?: string;
}

export const QRCode = ({
  value,
  size = 160,
  bgColor = 'transparent',
  fgColor = 'rgba(0, 200, 150, 0.9)'
}: QRCodeProps) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !value) return;

    QRCodeLib.toCanvas(canvas, value, {
      width: size,
      margin: 1,
      color: {
        dark: fgColor,
        light: bgColor,
      },
      errorCorrectionLevel: 'M',
    }).catch(err => {
      console.warn('QR code generation failed:', err);
    });
  }, [value, size, bgColor, fgColor]);

  return (
    <canvas
      ref={canvasRef}
      style={{
        width: size,
        height: size,
        borderRadius: 12,
      }}
    />
  );
};

export default QRCode;
