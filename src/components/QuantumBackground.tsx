import React, { useEffect, useState, useRef } from 'react';
import ColorBends from './ColorBends';

interface QuantumBackgroundProps {
  transferState?: 'idle' | 'transferring' | 'completed' | 'error';
}

interface Params {
  speed: number;
  warpStrength: number;
  scale: number;
  autoRotate: number;
  frequency: number;
}

const IDLE: Params = { speed: 0.2, warpStrength: 1, scale: 1, autoRotate: 0, frequency: 1 };

export const QuantumBackground: React.FC<QuantumBackgroundProps> = ({ transferState = 'idle' }) => {
  const [params, setParams] = useState<Params>(IDLE);
  const [flash, setFlash] = useState(0);
  const rafRef = useRef<number>(0);
  const currentRef = useRef<Params>({ ...IDLE });

  useEffect(() => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current);

    let target: Params;
    let duration: number;

    if (transferState === 'transferring') {
      // 曲速飞行 - 光带加速流动旋转
      target = { speed: 1.5, warpStrength: 1.4, scale: 1.15, autoRotate: 35, frequency: 0.85 };
      duration = 2000;
    } else if (transferState === 'completed') {
      // 穿越完成 - 极速旋转
      target = { speed: 2.5, warpStrength: 1.8, scale: 1.3, autoRotate: 70, frequency: 0.7 };
      duration = 500;
    } else {
      target = IDLE;
      duration = 1000;
    }

    const from = { ...currentRef.current };
    const start = performance.now();

    const tick = () => {
      const elapsed = performance.now() - start;
      const t = Math.min(elapsed / duration, 1);
      // easeInOutQuad
      const ease = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;

      currentRef.current = {
        speed: from.speed + (target.speed - from.speed) * ease,
        warpStrength: from.warpStrength + (target.warpStrength - from.warpStrength) * ease,
        scale: from.scale + (target.scale - from.scale) * ease,
        autoRotate: from.autoRotate + (target.autoRotate - from.autoRotate) * ease,
        frequency: from.frequency + (target.frequency - from.frequency) * ease,
      };
      setParams({ ...currentRef.current });

      if (t < 1) {
        rafRef.current = requestAnimationFrame(tick);
      } else if (transferState === 'completed') {
        // 闪光 + 回归
        setFlash(0.5);
        setTimeout(() => setFlash(0), 150);
        setTimeout(() => {
          const burstFrom = { ...currentRef.current };
          const returnStart = performance.now();
          const returnTick = () => {
            const e = performance.now() - returnStart;
            const rt = Math.min(e / 1200, 1);
            const re = rt < 0.5 ? 2 * rt * rt : 1 - Math.pow(-2 * rt + 2, 2) / 2;
            currentRef.current = {
              speed: burstFrom.speed + (IDLE.speed - burstFrom.speed) * re,
              warpStrength: burstFrom.warpStrength + (IDLE.warpStrength - burstFrom.warpStrength) * re,
              scale: burstFrom.scale + (IDLE.scale - burstFrom.scale) * re,
              autoRotate: burstFrom.autoRotate + (IDLE.autoRotate - burstFrom.autoRotate) * re,
              frequency: burstFrom.frequency + (IDLE.frequency - burstFrom.frequency) * re,
            };
            setParams({ ...currentRef.current });
            if (rt < 1) rafRef.current = requestAnimationFrame(returnTick);
          };
          rafRef.current = requestAnimationFrame(returnTick);
        }, 200);
      }
    };

    rafRef.current = requestAnimationFrame(tick);

    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [transferState]);

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 0, background: '#000' }}>
      <ColorBends
        rotation={45}
        speed={params.speed}
        scale={params.scale}
        frequency={params.frequency}
        warpStrength={params.warpStrength}
        mouseInfluence={0.5}
        parallax={0.3}
        noise={0.1}
        autoRotate={params.autoRotate}
      />
      {flash > 0 && (
        <div style={{ position: 'absolute', inset: 0, background: 'white', opacity: flash, pointerEvents: 'none' }} />
      )}
    </div>
  );
};
