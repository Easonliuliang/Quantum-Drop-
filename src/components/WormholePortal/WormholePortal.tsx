import React, { useEffect, useRef } from 'react';
import './WormholePortal.css';

interface WormholePortalProps {
  state?: 'idle' | 'hover' | 'transferring' | 'completed';
  progress?: number;
}

interface TunnelParticle {
  z: number;        // depth in tunnel (0 = entry, 1 = exit)
  angle: number;    // position around the ring
  speed: number;
  opacity: number;
  size: number;
  hue: number;
}

export const WormholePortal: React.FC<WormholePortalProps> = ({
  state = 'idle',
  progress = 0,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<TunnelParticle[]>([]);
  const animationRef = useRef<number>();
  const stateRef = useRef(state);
  const progressRef = useRef(progress);

  useEffect(() => {
    stateRef.current = state;
  }, [state]);

  useEffect(() => {
    progressRef.current = progress;
  }, [progress]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const size = 280;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size}px`;
    ctx.scale(dpr, dpr);

    const width = size;
    const height = size;
    const centerX = width / 2;
    const centerY = height / 2;

    // Tunnel parameters
    const tunnelLength = 1; // normalized 0-1
    const entryRadius = 100; // radius at entry (close to viewer)
    const exitRadius = 15;   // radius at exit (far end, small = perspective)
    const numRings = 12;

    // Initialize particles
    const createParticle = (): TunnelParticle => ({
      z: Math.random(),
      angle: Math.random() * Math.PI * 2,
      speed: 0.002 + Math.random() * 0.003,
      opacity: 0.3 + Math.random() * 0.5,
      size: 1 + Math.random() * 2,
      hue: 160 + Math.random() * 20, // cyan-teal range
    });

    particlesRef.current = [];
    for (let i = 0; i < 60; i++) {
      particlesRef.current.push(createParticle());
    }

    let time = 0;

    const draw = () => {
      const currentState = stateRef.current;
      const currentProgress = progressRef.current;

      // Clear
      ctx.fillStyle = '#08080c';
      ctx.fillRect(0, 0, width, height);

      time += 0.016;

      // State-based modifiers
      let speedMult = 1;
      let glowIntensity = 0.3;
      let tunnelPulse = 0;

      if (currentState === 'hover') {
        speedMult = 2;
        glowIntensity = 0.5;
        tunnelPulse = Math.sin(time * 3) * 0.05;
      } else if (currentState === 'transferring') {
        speedMult = 8;
        glowIntensity = 0.8;
        tunnelPulse = Math.sin(time * 6) * 0.03;
      } else if (currentState === 'completed') {
        speedMult = 0.5;
        glowIntensity = 1;
      }

      // === Draw tunnel rings (perspective) ===
      for (let i = 0; i < numRings; i++) {
        const t = i / (numRings - 1); // 0 = entry, 1 = exit
        const radius = entryRadius - (entryRadius - exitRadius) * t;
        const depthFade = 1 - t * 0.6;

        // Ring wobble for organic feel
        const wobble = Math.sin(time * 0.5 + t * 10) * 2 * (1 - t);
        const r = radius * (1 + tunnelPulse) + wobble;

        // Draw ring
        ctx.beginPath();
        ctx.arc(centerX, centerY, r, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(0, 180, 150, ${0.08 * depthFade * (glowIntensity + 0.5)})`;
        ctx.lineWidth = 1 + (1 - t) * 0.5;
        ctx.stroke();
      }

      // === Draw tunnel depth lines (perspective lines toward center) ===
      const numLines = 16;
      for (let i = 0; i < numLines; i++) {
        const angle = (i / numLines) * Math.PI * 2 + time * 0.1;

        ctx.beginPath();
        // Start from entry ring
        const startR = entryRadius * (1 + tunnelPulse);
        ctx.moveTo(
          centerX + Math.cos(angle) * startR,
          centerY + Math.sin(angle) * startR
        );
        // End at exit ring
        const endR = exitRadius * (1 + tunnelPulse);
        ctx.lineTo(
          centerX + Math.cos(angle) * endR,
          centerY + Math.sin(angle) * endR
        );

        const gradient = ctx.createLinearGradient(
          centerX + Math.cos(angle) * startR,
          centerY + Math.sin(angle) * startR,
          centerX + Math.cos(angle) * endR,
          centerY + Math.sin(angle) * endR
        );
        gradient.addColorStop(0, `rgba(0, 180, 150, ${0.06 * glowIntensity})`);
        gradient.addColorStop(1, `rgba(0, 180, 150, ${0.02 * glowIntensity})`);

        ctx.strokeStyle = gradient;
        ctx.lineWidth = 0.5;
        ctx.stroke();
      }

      // === Draw exit glow (the "other end") ===
      const exitGlow = ctx.createRadialGradient(
        centerX, centerY, 0,
        centerX, centerY, exitRadius * 2
      );
      exitGlow.addColorStop(0, `rgba(0, 255, 200, ${0.15 * glowIntensity})`);
      exitGlow.addColorStop(0.5, `rgba(0, 200, 160, ${0.05 * glowIntensity})`);
      exitGlow.addColorStop(1, 'rgba(0, 200, 160, 0)');

      ctx.beginPath();
      ctx.arc(centerX, centerY, exitRadius * 2, 0, Math.PI * 2);
      ctx.fillStyle = exitGlow;
      ctx.fill();

      // === Draw particles traveling through tunnel ===
      particlesRef.current.forEach((p, idx) => {
        // Update z position (traveling through tunnel)
        p.z += p.speed * speedMult;

        // Slight spiral motion
        p.angle += 0.01 * speedMult;

        // Reset when reaching the end
        if (p.z > 1) {
          particlesRef.current[idx] = createParticle();
          particlesRef.current[idx].z = 0;
          return;
        }

        // Calculate position based on depth
        const t = p.z;
        const radius = entryRadius - (entryRadius - exitRadius) * t;
        const r = radius * (1 + tunnelPulse);

        const x = centerX + Math.cos(p.angle) * r;
        const y = centerY + Math.sin(p.angle) * r;

        // Size and opacity decrease with depth (perspective)
        const perspectiveScale = 1 - t * 0.7;
        const size = p.size * perspectiveScale;
        const opacity = p.opacity * perspectiveScale;

        // Draw particle with trail
        const trailLength = 8 * speedMult * perspectiveScale;
        const prevT = Math.max(0, t - 0.05);
        const prevRadius = entryRadius - (entryRadius - exitRadius) * prevT;
        const prevR = prevRadius * (1 + tunnelPulse);
        const prevAngle = p.angle - 0.01 * speedMult;
        const prevX = centerX + Math.cos(prevAngle) * prevR;
        const prevY = centerY + Math.sin(prevAngle) * prevR;

        // Trail gradient
        const trailGradient = ctx.createLinearGradient(prevX, prevY, x, y);
        trailGradient.addColorStop(0, `hsla(${p.hue}, 80%, 60%, 0)`);
        trailGradient.addColorStop(1, `hsla(${p.hue}, 80%, 60%, ${opacity})`);

        ctx.beginPath();
        ctx.moveTo(prevX, prevY);
        ctx.lineTo(x, y);
        ctx.strokeStyle = trailGradient;
        ctx.lineWidth = size;
        ctx.lineCap = 'round';
        ctx.stroke();

        // Particle head
        ctx.beginPath();
        ctx.arc(x, y, size * 0.5, 0, Math.PI * 2);
        ctx.fillStyle = `hsla(${p.hue}, 80%, 70%, ${opacity})`;
        ctx.fill();
      });

      // === Draw entry ring glow ===
      ctx.beginPath();
      ctx.arc(centerX, centerY, entryRadius, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(0, 200, 160, ${0.15 * glowIntensity})`;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Outer subtle glow
      const entryGlow = ctx.createRadialGradient(
        centerX, centerY, entryRadius - 10,
        centerX, centerY, entryRadius + 20
      );
      entryGlow.addColorStop(0, 'rgba(0, 200, 160, 0)');
      entryGlow.addColorStop(0.5, `rgba(0, 200, 160, ${0.05 * glowIntensity})`);
      entryGlow.addColorStop(1, 'rgba(0, 200, 160, 0)');

      ctx.beginPath();
      ctx.arc(centerX, centerY, entryRadius + 20, 0, Math.PI * 2);
      ctx.fillStyle = entryGlow;
      ctx.fill();

      // === Progress indicator (when transferring) ===
      if (currentState === 'transferring' && currentProgress > 0) {
        const progressAngle = (currentProgress / 100) * Math.PI * 2 - Math.PI / 2;
        ctx.beginPath();
        ctx.arc(centerX, centerY, entryRadius + 8, -Math.PI / 2, progressAngle);
        ctx.strokeStyle = 'rgba(0, 255, 200, 0.6)';
        ctx.lineWidth = 2;
        ctx.lineCap = 'round';
        ctx.stroke();
      }

      animationRef.current = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, []);

  return (
    <div className="wormhole-portal">
      <canvas ref={canvasRef} className="wormhole-canvas" />
    </div>
  );
};

export default WormholePortal;
