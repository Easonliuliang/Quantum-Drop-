import React, { useEffect, useRef } from 'react';

interface QuantumBackgroundProps {
  transferState?: 'idle' | 'transferring' | 'completed' | 'error';
}

export const QuantumBackground: React.FC<QuantumBackgroundProps> = ({ transferState = 'idle' }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const stateRef = useRef<string>(transferState);
  const particlesRef = useRef<any[]>([]);
  const animationRef = useRef<number>();
  const contextRef = useRef<CanvasRenderingContext2D | null>(null);
  const dimensionsRef = useRef({ width: 0, height: 0 });

  useEffect(() => {
    if (transferState === 'completed') {
      stateRef.current = 'collapsing';
      const t1 = setTimeout(() => { stateRef.current = 'exploding'; }, 1000);
      const t2 = setTimeout(() => {
        stateRef.current = 'idle';
        // Redistribute particles across screen
        const w = dimensionsRef.current.width;
        const h = dimensionsRef.current.height;
        particlesRef.current.forEach((p) => {
          p.baseX = Math.random() * w;
          p.baseY = Math.random() * h;
        });
      }, 2000);
      return () => { clearTimeout(t1); clearTimeout(t2); };
    } else {
      stateRef.current = transferState;
    }
  }, [transferState]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    contextRef.current = ctx;

    const numParticles = 200;

    class Particle {
      x: number;
      y: number;
      baseX: number;
      baseY: number;
      size: number;
      opacity: number;
      baseOpacity: number;
      twinkleSpeed: number;
      twinklePhase: number;
      driftX: number;
      driftY: number;
      driftPhase: number;
      color: string;

      constructor(w: number, h: number) {
        this.x = Math.random() * w;
        this.y = Math.random() * h;
        this.baseX = this.x;
        this.baseY = this.y;

        // Star sizes - mostly small, few larger
        const sizeRand = Math.random();
        if (sizeRand > 0.95) {
          this.size = Math.random() * 2 + 2; // Big stars (5%)
        } else if (sizeRand > 0.8) {
          this.size = Math.random() * 1 + 1.5; // Medium stars (15%)
        } else {
          this.size = Math.random() * 1 + 0.5; // Small stars (80%)
        }

        // Opacity based on size
        this.baseOpacity = Math.min(0.9, this.size * 0.25 + 0.2);
        this.opacity = this.baseOpacity;

        // Twinkle
        this.twinkleSpeed = Math.random() * 0.02 + 0.005;
        this.twinklePhase = Math.random() * Math.PI * 2;

        // Slow drift
        this.driftX = (Math.random() - 0.5) * 0.3;
        this.driftY = (Math.random() - 0.5) * 0.3;
        this.driftPhase = Math.random() * Math.PI * 2;

        // Color: white to light blue
        const colorRand = Math.random();
        if (colorRand > 0.7) {
          this.color = `rgba(200, 220, 255, `; // Light blue
        } else if (colorRand > 0.4) {
          this.color = `rgba(230, 240, 255, `; // Very light blue
        } else {
          this.color = `rgba(255, 255, 255, `; // Pure white
        }
      }

      update(width: number, height: number, state: string, time: number) {
        if (state === 'idle') {
          // Target position with gentle floating
          const targetX = this.baseX + Math.sin(time * 0.0005 + this.driftPhase) * 20 * this.driftX;
          const targetY = this.baseY + Math.cos(time * 0.0003 + this.driftPhase) * 20 * this.driftY;

          // Smooth interpolation to target (lerp)
          this.x += (targetX - this.x) * 0.02;
          this.y += (targetY - this.y) * 0.02;

          // Twinkle effect
          this.opacity = this.baseOpacity * (0.5 + 0.5 * Math.sin(time * this.twinkleSpeed + this.twinklePhase));

        } else if (state === 'transferring' || state === 'collapsing') {
          // Rush toward center - tunnel effect
          const centerX = width / 2;
          const centerY = height / 2;
          const dx = centerX - this.x;
          const dy = centerY - this.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          // Speed based on state
          const speed = state === 'transferring' ? 5 : 8;

          if (dist > 10) {
            this.x += (dx / dist) * speed;
            this.y += (dy / dist) * speed;
          } else {
            // Respawn at edge for infinite tunnel effect
            const edge = Math.floor(Math.random() * 4);
            if (edge === 0) { this.x = 0; this.y = Math.random() * height; }
            else if (edge === 1) { this.x = width; this.y = Math.random() * height; }
            else if (edge === 2) { this.x = Math.random() * width; this.y = 0; }
            else { this.x = Math.random() * width; this.y = height; }
          }

          // Bright
          this.opacity = 1;

        } else if (state === 'collapsing_unused') {
          // Tunnel effect - rush toward center
          const centerX = width / 2;
          const centerY = height / 2;
          const dx = centerX - this.x;
          const dy = centerY - this.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist > 10) {
            this.x += (dx / dist) * 8;
            this.y += (dy / dist) * 8;
          } else {
            // Respawn at edge
            const edge = Math.floor(Math.random() * 4);
            if (edge === 0) { this.x = 0; this.y = Math.random() * height; }
            else if (edge === 1) { this.x = width; this.y = Math.random() * height; }
            else if (edge === 2) { this.x = Math.random() * width; this.y = 0; }
            else { this.x = Math.random() * width; this.y = height; }
          }

          // Streak effect - increase opacity
          this.opacity = Math.min(1, this.baseOpacity * 2);

        } else if (state === 'exploding') {
          // Burst from center
          const centerX = width / 2;
          const centerY = height / 2;
          const dx = this.x - centerX;
          const dy = this.y - centerY;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;

          this.x += (dx / dist) * 12;
          this.y += (dy / dist) * 12;

          // Fade out as they fly away
          this.opacity = Math.max(0, this.baseOpacity * (1 - dist / Math.max(width, height)));

          // Respawn near center if off screen
          if (this.x < -50 || this.x > width + 50 || this.y < -50 || this.y > height + 50) {
            this.x = centerX + (Math.random() - 0.5) * 100;
            this.y = centerY + (Math.random() - 0.5) * 100;
            this.baseX = this.x;
            this.baseY = this.y;
          }
        }
      }

      draw(ctx: CanvasRenderingContext2D, state: string, width: number, height: number) {
        ctx.beginPath();

        if (state === 'transferring' || state === 'collapsing') {
          // Streak toward center - tunnel effect
          const centerX = width / 2;
          const centerY = height / 2;
          const angle = Math.atan2(centerY - this.y, centerX - this.x);
          const streakLength = state === 'collapsing' ? 30 : 20;
          ctx.moveTo(this.x, this.y);
          ctx.lineTo(
            this.x - Math.cos(angle) * streakLength,
            this.y - Math.sin(angle) * streakLength
          );
          ctx.strokeStyle = this.color + this.opacity + ')';
          ctx.lineWidth = this.size;
          ctx.stroke();
        } else {
          // Draw as dot/star
          ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
          ctx.fillStyle = this.color + this.opacity + ')';
          ctx.fill();

          // Glow for larger stars
          if (this.size > 1.5) {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size * 2, 0, Math.PI * 2);
            ctx.fillStyle = this.color + (this.opacity * 0.2) + ')';
            ctx.fill();
          }
        }
      }
    }

    const init = () => {
      particlesRef.current = [];
      for (let i = 0; i < numParticles; i++) {
        particlesRef.current.push(new Particle(canvas.width, canvas.height));
      }
    };

    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      dimensionsRef.current = { width: canvas.width, height: canvas.height };
      init();
    };

    const animate = () => {
      if (!contextRef.current) return;
      const ctx = contextRef.current;
      const width = dimensionsRef.current.width;
      const height = dimensionsRef.current.height;
      const currentState = stateRef.current;
      const time = Date.now();

      // Clear with dark background - lower opacity = longer trails
      let trailFade = 0.15;
      if (currentState === 'transferring') trailFade = 0.08;
      if (currentState === 'collapsing') trailFade = 0.05;
      if (currentState === 'exploding') trailFade = 0.1;

      ctx.fillStyle = `rgba(8, 10, 15, ${trailFade})`;
      ctx.fillRect(0, 0, width, height);

      particlesRef.current.forEach((particle) => {
        particle.update(width, height, currentState, time);
        particle.draw(ctx, currentState, width, height);
      });

      animationRef.current = requestAnimationFrame(animate);
    };

    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();
    animate();

    return () => {
      window.removeEventListener('resize', resizeCanvas);
      if (animationRef.current) cancelAnimationFrame(animationRef.current);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        zIndex: 0,
        pointerEvents: 'none',
        background: '#080a0f',
      }}
    />
  );
};
