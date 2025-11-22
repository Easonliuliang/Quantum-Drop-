import React, { useEffect, useRef } from 'react';

interface QuantumBackgroundProps {
  transferState?: 'idle' | 'transferring' | 'completed' | 'error';
}

export const QuantumBackground: React.FC<QuantumBackgroundProps> = ({ transferState = 'idle' }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const mouseRef = useRef({ x: 0, y: 0, active: false });

  // Use refs to maintain state without triggering re-renders/resets of the canvas
  const stateRef = useRef<string>(transferState);
  const particlesRef = useRef<any[]>([]);
  const animationRef = useRef<number>();
  const contextRef = useRef<CanvasRenderingContext2D | null>(null);
  const dimensionsRef = useRef({ width: 0, height: 0 });

  // Handle state transitions and animation sequencing
  useEffect(() => {
    if (transferState === 'completed') {
      // Sequence: Collapse -> Explode -> Idle
      stateRef.current = 'collapsing';

      const t1 = setTimeout(() => {
        stateRef.current = 'exploding';
      }, 5000); // Maintain Tunnel effect for 5s

      const t2 = setTimeout(() => {
        stateRef.current = 'idle';
      }, 6500); // Short explosion/reset to idle

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

    let flowField: number[] = [];
    let rows: number;
    let cols: number;
    const scale = 20;
    const numParticles = 1000;

    class Particle {
      x: number;
      y: number;
      speedX: number;
      speedY: number;
      history: { x: number; y: number }[];
      maxLength: number;
      angle: number;
      baseSpeed: number;
      speed: number;
      color: string;
      z: number;

      constructor(w: number, h: number) {
        this.x = Math.random() * w;
        this.y = Math.random() * h;
        this.speedX = 0;
        this.speedY = 0;
        this.history = [];
        this.maxLength = Math.floor(Math.random() * 10 + 5);
        this.angle = 0;
        this.z = Math.random() * 0.9 + 0.1;
        this.baseSpeed = (Math.random() * 1 + 0.5) * this.z;
        this.speed = this.baseSpeed;

        const opacity = this.z * 0.5 + 0.1;
        this.color = Math.random() > 0.5
          ? `rgba(0, 243, 255, ${opacity})`
          : `rgba(188, 19, 254, ${opacity})`;
      }

      update(width: number, height: number, cols: number, field: number[], state: string, mouse: { x: number, y: number, active: boolean }) {
        const x = Math.floor(this.x / scale);
        const y = Math.floor(this.y / scale);
        const index = x + y * cols;

        if (field[index]) {
          this.angle = field[index];
        }

        let speedMultiplier = 1;
        let overrideMotion = false;

        if (state === 'transferring') {
          speedMultiplier = 5;
        } else if (state === 'collapsing') {
          // Collapse: Smooth Radial Suction (Time Tunnel)
          const centerX = width / 2;
          const centerY = height / 2;
          const dx = centerX - this.x;
          const dy = centerY - this.y;

          // Calculate angle towards center
          const angleToCenter = Math.atan2(dy, dx);

          // Override angle for smooth linear motion
          this.angle = angleToCenter;

          // High speed but consistent
          speedMultiplier = 4.0;

          // Infinite Tunnel: Respawn at edges when sucked in
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 20) { // Event Horizon
            // Respawn at random edge
            if (Math.random() > 0.5) {
              this.x = Math.random() > 0.5 ? 0 : width;
              this.y = Math.random() * height;
            } else {
              this.x = Math.random() * width;
              this.y = Math.random() > 0.5 ? 0 : height;
            }
            // Reset history to avoid cross-screen lines
            this.history = [];
          }

          // Let the standard update loop handle the movement using speedX/speedY
          // This ensures smooth trails without jagged jumps
          overrideMotion = false;

        } else if (state === 'exploding') {
          // Explode: Push from center
          const centerX = width / 2;
          const centerY = height / 2;
          const dx = this.x - centerX;
          const dy = this.y - centerY;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;

          // Explosive force
          this.x += (dx / dist) * 15 * this.speed; // Slightly reduced speed for better control
          this.y += (dy / dist) * 15 * this.speed;
          overrideMotion = true;

          // Fountain Effect: If particles fly off screen, respawn them in the center
          // This ensures the center doesn't become empty
          if (this.x < 0 || this.x > width || this.y < 0 || this.y > height) {
            this.x = centerX + (Math.random() - 0.5) * 50;
            this.y = centerY + (Math.random() - 0.5) * 50;
            this.history = [];
          }
        }

        // Mouse interaction (only if not in special animation states)
        if (mouse.active && state === 'idle') {
          const dx = mouse.x - this.x;
          const dy = mouse.y - this.y;
          const distance = Math.sqrt(dx * dx + dy * dy);
          const forceRadius = 200;

          if (distance < forceRadius) {
            const force = (forceRadius - distance) / forceRadius;
            const repulsionX = (dx / distance) * force * 5 * this.z;
            const repulsionY = (dy / distance) * force * 5 * this.z;
            this.x -= repulsionX;
            this.y -= repulsionY;
          }
        }

        this.speed = this.baseSpeed * speedMultiplier;

        if (!overrideMotion) {
          this.speedX = Math.cos(this.angle) * this.speed;
          this.speedY = Math.sin(this.angle) * this.speed;
          this.x += this.speedX;
          this.y += this.speedY;
        }

        this.history.push({ x: this.x, y: this.y });
        if (this.history.length > this.maxLength) {
          this.history.shift();
        }

        // Wrap around edges (disable during collapse/explode to keep focus)
        if (state === 'idle' || state === 'transferring') {
          if (this.x > width) { this.x = 0; this.history = []; }
          if (this.x < 0) { this.x = width; this.history = []; }
          if (this.y > height) { this.y = 0; this.history = []; }
          if (this.y < 0) { this.y = height; this.history = []; }
        }
      }

      draw(context: CanvasRenderingContext2D) {
        context.beginPath();
        context.moveTo(this.history[0]?.x || this.x, this.history[0]?.y || this.y);
        for (let i = 0; i < this.history.length; i++) {
          context.lineTo(this.history[i].x, this.history[i].y);
        }
        context.strokeStyle = this.color;
        context.lineWidth = this.z * 1.5;
        context.stroke();
      }
    }

    const init = () => {
      particlesRef.current = [];
      rows = Math.floor(canvas.height / scale) + 1;
      cols = Math.floor(canvas.width / scale) + 1;
      flowField = new Array(cols * rows);

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

    const handleMouseMove = (e: MouseEvent) => {
      mouseRef.current = { x: e.clientX, y: e.clientY, active: true };
    };

    const handleMouseLeave = () => {
      mouseRef.current = { ...mouseRef.current, active: false };
    };

    const animate = () => {
      if (!contextRef.current) return;
      const ctx = contextRef.current;
      const width = dimensionsRef.current.width;
      const height = dimensionsRef.current.height;
      const currentState = stateRef.current;

      // Trail effect
      let trailOpacity = 0.1;
      if (currentState === 'transferring') trailOpacity = 0.2;
      if (currentState === 'exploding') trailOpacity = 0.05; // Long trails for explosion

      ctx.fillStyle = `rgba(5, 5, 8, ${trailOpacity})`;
      ctx.fillRect(0, 0, width, height);

      // Update flow field
      const time = Date.now() * 0.0005;
      for (let y = 0; y < rows; y++) {
        for (let x = 0; x < cols; x++) {
          const index = x + y * cols;
          const angle = (Math.cos(x * 0.05 + time) + Math.sin(y * 0.05 + time)) * Math.PI;
          flowField[index] = angle;
        }
      }

      particlesRef.current.forEach((particle) => {
        particle.update(width, height, cols, flowField, currentState, mouseRef.current);
        particle.draw(ctx);
      });

      animationRef.current = requestAnimationFrame(animate);
    };

    window.addEventListener('resize', resizeCanvas);
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseleave', handleMouseLeave);

    resizeCanvas();
    animate();

    return () => {
      window.removeEventListener('resize', resizeCanvas);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseleave', handleMouseLeave);
      if (animationRef.current) cancelAnimationFrame(animationRef.current);
    };
  }, []); // Run once on mount

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
        background: '#050508',
      }}
    />
  );
};
