import React, { useEffect, useRef } from 'react';

export const QuantumBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let particles: Particle[] = [];
    let flowField: number[] = [];
    let rows: number;
    let cols: number;
    const scale = 20; // Grid cell size
    const numParticles = 800; // Particle count

    class Particle {
      x: number;
      y: number;
      speedX: number;
      speedY: number;
      history: { x: number; y: number }[];
      maxLength: number;
      angle: number;
      speed: number;
      color: string;

      constructor(w: number, h: number) {
        this.x = Math.random() * w;
        this.y = Math.random() * h;
        this.speedX = 0;
        this.speedY = 0;
        this.history = [];
        this.maxLength = Math.floor(Math.random() * 10 + 5);
        this.angle = 0;
        this.speed = Math.random() * 1 + 0.5;
        // Randomly assign cyan or purple tint
        this.color = Math.random() > 0.5
          ? `rgba(0, 243, 255, ${Math.random() * 0.5 + 0.1})`
          : `rgba(188, 19, 254, ${Math.random() * 0.5 + 0.1})`;
      }

      update(width: number, height: number, cols: number, field: number[]) {
        const x = Math.floor(this.x / scale);
        const y = Math.floor(this.y / scale);
        const index = x + y * cols;

        if (field[index]) {
          this.angle = field[index];
        }

        this.speedX = Math.cos(this.angle) * this.speed;
        this.speedY = Math.sin(this.angle) * this.speed;
        this.x += this.speedX;
        this.y += this.speedY;

        this.history.push({ x: this.x, y: this.y });
        if (this.history.length > this.maxLength) {
          this.history.shift();
        }

        // Wrap around edges
        if (this.x > width) { this.x = 0; this.history = []; }
        if (this.x < 0) { this.x = width; this.history = []; }
        if (this.y > height) { this.y = 0; this.history = []; }
        if (this.y < 0) { this.y = height; this.history = []; }
      }

      draw(context: CanvasRenderingContext2D) {
        context.beginPath();
        context.moveTo(this.history[0]?.x || this.x, this.history[0]?.y || this.y);
        for (let i = 0; i < this.history.length; i++) {
          context.lineTo(this.history[i].x, this.history[i].y);
        }
        context.strokeStyle = this.color;
        context.lineWidth = 1;
        context.stroke();
      }
    }

    const init = () => {
      particles = [];
      rows = Math.floor(canvas.height / scale) + 1;
      cols = Math.floor(canvas.width / scale) + 1;
      flowField = new Array(cols * rows);

      for (let i = 0; i < numParticles; i++) {
        particles.push(new Particle(canvas.width, canvas.height));
      }
    };

    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      init();
    };

    const animate = () => {
      ctx.fillStyle = 'rgba(5, 5, 8, 0.1)'; // Trail effect
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Update flow field with time-based noise (simulated here with sine waves)
      const time = Date.now() * 0.0005;
      for (let y = 0; y < rows; y++) {
        for (let x = 0; x < cols; x++) {
          const index = x + y * cols;
          // Create a swirling pattern
          const angle = (Math.cos(x * 0.05 + time) + Math.sin(y * 0.05 + time)) * Math.PI;
          flowField[index] = angle;
        }
      }

      particles.forEach((particle) => {
        particle.update(canvas.width, canvas.height, cols, flowField);
        particle.draw(ctx);
      });

      animationFrameId = requestAnimationFrame(animate);
    };

    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();
    animate();

    return () => {
      window.removeEventListener('resize', resizeCanvas);
      cancelAnimationFrame(animationFrameId);
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
        background: '#050508', // Fallback color
      }}
    />
  );
};
