import React, { useEffect, useRef } from 'react';

/**
 * ThreatNetCanvas – Animated particle threat-network visualization.
 * Pure Canvas 2D. No external dependencies.
 *
 * Aesthetic: Dark void background, ember-orange nodes with connecting
 * lines forming a living neural/threat-graph. Cyan pulse rings radiate
 * from "hot" threat nodes. Subtle aurora gradient washes the background.
 */
export default function ThreatNetCanvas({ onInteract }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    // ── Sizing ──────────────────────────────────────────────────────
    let W = canvas.offsetWidth;
    let H = canvas.offsetHeight;
    canvas.width = W * window.devicePixelRatio;
    canvas.height = H * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

    // ── Config ───────────────────────────────────────────────────────
    const NODE_COUNT = 52;
    const CONNECTION_RADIUS = 165;
    const EMBER = '#ff4d00';
    const EMBER_DIM = '#ff2a00';
    const CYAN = '#00f0ff';
    const NODE_SPEED = 0.28;

    // ── Nodes ────────────────────────────────────────────────────────
    const nodes = Array.from({ length: NODE_COUNT }, (_, i) => ({
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * NODE_SPEED,
      vy: (Math.random() - 0.5) * NODE_SPEED,
      r: Math.random() * 2.2 + 1.2,
      // "threat" nodes are ember-orange, others are dim white/cyan
      isThreat: Math.random() < 0.35,
      // pulse ring state
      pulse: Math.random() < 0.2,
      pulseRadius: 0,
      pulseDelay: Math.random() * 180,
      pulseTimer: 0,
      // flicker phase offset
      phase: Math.random() * Math.PI * 2,
      opacity: 0.6 + Math.random() * 0.4,
    }));

    // ── Aurora background gradients (pre-built, repainted each frame) ─
    let auroraT = 0;

    const drawAurora = () => {
      // Sweep 1 – ember bottom-right glow
      const g1 = ctx.createRadialGradient(
        W * 0.82 + Math.sin(auroraT * 0.4) * 30,
        H * 0.72 + Math.cos(auroraT * 0.3) * 20,
        0,
        W * 0.82,
        H * 0.72,
        W * 0.6
      );
      g1.addColorStop(0, 'rgba(255,77,0,0.08)');
      g1.addColorStop(0.5, 'rgba(255,42,0,0.04)');
      g1.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = g1;
      ctx.fillRect(0, 0, W, H);

      // Sweep 2 – cyan top-left shimmer
      const g2 = ctx.createRadialGradient(
        W * 0.12 + Math.cos(auroraT * 0.5) * 25,
        H * 0.22 + Math.sin(auroraT * 0.35) * 18,
        0,
        W * 0.12,
        H * 0.22,
        W * 0.45
      );
      g2.addColorStop(0, 'rgba(0,240,255,0.055)');
      g2.addColorStop(0.6, 'rgba(0,180,255,0.025)');
      g2.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = g2;
      ctx.fillRect(0, 0, W, H);

      // Sweep 3 – subtle center deep-blue
      const g3 = ctx.createRadialGradient(W * 0.5, H * 0.5, 0, W * 0.5, H * 0.5, W * 0.7);
      g3.addColorStop(0, 'rgba(20,10,40,0.18)');
      g3.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = g3;
      ctx.fillRect(0, 0, W, H);
    };

    // ── Connections ──────────────────────────────────────────────────
    const drawConnections = () => {
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i];
          const b = nodes[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist > CONNECTION_RADIUS) continue;

          const fade = 1 - dist / CONNECTION_RADIUS;
          const isThreatEdge = a.isThreat || b.isThreat;

          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);

          if (isThreatEdge) {
            ctx.strokeStyle = `rgba(255,77,0,${fade * 0.45})`;
            ctx.lineWidth = fade * 1.1;
          } else {
            ctx.strokeStyle = `rgba(120,140,180,${fade * 0.18})`;
            ctx.lineWidth = fade * 0.7;
          }
          ctx.stroke();
        }
      }
    };

    // ── Single node ──────────────────────────────────────────────────
    const drawNode = (n, t) => {
      const flicker = 0.75 + Math.sin(t * 2.2 + n.phase) * 0.25;
      const alpha = n.opacity * flicker;

      if (n.isThreat) {
        // Ember glow halo
        const halo = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.r * 5);
        halo.addColorStop(0, `rgba(255,77,0,${alpha * 0.55})`);
        halo.addColorStop(1, 'rgba(255,77,0,0)');
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r * 5, 0, Math.PI * 2);
        ctx.fillStyle = halo;
        ctx.fill();

        // Core dot
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,120,30,${alpha})`;
        ctx.fill();
      } else {
        // Dim node
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r * 0.85, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(160,180,220,${alpha * 0.65})`;
        ctx.fill();
      }
    };

    // ── Pulse ring on threat nodes ────────────────────────────────────
    const drawPulse = (n) => {
      if (!n.pulse) return;
      n.pulseTimer++;
      if (n.pulseTimer < n.pulseDelay) return;

      n.pulseRadius += 1.4;
      const maxR = 55;
      const pAlpha = Math.max(0, 0.55 * (1 - n.pulseRadius / maxR));

      ctx.beginPath();
      ctx.arc(n.x, n.y, n.pulseRadius, 0, Math.PI * 2);
      ctx.strokeStyle = n.isThreat
        ? `rgba(255,77,0,${pAlpha})`
        : `rgba(0,240,255,${pAlpha * 0.7})`;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      if (n.pulseRadius > maxR) {
        n.pulseRadius = 0;
        n.pulseTimer = 0;
        n.pulseDelay = 60 + Math.random() * 200;
      }
    };

    // ── Scan beam (a slowly rotating line from center) ───────────────
    let scanAngle = 0;
    const drawScanBeam = () => {
      const cx = W * 0.5;
      const cy = H * 0.5;
      const beamLen = Math.max(W, H) * 0.6;

      const grad = ctx.createLinearGradient(
        cx, cy,
        cx + Math.cos(scanAngle) * beamLen,
        cy + Math.sin(scanAngle) * beamLen
      );
      grad.addColorStop(0, 'rgba(255,77,0,0.12)');
      grad.addColorStop(0.4, 'rgba(255,77,0,0.04)');
      grad.addColorStop(1, 'rgba(255,77,0,0)');

      ctx.save();
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, beamLen, scanAngle - 0.22, scanAngle);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.restore();

      scanAngle += 0.006;
    };

    // ── Main animation loop ──────────────────────────────────────────
    let raf;
    let t = 0;

    const tick = () => {
      raf = requestAnimationFrame(tick);
      t += 0.016;
      auroraT += 0.008;

      // Clear
      ctx.clearRect(0, 0, W, H);

      // Background void
      ctx.fillStyle = '#05050a';
      ctx.fillRect(0, 0, W, H);

      // Aurora wash
      drawAurora();

      // Scan beam
      drawScanBeam();

      // Connections
      drawConnections();

      // Nodes: update position + draw
      for (const n of nodes) {
        n.x += n.vx;
        n.y += n.vy;

        // Soft wall bounce
        if (n.x < 0 || n.x > W) n.vx *= -1;
        if (n.y < 0 || n.y > H) n.vy *= -1;

        drawNode(n, t);
        drawPulse(n);
      }
    };

    tick();

    // ── Resize ───────────────────────────────────────────────────────
    const onResize = () => {
      W = canvas.offsetWidth;
      H = canvas.offsetHeight;
      canvas.width = W * window.devicePixelRatio;
      canvas.height = H * window.devicePixelRatio;
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    };
    window.addEventListener('resize', onResize);

    // ── Mouse interaction – attract nearby nodes ──────────────────────
    const onMouseMove = (e) => {
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      for (const n of nodes) {
        const dx = n.x - mx;
        const dy = n.y - my;
        const d = Math.sqrt(dx * dx + dy * dy);
        if (d < 90) {
          n.vx += (dx / d) * 0.12;
          n.vy += (dy / d) * 0.12;
          // Clamp speed
          const speed = Math.sqrt(n.vx * n.vx + n.vy * n.vy);
          if (speed > 1.4) { n.vx = (n.vx / speed) * 1.4; n.vy = (n.vy / speed) * 1.4; }
        }
      }
      if (onInteract) onInteract();
    };
    canvas.addEventListener('mousemove', onMouseMove);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', onResize);
      canvas.removeEventListener('mousemove', onMouseMove);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="w-full h-full block"
      style={{ background: 'transparent' }}
    />
  );
}
