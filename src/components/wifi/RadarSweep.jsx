import React, { useEffect, useRef } from 'react';

export default function RadarSweep({ networks = [], scanning = false }) {
  const canvasRef = useRef(null);
  const animRef = useRef(null);
  const angleRef = useRef(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return undefined;
    const ctx = canvas.getContext('2d');
    if (!ctx) return undefined;
    const size = canvas.width;
    const center = size / 2;
    const radius = size / 2 - 8;
    const dots = networks.slice(0, 24).map((net, index) => {
      const parsed = net?.rssi === null || net?.rssi === undefined ? NaN : Number(net.rssi);
      const valid = Number.isFinite(parsed) && parsed >= -127 && parsed <= 0;
      const strength = valid ? Math.max(0.12, Math.min(0.95, (parsed + 100) / 70)) : 0.12;
      return {
        x: center + Math.cos(index / Math.max(networks.length, 1) * Math.PI * 2) * strength * radius,
        y: center + Math.sin(index / Math.max(networks.length, 1) * Math.PI * 2) * strength * radius,
        rssi: valid ? parsed : null,
        visible: !scanning,
        alpha: 1,
      };
    });

    const draw = () => {
      ctx.clearRect(0, 0, size, size);
      ctx.strokeStyle = 'rgba(0, 212, 255, 0.08)';
      ctx.lineWidth = 1;
      [0.25, 0.5, 0.75, 1].forEach(scale => {
        ctx.beginPath();
        ctx.arc(center, center, radius * scale, 0, Math.PI * 2);
        ctx.stroke();
      });
      ctx.strokeStyle = 'rgba(0, 212, 255, 0.06)';
      ctx.beginPath();
      ctx.moveTo(center - radius, center);
      ctx.lineTo(center + radius, center);
      ctx.moveTo(center, center - radius);
      ctx.lineTo(center, center + radius);
      ctx.stroke();

      if (scanning) {
        angleRef.current = (angleRef.current + 0.025) % (Math.PI * 2);
        const angle = angleRef.current;
        ctx.save();
        ctx.beginPath();
        ctx.moveTo(center, center);
        ctx.arc(center, center, radius, angle - 1.2, angle);
        ctx.closePath();
        const gradient = ctx.createLinearGradient(center, center, center + radius, center);
        gradient.addColorStop(0, 'rgba(0,212,255,0)');
        gradient.addColorStop(1, 'rgba(0,212,255,0.15)');
        ctx.fillStyle = gradient;
        ctx.fill();
        ctx.restore();
        ctx.strokeStyle = 'rgba(0,212,255,0.7)';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(center, center);
        ctx.lineTo(center + Math.cos(angle) * radius, center + Math.sin(angle) * radius);
        ctx.stroke();
        dots.forEach(dot => { dot.visible = true; });
      }

      dots.forEach(dot => {
        if (!dot.visible) return;
        const color = dot.rssi === null ? '148,163,184' : dot.rssi >= -55 ? '74,222,128' : dot.rssi >= -65 ? '0,212,255' : dot.rssi >= -75 ? '250,204,21' : '248,113,113';
        ctx.beginPath();
        ctx.arc(dot.x, dot.y, 4.5, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(' + color + ',' + dot.alpha + ')';
        ctx.fill();
      });
      ctx.beginPath();
      ctx.arc(center, center, 4, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0,212,255,0.8)';
      ctx.fill();

      if (scanning) animRef.current = requestAnimationFrame(draw);
    };

    draw();
    return () => {
      if (animRef.current !== null) cancelAnimationFrame(animRef.current);
    };
  }, [networks, scanning]);

  return <canvas ref={canvasRef} width={220} height={220} className="rounded-full" role="img" aria-label="Abstract, non-spatial relative signal visualisation" style={{ imageRendering: 'crisp-edges' }} />;
}
