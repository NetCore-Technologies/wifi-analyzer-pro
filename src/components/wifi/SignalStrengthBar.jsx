import React from 'react';

function hasSignal(rssi) {
  return rssi !== null && rssi !== undefined && rssi !== '' && Number.isFinite(Number(rssi)) && Number(rssi) >= -127 && Number(rssi) <= 0;
}
export function getSignalColor(rssi) {
  if (!hasSignal(rssi)) return { text: 'text-muted-foreground', bg: 'bg-muted', border: 'border-border', glow: 'shadow-none', label: 'Not measured' };
  const value = Number(rssi);
  if (value >= -55) return { text: 'text-green-400', bg: 'bg-green-400', border: 'border-green-400/30', glow: 'shadow-green-400/30', label: 'Excellent' };
  if (value >= -65) return { text: 'text-cyan-400', bg: 'bg-cyan-400', border: 'border-cyan-400/30', glow: 'shadow-cyan-400/30', label: 'Good' };
  if (value >= -75) return { text: 'text-yellow-400', bg: 'bg-yellow-400', border: 'border-yellow-400/30', glow: 'shadow-yellow-400/30', label: 'Fair' };
  if (value >= -85) return { text: 'text-orange-400', bg: 'bg-orange-400', border: 'border-orange-400/30', glow: 'shadow-orange-400/30', label: 'Weak' };
  return { text: 'text-red-400', bg: 'bg-red-400', border: 'border-red-400/30', glow: 'shadow-red-400/30', label: 'Poor' };
}
export function SignalBars({ rssi, size = 'md' }) {
  const valid = hasSignal(rssi);
  const quality = valid ? Math.max(0, Math.min(100, 2 * (Number(rssi) + 100))) : 0;
  const filled = valid ? Math.ceil(quality / 25) : 0;
  const color = getSignalColor(rssi);
  const heights = size === 'sm' ? ['h-2', 'h-3', 'h-4', 'h-5'] : ['h-3', 'h-4', 'h-6', 'h-8'];
  const width = size === 'sm' ? 'w-1.5' : 'w-2';
  return <div className="flex items-end gap-0.5" aria-label={valid ? String(rssi) + ' dBm, ' + color.label : 'Signal strength not measured'}>{heights.map((height, index) => <div key={height} className={`${width} ${height} rounded-sm transition-all duration-500 ${index < filled ? color.bg + ' shadow-sm ' + color.glow : 'bg-muted/40'}`} />)}</div>;
}
export function SignalStrengthBar({ rssi, showLabel = true }) {
  const valid = hasSignal(rssi);
  const quality = valid ? Math.max(0, Math.min(100, 2 * (Number(rssi) + 100))) : 0;
  const color = getSignalColor(rssi);
  return (
    <div className="space-y-1">
      <div className="flex justify-between items-center text-xs">
        <span className={`font-mono font-medium ${color.text}`}>{valid ? String(Number(rssi)) + ' dBm' : 'Not measured'}</span>
        {showLabel && <span className={`${color.text} font-medium`}>{color.label}</span>}
      </div>
      <div className="h-1.5 bg-muted/40 rounded-full overflow-hidden">{valid && <div className={`h-full ${color.bg} rounded-full transition-all duration-700 ease-out`} style={{ width: quality + '%' }} />}</div>
    </div>
  );
}
