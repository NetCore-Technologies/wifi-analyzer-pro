import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Wifi, Lock, Unlock, Zap, Activity, Radio } from 'lucide-react';
import { SignalBars, SignalStrengthBar, getSignalColor } from './SignalStrengthBar';

function metric(value, unit) {
  if (value === null || value === undefined || value === '') return '—';
  const number = Number(value);
  return Number.isFinite(number) ? String(number) + unit : '—';
}
function frequency(value) {
  if (value === null || value === undefined || value === '') return '—';
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return '—';
  return number >= 1000 ? String(number) + ' MHz' : String(number) + ' GHz';
}

export default function NetworkCard({ network, index, isSelected, onClick }) {
  const color = getSignalColor(network?.rssi);
  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.04, duration: 0.3 }}
      className={`glass rounded-xl p-4 cursor-pointer transition-all duration-200 hover:border-primary/30 ${isSelected ? 'border-primary/50 glow-cyan' : 'border-border hover:scale-[1.01]'}`}
      onClick={onClick} role="button" tabIndex={0} aria-pressed={Boolean(isSelected)}
      onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onClick?.(); } }}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className={`p-2 rounded-lg ${color.bg}/10 border ${color.border} mt-0.5 flex-shrink-0`}><Wifi className={`w-4 h-4 ${color.text}`} /></div>
          <div className="min-w-0">
            <div className="font-semibold text-foreground truncate">{network?.ssid || '<Hidden>'}</div>
            <div className="text-xs font-mono text-muted-foreground mt-0.5">{network?.bssid || 'BSSID unavailable'}</div>
            <div className="flex items-center gap-2 mt-1.5 flex-wrap">
              <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${color.text} ${color.border} bg-card`}>{network?.band || 'Band unknown'}</span>
              <span className="text-xs px-2 py-0.5 rounded-full border border-border text-muted-foreground bg-card">{network?.channel == null ? 'Channel unknown' : 'Ch ' + network.channel}</span>
              <span className="text-xs px-2 py-0.5 rounded-full border border-border text-muted-foreground bg-card flex items-center gap-1">{network?.security === 'Open' ? <Unlock className="w-2.5 h-2.5" /> : <Lock className="w-2.5 h-2.5" />}{network?.security || 'Security unknown'}</span>
            </div>
          </div>
        </div>
        <div className="flex flex-col items-end gap-2 flex-shrink-0"><SignalBars rssi={network?.rssi} /><span className={`text-sm font-mono font-bold ${color.text}`}>{metric(network?.rssi, ' dBm')}</span></div>
      </div>
      <AnimatePresence>
        {isSelected && <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.25 }} className="overflow-hidden">
          <div className="pt-4 mt-4 border-t border-border grid grid-cols-2 gap-3">
            <Metric icon={Activity} label="RSRP" value={metric(network?.rsrp, ' dBm')} color={color.text} />
            <Metric icon={Activity} label="RSRQ" value={metric(network?.rsrq, ' dB')} color={color.text} />
            <Metric icon={Radio} label="SNR" value={metric(network?.snr, ' dB')} color={color.text} />
            <Metric icon={Radio} label="SINR" value={metric(network?.sinr, ' dB')} color={color.text} />
            <Metric icon={Radio} label="Signal Quality" value={metric(network?.signal_pct, '%')} color={color.text} />
            <Metric icon={Zap} label="Link Speed" value={metric(network?.link_speed, ' Mbps')} color={color.text} />
            <Metric icon={Wifi} label="Frequency" value={frequency(network?.frequency)} color={color.text} />
            <div className="col-span-2"><SignalStrengthBar rssi={network?.rssi} /></div>
          </div>
        </motion.div>}
      </AnimatePresence>
    </motion.div>
  );
}
function Metric({ icon: Icon, label, value, color }) {
  return <div className="bg-secondary/50 rounded-lg p-2.5"><div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1"><Icon className="w-3 h-3" />{label}</div><div className={`text-sm font-mono font-semibold ${color}`}>{value}</div></div>;
}
