import React from 'react';
import { motion } from 'framer-motion';
import { Wifi, Shield, ShieldOff, Activity, Cpu } from 'lucide-react';
import { getSignalColor } from './SignalStrengthBar';

export default function StatsBar({ networks = [], systemInfo }) {
  const measured = networks.filter(net => net?.rssi !== null && net?.rssi !== undefined && net.rssi !== '' && Number.isFinite(Number(net.rssi)) && Number(net.rssi) >= -127 && Number(net.rssi) <= 0);
  const best = measured.reduce((strongest, net) => Number(net.rssi) > Number(strongest.rssi) ? net : strongest, null);
  const bands = {
    '2.4 GHz': networks.filter(net => net.band === '2.4GHz').length,
    '5 GHz': networks.filter(net => net.band === '5GHz').length,
    '6 GHz': networks.filter(net => net.band === '6GHz').length,
  };
  const open = networks.filter(net => net.security === 'Open').length;
  const bestColor = getSignalColor(best?.rssi);
  const stats = [
    { label: 'BSS Records', value: networks.length, icon: Wifi, color: 'text-primary' },
    { label: 'Best Measured RSSI', value: best ? Number(best.rssi) + ' dBm' : '—', icon: Activity, color: bestColor.text },
    { label: '2.4 GHz', value: bands['2.4 GHz'], icon: Activity, color: 'text-cyan-400' },
    { label: '5 GHz', value: bands['5 GHz'], icon: Activity, color: 'text-purple' },
    { label: '6 GHz', value: bands['6 GHz'], icon: Activity, color: 'text-blue-400' },
    { label: 'Open Security', value: open, icon: open > 0 ? ShieldOff : Shield, color: open > 0 ? 'text-red-400' : 'text-green-400' },
  ];

  const cpu = systemInfo?.cpu_pct ?? systemInfo?.cpu_percent;
  const ram = systemInfo?.ram_pct ?? systemInfo?.memory_percent;
  const disk = systemInfo?.disk_pct;
  if (cpu != null && Number.isFinite(Number(cpu))) stats.push({ label: 'CPU', value: Number(cpu) + '%', icon: Cpu, color: 'text-muted-foreground' });
  if (ram != null && Number.isFinite(Number(ram))) stats.push({ label: 'RAM', value: Number(ram) + '%', icon: Cpu, color: 'text-muted-foreground' });
  if (disk != null && Number.isFinite(Number(disk))) stats.push({ label: 'Disk', value: Number(disk) + '%', icon: Cpu, color: 'text-muted-foreground' });

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-8 gap-3">
      {stats.map((stat, index) => (
        <motion.div key={stat.label} initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}
          transition={{ delay: index * 0.04 }} className="glass rounded-xl p-3">
          <div className="flex items-center gap-2 mb-1"><stat.icon className={`w-3.5 h-3.5 ${stat.color}`} /><span className="text-xs text-muted-foreground truncate">{stat.label}</span></div>
          <div className={`text-xl font-bold font-mono ${stat.color}`}>{stat.value}</div>
        </motion.div>
      ))}
    </div>
  );
}
