import React from 'react';
import { motion } from 'framer-motion';
import { Radio } from 'lucide-react';
import { WIFI_BANDS, rankObservedChannels } from '../../lib/rfPlanningEvidence.js';

function BandCard({ band, networks }) {
  const ordered = rankObservedChannels(networks, band);
  if (!ordered.length) {
    return (
      <div className="glass rounded-xl p-4 space-y-2">
        <div className="flex items-center gap-2"><Radio className="w-4 h-4 text-primary" /><span className="text-sm font-semibold text-foreground">{band}</span></div>
        <div className="text-xs text-muted-foreground">No channel observations in this scan. No candidate is inferred.</div>
      </div>
    );
  }
  const best = ordered[0];
  const maximum = Math.max(...ordered.map(item => item.count), 1);
  return (
    <div className="glass rounded-xl p-4 space-y-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2"><Radio className="w-4 h-4 text-primary" /><span className="text-sm font-semibold text-foreground">{band}</span></div>
        <span className="text-xs text-primary font-medium">Lowest observed: Ch {best.channel}</span>
      </div>
      <div className="text-xs text-muted-foreground">{ordered.reduce((sum, item) => sum + item.count, 0)} observed BSS records across {ordered.length} channel{ordered.length === 1 ? '' : 's'}.</div>
      <div className="space-y-1.5">
        {ordered.map(item => (
          <div key={item.channel} className="flex items-center gap-2">
            <span className="text-xs font-mono text-muted-foreground w-10 text-right">{item.channel}</span>
            <div className="flex-1 h-1.5 rounded-full bg-primary/10"><div className={`h-1.5 rounded-full ${item.channel === best.channel ? 'bg-primary' : 'bg-muted-foreground/50'}`} style={{ width: (item.count / maximum * 100) + '%' }} /></div>
            <span className="text-xs text-muted-foreground w-5 text-right">{item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ChannelRecommendPanel({ networks = [] }) {
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
      <p className="text-xs text-muted-foreground">These are scan-relative candidates, not automatic channel recommendations. The scan does not measure airtime utilisation, RF power, channel width, regulatory permissions, DFS/CAC state or neighbouring AP transmit power. Validate a complete site survey and country-specific rules before changing production radios.</p>
      {WIFI_BANDS.map(band => <BandCard key={band} band={band} networks={networks} />)}
    </motion.div>
  );
}
