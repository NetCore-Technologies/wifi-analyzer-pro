import React, { useMemo } from 'react';
import { motion } from 'framer-motion';
import { ArrowRightLeft, Info, Radio } from 'lucide-react';
import { getSignalColor } from './SignalStrengthBar';
import { summariseBandPresence } from '../../lib/bandObservation.js';

const BAND_LABELS = ["2.4GHz", "5GHz", "6GHz"];

function BandObservation({ band, details }) {
  const strongest = details.strongest;
  const color = getSignalColor(strongest?.rssi);
  return (
    <div className="rounded-lg p-3 border border-border bg-secondary/30 min-w-0">
      <div className="text-xs text-muted-foreground mb-1">{band}</div>
      <div className="text-sm font-semibold text-foreground">{details.bss_count} BSS record{details.bss_count === 1 ? '' : 's'}</div>
      {strongest ? (
        <>
          <div className={`font-mono font-bold text-sm mt-1 ${color.text}`}>{strongest.rssi} dBm strongest observed</div>
          <div className="text-[11px] text-muted-foreground truncate">{strongest.bssid || 'BSSID not reported'} · {strongest.channel == null ? 'Channel unknown' : 'Ch ' + strongest.channel}</div>
        </>
      ) : (
        <div className="text-xs text-muted-foreground mt-1">No valid RSSI measurement for this band</div>
      )}
    </div>
  );
}

function NetworkGroup({ summary, multiBand }) {
  return (
    <div className="glass rounded-xl p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-semibold text-foreground truncate">{summary.ssid}</span>
        <span className="text-xs text-muted-foreground">{summary.total_bss_count} observed BSS record{summary.total_bss_count === 1 ? '' : 's'}</span>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
        {BAND_LABELS.filter(band => summary.bands[band].bss_count > 0).map(band => (
          <BandObservation key={band} band={band} details={summary.bands[band]} />
        ))}
      </div>
      {summary.unknown_band_count > 0 && (
        <div className="text-xs text-muted-foreground">{summary.unknown_band_count} record(s) have no reliable band information.</div>
      )}
      {multiBand && (
        <div className="text-xs text-primary">Same SSID observed on multiple bands. This does not establish shared AP hardware or client band-steering support.</div>
      )}
    </div>
  );
}

export default function BandSteeringPanel({ networks = [] }) {
  const result = useMemo(() => summariseBandPresence(networks), [networks]);
  const totalVisible = result.multiBand.length + result.singleOrUnknownBand.length;

  if (!Array.isArray(networks) || !networks.length) {
    return <div className="text-center py-8 text-muted-foreground text-sm">No network observations are available yet.</div>;
  }

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
      <div className="glass rounded-xl p-4 flex items-start gap-2">
        <Info className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
        <p className="text-xs text-muted-foreground">
          Scan results can show that the same visible SSID is advertised on multiple frequency bands. They cannot show that the BSSIDs belong to one physical AP, that a controller has band steering enabled, or which band a client should use. Client association and controller policy evidence are required for those conclusions.
        </p>
      </div>

      {result.multiBand.length > 0 && (
        <section className="space-y-3">
          <h3 className="text-sm font-semibold text-muted-foreground flex items-center gap-2">
            <ArrowRightLeft className="w-4 h-4 text-primary" /> Same-SSID multi-band observations
          </h3>
          {result.multiBand.map(summary => <NetworkGroup key={summary.ssid} summary={summary} multiBand />)}
        </section>
      )}

      {result.singleOrUnknownBand.length > 0 && (
        <section className="space-y-3">
          <h3 className="text-sm font-semibold text-muted-foreground flex items-center gap-2">
            <Radio className="w-4 h-4 text-muted-foreground" /> Single-band or incomplete band evidence
          </h3>
          {result.singleOrUnknownBand.map(summary => <NetworkGroup key={summary.ssid} summary={summary} multiBand={false} />)}
        </section>
      )}

      {result.hiddenBssCount > 0 && (
        <div className="glass rounded-xl p-3 text-xs text-muted-foreground">
          {result.hiddenBssCount} hidden-SSID BSS record(s) cannot be grouped by SSID, so they are excluded from cross-band presence analysis.
        </div>
      )}
      {totalVisible === 0 && result.hiddenBssCount === 0 && (
        <div className="glass rounded-xl p-8 text-center text-sm text-muted-foreground">No valid visible SSID records are available for cross-band analysis.</div>
      )}
    </motion.div>
  );
}
