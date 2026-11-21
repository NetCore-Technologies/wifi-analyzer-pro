import { useState, useEffect, useCallback, useRef } from 'react';
import { apiBase, apiFetch } from '../lib/api.js';
import { getScanSource } from '../lib/observationProvenance.js';

const MOCK_NETWORKS = [
  { ssid: 'HomeNetwork_5G', bssid: 'AA:BB:CC:DD:EE:01', rssi: -48, channel: 36, band: '5GHz', frequency: 5.18, security: 'WPA3', security_detail: 'WPA3', noise: -95, snr: 47, rsrp: -48, rsrq: -8, sinr: 44, link_speed: 867, quality: 104 },
  { ssid: 'HomeNetwork_2G', bssid: 'AA:BB:CC:DD:EE:02', rssi: -55, channel: 6, band: '2.4GHz', frequency: 2.437, security: 'WPA2', security_detail: 'WPA2', noise: -95, snr: 40, rsrp: -55, rsrq: -10, sinr: 37, link_speed: 300, quality: 90 },
  { ssid: 'Neighbor_WiFi', bssid: 'AA:BB:CC:DD:EE:03', rssi: -68, channel: 11, band: '2.4GHz', frequency: 2.462, security: 'WPA2', security_detail: 'WPA2', noise: -95, snr: 27, rsrp: -68, rsrq: -14, sinr: 24, link_speed: 72, quality: 64 },
  { ssid: 'Office_Network', bssid: 'AA:BB:CC:DD:EE:04', rssi: -72, channel: 48, band: '5GHz', frequency: 5.24, security: 'WPA2/WPA3', security_detail: 'WPA2/WPA3', noise: -95, snr: 23, rsrp: -72, rsrq: -16, sinr: 20, link_speed: 216, quality: 56 },
  { ssid: 'GuestNet', bssid: 'AA:BB:CC:DD:EE:05', rssi: -80, channel: 1, band: '2.4GHz', frequency: 2.412, security: 'Open', security_detail: 'Open', noise: -95, snr: 15, rsrp: -80, rsrq: -19, sinr: 12, link_speed: 36, quality: 40 },
  { ssid: 'Corp_Secure', bssid: 'AA:BB:CC:DD:EE:06', rssi: -63, channel: 100, band: '5GHz', frequency: 5.5, security: 'WPA2', security_detail: 'WPA2-Enterprise', noise: -95, snr: 32, rsrp: -63, rsrq: -12, sinr: 29, link_speed: 433, quality: 74 },
  { ssid: 'IoT_Hub', bssid: 'AA:BB:CC:DD:EE:07', rssi: -85, channel: 6, band: '2.4GHz', frequency: 2.437, security: 'WPA2', security_detail: 'WPA2', noise: -95, snr: 10, rsrp: -85, rsrq: -20, sinr: 7, link_speed: 11, quality: 30 },
];

export default function useWifiData(autoRefresh = true, interval = 5000) {
  const [networks, setNetworks] = useState(MOCK_NETWORKS);
  const [congestion, setCongestion] = useState({ '2.4GHz': { 1: 2, 6: 3, 11: 1 }, '5GHz': { 36: 1, 48: 1, 100: 1 } });
  const [systemInfo, setSystemInfo] = useState({ os: 'Demo Mode' });
  const [phyInfo, setPhyInfo] = useState(null);
  const [linkStats, setLinkStats] = useState(null);
  const [diagnostics, setDiagnostics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [backendConnected, setBackendConnected] = useState(false);
  const [observationSource, setObservationSource] = useState('demo');
  const [lastScan, setLastScan] = useState(null);
  const [history, setHistory] = useState({});
  const [devices, setDevices] = useState([]);
  const timerRef = useRef(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [scanRes, sysRes, phyRes, linkRes, diagRes, devRes] = await Promise.all([
        apiFetch(`${apiBase()}/api/scan`, { signal: AbortSignal.timeout(15000) }),
        apiFetch(`${apiBase()}/api/system`, { signal: AbortSignal.timeout(5000) }),
        apiFetch(`${apiBase()}/api/phy`, { signal: AbortSignal.timeout(8000) }),
        apiFetch(`${apiBase()}/api/link`, { signal: AbortSignal.timeout(8000) }),
        apiFetch(`${apiBase()}/api/diagnostics`, { signal: AbortSignal.timeout(18000) }),
        apiFetch(`${apiBase()}/api/devices`, { signal: AbortSignal.timeout(10000) }),
      ]);
      if ([scanRes, sysRes, phyRes, linkRes, diagRes, devRes].some(response => !response.ok)) {
        throw new Error('One or more local API requests failed.');
      }
      const scanData = await scanRes.json();
      const source = getScanSource(scanData);
      if (source === 'unknown' || !Array.isArray(scanData.networks)) {
        throw new Error('The scan endpoint returned invalid or unverified observations.');
      }
      const sysData = await sysRes.json();
      const phyData = await phyRes.json();
      const linkData = await linkRes.json();
      const diagData = await diagRes.json();
      const devData = await devRes.json();
      setNetworks(scanData.networks || []);
      setCongestion(scanData.congestion || {});
      setSystemInfo(sysData);
      setPhyInfo(phyData);
      setLinkStats(linkData);
      setDiagnostics(diagData);
      setDevices(devData.devices || []);
      setBackendConnected(true);
      setObservationSource(source);
      setError(null);
      const scanTimestamp = Number(scanData.timestamp);
      setLastScan(Number.isFinite(scanTimestamp) && scanTimestamp > 0
        ? new Date(scanTimestamp * 1000)
        : new Date());
      setHistory(prev => {
        const now = Date.now();
        const updated = { ...prev };
        (scanData.networks || []).forEach(net => {
          const key = net.bssid;
          if (!updated[key]) updated[key] = [];
          updated[key] = [...updated[key].slice(-29), { t: now, rssi: net.rssi }];
        });
        return updated;
      });
    } catch {
      setBackendConnected(false);
      setError('Local API unavailable. Live observations are paused; sample data remains clearly labelled.');
      setObservationSource('demo');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    if (autoRefresh) timerRef.current = setInterval(fetchData, interval);
    return () => clearInterval(timerRef.current);
  }, [fetchData, autoRefresh, interval]);

  return { networks, congestion, systemInfo, phyInfo, linkStats, diagnostics, devices, loading, error, backendConnected, observationSource, lastScan, history, refresh: fetchData };
}
