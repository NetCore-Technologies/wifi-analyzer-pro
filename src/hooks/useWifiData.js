import { useState, useEffect, useCallback, useRef } from 'react';
import { apiBase, apiFetch } from '../lib/api.js';
import { getScanSource } from '../lib/observationProvenance.js';
import { appendSignalHistory } from '../lib/telemetryHistory.js';

const MOCK_NETWORKS = [
  { ssid: 'HomeNetwork_5G', bssid: 'AA:BB:CC:DD:EE:01', rssi: -48, channel: 36, band: '5GHz', frequency: 5.18, security: 'WPA3', security_detail: 'WPA3', noise: -95, snr: 47, rsrp: -48, rsrq: -8, sinr: 44, link_speed: 867, quality: 100 },
  { ssid: 'HomeNetwork_2G', bssid: 'AA:BB:CC:DD:EE:02', rssi: -55, channel: 6, band: '2.4GHz', frequency: 2.437, security: 'WPA2', security_detail: 'WPA2', noise: -95, snr: 40, rsrp: -55, rsrq: -10, sinr: 37, link_speed: 300, quality: 90 },
  { ssid: 'Neighbor_WiFi', bssid: 'AA:BB:CC:DD:EE:03', rssi: -68, channel: 11, band: '2.4GHz', frequency: 2.462, security: 'WPA2', security_detail: 'WPA2', noise: -95, snr: 27, rsrp: -68, rsrq: -14, sinr: 24, link_speed: 72, quality: 64 },
  { ssid: 'Office_Network', bssid: 'AA:BB:CC:DD:EE:04', rssi: -72, channel: 48, band: '5GHz', frequency: 5.24, security: 'WPA2/WPA3', security_detail: 'WPA2/WPA3', noise: -95, snr: 23, rsrp: -72, rsrq: -16, sinr: 20, link_speed: 216, quality: 56 },
  { ssid: 'GuestNet', bssid: 'AA:BB:CC:DD:EE:05', rssi: -80, channel: 1, band: '2.4GHz', frequency: 2.412, security: 'Open', security_detail: 'Open', noise: -95, snr: 15, rsrp: -80, rsrq: -19, sinr: 12, link_speed: 36, quality: 40 },
  { ssid: 'Corp_Secure', bssid: 'AA:BB:CC:DD:EE:06', rssi: -63, channel: 100, band: '5GHz', frequency: 5.5, security: 'WPA2', security_detail: 'WPA2-Enterprise', noise: -95, snr: 32, rsrp: -63, rsrq: -12, sinr: 29, link_speed: 433, quality: 74 },
  { ssid: 'IoT_Hub', bssid: 'AA:BB:CC:DD:EE:07', rssi: -85, channel: 6, band: '2.4GHz', frequency: 2.437, security: 'WPA2', security_detail: 'WPA2', noise: -95, snr: 10, rsrp: -85, rsrq: -20, sinr: 7, link_speed: 11, quality: 30 },
];

function requestSignal(controller, timeoutMs) {
  const timeout = AbortSignal.timeout(timeoutMs);
  return typeof AbortSignal.any === 'function' ? AbortSignal.any([controller.signal, timeout]) : controller.signal;
}

export default function useWifiData(autoRefresh = true, interval = 5000) {
  const [networks, setNetworks] = useState(MOCK_NETWORKS);
  const [congestion, setCongestion] = useState({});
  const [systemInfo, setSystemInfo] = useState({ os: 'Demo Mode' });
  const [phyInfo, setPhyInfo] = useState(null);
  const [linkStats, setLinkStats] = useState(null);
  const [diagnostics, setDiagnostics] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [backendConnected, setBackendConnected] = useState(false);
  const [observationSource, setObservationSource] = useState('demo');
  const [dataStale, setDataStale] = useState(false);
  const [lastScan, setLastScan] = useState(null);
  const [history, setHistory] = useState({});
  const [devices, setDevices] = useState([]);
  const requestControllerRef = useRef(null);
  const requestSequenceRef = useRef(0);
  const hasLiveDataRef = useRef(false);

  const fetchData = useCallback(async () => {
    requestControllerRef.current?.abort();
    const controller = new AbortController();
    requestControllerRef.current = controller;
    const requestId = ++requestSequenceRef.current;
    setLoading(true);

    try {
      const responses = await Promise.all([
        apiFetch(apiBase() + '/api/scan', { signal: requestSignal(controller, 15000) }),
        apiFetch(apiBase() + '/api/system', { signal: requestSignal(controller, 5000) }),
        apiFetch(apiBase() + '/api/phy', { signal: requestSignal(controller, 8000) }),
        apiFetch(apiBase() + '/api/link', { signal: requestSignal(controller, 8000) }),
        apiFetch(apiBase() + '/api/diagnostics', { signal: requestSignal(controller, 18000) }),
        apiFetch(apiBase() + '/api/devices', { signal: requestSignal(controller, 10000) }),
      ]);
      if (requestId !== requestSequenceRef.current) return;
      if (responses.some(response => !response.ok)) throw new Error('One or more local API requests failed.');

      const [scanData, sysData, phyData, linkData, diagData, devData] = await Promise.all(responses.map(response => response.json()));
      if (requestId !== requestSequenceRef.current) return;

      const source = getScanSource(scanData);
      if (source === 'unknown' || !Array.isArray(scanData.networks)) {
        throw new Error('The scan endpoint returned invalid or unverified observations.');
      }

      const timestamp = Number(scanData.timestamp);
      const sampledAt = Number.isFinite(timestamp) && timestamp > 0 ? timestamp * 1000 : Date.now();
      setNetworks(scanData.networks);
      setCongestion(scanData.congestion && typeof scanData.congestion === 'object' ? scanData.congestion : {});
      setSystemInfo(sysData);
      setPhyInfo(phyData);
      setLinkStats(linkData);
      setDiagnostics(diagData);
      setDevices(Array.isArray(devData.devices) ? devData.devices : []);
      setBackendConnected(true);
      setObservationSource(source);
      setDataStale(false);
      hasLiveDataRef.current = source === 'live';
      setError(null);
      setLastScan(Number.isFinite(timestamp) && timestamp > 0 ? new Date(timestamp * 1000) : null);
      setHistory(previous => appendSignalHistory(previous, scanData.networks, sampledAt));
    } catch {
      if (controller.signal.aborted || requestId !== requestSequenceRef.current) return;
      setBackendConnected(false);
      setDataStale(hasLiveDataRef.current);
      setError(hasLiveDataRef.current
        ? 'Local API unavailable. The last live observations are retained and marked stale.'
        : 'Local API unavailable. Only clearly labelled demo observations are shown.');
    } finally {
      if (requestId === requestSequenceRef.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    let timer = null;
    const poll = async () => {
      await fetchData();
      if (active && autoRefresh && interval > 0) timer = setTimeout(poll, interval);
    };
    void poll();
    return () => {
      active = false;
      if (timer !== null) clearTimeout(timer);
      requestSequenceRef.current += 1;
      requestControllerRef.current?.abort();
      requestControllerRef.current = null;
    };
  }, [fetchData, autoRefresh, interval]);

  return {
    networks, congestion, systemInfo, phyInfo, linkStats, diagnostics, devices,
    loading, error, backendConnected, observationSource, dataStale, lastScan, history,
    refresh: fetchData,
  };
}
