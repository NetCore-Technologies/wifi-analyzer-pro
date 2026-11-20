import { useCallback, useEffect, useState } from 'react';
import { LockKeyhole, ShieldCheck, RefreshCw, Wifi } from 'lucide-react';
import { AuthContext } from './AuthContext.jsx';
import { apiBase, getSessionToken, setSessionToken } from '../lib/api.js';

const fieldStyle = {
  width: '100%', boxSizing: 'border-box', padding: '12px 14px', borderRadius: 8,
  background: '#111827', border: '1px solid #2a3f65', color: '#e2e8f0', outline: 'none',
};
const buttonStyle = {
  width: '100%', padding: '12px 14px', borderRadius: 8, border: '1px solid #06d6f0',
  background: 'rgba(6,214,240,.13)', color: '#06d6f0', fontWeight: 700, cursor: 'pointer',
};

export default function AuthGate({ children }) {
  const [mode, setMode] = useState('checking');
  const [password, setPassword] = useState('');
  const [username, setUsername] = useState('admin');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [identity, setIdentity] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const refreshStatus = useCallback(async () => {
    setMode('checking');
    setError('');
    try {
      const response = await fetch(`${apiBase()}/api/auth/status`, {
        headers: getSessionToken() ? { Authorization: `Bearer ${getSessionToken()}` } : {},
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw new Error(`Backend returned HTTP ${response.status}`);
      const status = await response.json();
      if (status.broken) {
        setSessionToken('');
        setIdentity(null);
        setMode('recovery');
        setError('The saved local auth file is unreadable. Restore a valid backup or remove the file manually on the host before signing in again.');
      } else if (!status.configured) {
        setIdentity(null);
        setMode('setup');
      } else if (status.authenticated) {
        setIdentity(status.identity || null);
        setMode('ready');
      } else {
        setSessionToken('');
        setIdentity(null);
        setMode('login');
      }
    } catch (err) {
      setMode('unavailable');
      setError(err.message || 'The local backend could not be reached.');
    }
  }, []);

  useEffect(() => {
    refreshStatus();
    const onExpired = () => { setMode('login'); setPassword(''); setIdentity(null); setNotice('Your session expired. Please sign in again.'); };
    window.addEventListener('wifi-analyzer:auth-expired', onExpired);
    return () => window.removeEventListener('wifi-analyzer:auth-expired', onExpired);
  }, [refreshStatus]);

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true); setError(''); setNotice('');
    try {
      const endpoint = mode === 'setup' ? '/api/auth/setup' : '/api/auth/login';
      const response = await fetch(`${apiBase()}${endpoint}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password,
          ...(mode === 'login' && mfaCode.trim() ? { code: mfaCode.trim() } : {}),
        }),
        signal: AbortSignal.timeout(10000),
      });
      const payload = await response.json();
      if (!response.ok) {
        if (payload.mfa_required) setMfaRequired(true);
        throw new Error(payload.error || `Authentication failed (${response.status})`);
      }
      setSessionToken(payload.token);
      setIdentity(payload.status?.identity || null);
      setPassword(''); setMfaCode(''); setMfaRequired(false); setMode('ready');
      if (endpoint.endsWith('/setup')) setNotice('Local account password configured.');
    } catch (err) {
      setError(err.message || 'Authentication failed.');
    } finally { setBusy(false); }
  };

  const logout = useCallback(async () => {
    const token = getSessionToken();
    try {
      await fetch(`${apiBase()}/api/auth/logout`, {
        method: 'POST', headers: token ? { Authorization: `Bearer ${token}` } : {},
        signal: AbortSignal.timeout(4000),
      });
    } catch { /* Clear the browser token even when the server is unavailable. */ }
    setSessionToken(''); setIdentity(null); setMode('login'); setNotice('You have been logged out.');
  }, []);

  if (mode === 'ready') {
    return <AuthContext.Provider value={{ logout, identity }}>{children}</AuthContext.Provider>;
  }

  return (
    <div style={{ minHeight: '100vh', background: '#070b14', color: '#e2e8f0', display: 'grid', placeItems: 'center', padding: 20, fontFamily: 'system-ui, sans-serif' }}>
      <div style={{ width: 'min(100%, 420px)', background: '#0c1120', border: '1px solid #1e2d47', borderRadius: 14, padding: 28, boxShadow: '0 20px 80px rgba(0,0,0,.4)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
          <div style={{ width: 38, height: 38, display: 'grid', placeItems: 'center', borderRadius: 10, background: 'rgba(6,214,240,.1)', color: '#06d6f0' }}><Wifi size={20}/></div>
          <div><div style={{ fontWeight: 800 }}>WiFi Analyzer Pro</div><div style={{ fontSize: 11, color: '#06d6f0' }}>LOCAL ACCOUNT</div></div>
        </div>
        {mode === 'checking' ? <p style={{ color: '#94a3b8' }}>Checking the local backend…</p> : null}
        {mode === 'recovery' ? <>
          <h2 style={{ fontSize: 20, margin: '0 0 8px' }}>Account recovery required</h2>
          <p style={{ color: '#94a3b8', fontSize: 13 }}>The backend failed closed because its saved password verifier cannot be read. No new account can be created over this screen.</p>
          <button style={buttonStyle} onClick={refreshStatus}><RefreshCw size={14} style={{ verticalAlign: 'middle', marginRight: 8 }}/>Retry account status</button>
        </> : null}
        {mode === 'unavailable' ? <>
          <h2 style={{ fontSize: 20, margin: '0 0 8px' }}>Backend unavailable</h2>
          <p style={{ color: '#94a3b8', fontSize: 13 }}>Start the WiFi Analyzer backend to sign in.</p>
          <pre style={{ ...fieldStyle, fontSize: 12, overflow: 'auto' }}>python wifi_analyzer_backend/server.py</pre>
          <button style={buttonStyle} onClick={refreshStatus}><RefreshCw size={14} style={{ verticalAlign: 'middle', marginRight: 8 }}/>Retry connection</button>
        </> : null}
        {mode === 'setup' || mode === 'login' ? <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            {mode === 'setup' ? <ShieldCheck color="#22c55e"/> : <LockKeyhole color="#06d6f0"/>}
            <h2 style={{ fontSize: 20, margin: 0 }}>{mode === 'setup' ? 'Create your local password' : 'Welcome back'}</h2>
          </div>
          <p style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.6, marginBottom: 20 }}>
            {mode === 'setup' ? 'This first-run password protects the local API. It is stored as a salted scrypt verifier in your user config directory.' : 'Enter your local password to unlock the analyzer.'}
          </p>
          <form onSubmit={submit} style={{ display: 'grid', gap: 12 }}>
            <label style={{ fontSize: 12, color: '#94a3b8' }} htmlFor="wifi-auth-username">Username</label>
            <input id="wifi-auth-username" autoComplete="username" required minLength={3} maxLength={64}
              value={username} onChange={event => setUsername(event.target.value)}
              style={fieldStyle}/>
            <label style={{ fontSize: 12, color: '#94a3b8' }} htmlFor="wifi-auth-password">{mode === 'setup' ? 'Password (12 characters minimum)' : 'Password'}</label>
            <input id="wifi-auth-password" autoComplete={mode === 'setup' ? 'new-password' : 'current-password'} type="password" minLength={mode === 'setup' ? 12 : undefined} required value={password} onChange={e => setPassword(e.target.value)} style={fieldStyle}/>
            {mode === 'login' && mfaRequired ? <>
              <label style={{ fontSize: 12, color: '#94a3b8' }} htmlFor="wifi-auth-mfa-code">Authenticator code or unused recovery code</label>
              <input id="wifi-auth-mfa-code" autoComplete="one-time-code" required maxLength={24}
                value={mfaCode} onChange={event => setMfaCode(event.target.value)}
                placeholder="123456 or recovery code" style={fieldStyle}/>
            </> : null}
            <button type="submit" disabled={busy} style={{ ...buttonStyle, opacity: busy ? .65 : 1 }}>{busy ? 'Please wait…' : mode === 'setup' ? 'Create password and continue' : 'Sign in'}</button>
          </form>
        </> : null}
        {error ? <p role="alert" style={{ color: '#f87171', fontSize: 12, marginTop: 16 }}>{error}</p> : null}
        {notice ? <p role="status" style={{ color: '#4ade80', fontSize: 12, marginTop: 16 }}>{notice}</p> : null}
        <p style={{ color: '#64748b', fontSize: 11, lineHeight: 1.5, marginTop: 22 }}>Sessions are process-local and expire automatically. Keep remote access behind a VPN or authenticated reverse proxy.</p>
      </div>
    </div>
  );
}
