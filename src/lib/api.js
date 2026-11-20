const API_BASE = `${window.location.protocol}//${window.location.hostname}:199`;
const SESSION_KEY = 'wifi-analyzer-pro-session';

export function apiBase() {
  return API_BASE;
}

export function getSessionToken() {
  try {
    return window.sessionStorage.getItem(SESSION_KEY) || '';
  } catch {
    return '';
  }
}

export function setSessionToken(token) {
  try {
    if (token) window.sessionStorage.setItem(SESSION_KEY, token);
    else window.sessionStorage.removeItem(SESSION_KEY);
  } catch {
    // A restricted browser storage context should fail closed at the API gate.
  }
}

export async function apiFetch(input, options = {}) {
  const headers = new Headers(options.headers || {});
  const token = getSessionToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(input, { ...options, headers });
  if (response.status === 401 && token) {
    setSessionToken('');
    window.dispatchEvent(new Event('wifi-analyzer:auth-expired'));
  }
  return response;
}
