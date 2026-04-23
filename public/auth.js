/**
 * ESAD Simple-CDN — Auth Guard
 * Shared across all protected pages.
 *
 * Two auth modes (as per REQS_V2.md §5.2):
 *  - Session token: obtained via /auth/login (username + password) — full access
 *  - API token:     used in automated environments (CLI/CI) — deploy actions only
 */

const AUTH_KEY = 'esad_cdn_session';

const Auth = {
  getToken() {
    return sessionStorage.getItem(AUTH_KEY) || localStorage.getItem(AUTH_KEY);
  },

  getUser() {
    try {
      const raw = sessionStorage.getItem(AUTH_KEY + '_user') || localStorage.getItem(AUTH_KEY + '_user');
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  },

  save(token, user, remember = false) {
    const store = remember ? localStorage : sessionStorage;
    store.setItem(AUTH_KEY, token);
    store.setItem(AUTH_KEY + '_user', JSON.stringify(user));
  },

  clear() {
    [sessionStorage, localStorage].forEach(s => {
      s.removeItem(AUTH_KEY);
      s.removeItem(AUTH_KEY + '_user');
    });
  },

  /** Redirects to /login.html if there is no token, then returns false. */
  requireAuth() {
    if (!this.getToken()) {
      window.location.href = '/login.html?redirect=' + encodeURIComponent(window.location.pathname + window.location.search);
      return false;
    }
    return true;
  },

  /** Wraps fetch with Authorization header automatically. */
  async fetch(url, options = {}) {
    const token = this.getToken();
    const res = await fetch(url, {
      ...options,
      headers: {
        ...(options.headers || {}),
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      },
    });
    if (res.status === 401 || res.status === 403) {
      this.handleUnauthorized();
    }
    return res;
  },

  /** Call on 401/403 responses to force re-login. */
  handleUnauthorized() {
    this.clear();
    window.location.href = '/login.html?expired=1';
  }
};
