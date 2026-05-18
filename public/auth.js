/**
 * ESAD Simple-CDN — Auth Guard
 * Shared across all protected pages.
 */

const AUTH_KEY = 'esad_cdn_session';

/** Role hierarchy for UI masking decisions */
const ROLE_RANK = { owner: 7, master: 6, manager: 5, release_manager: 4, moderator: 3, dev: 2, user: 1 };

const Auth = {
  isAuthenticated() {
    return !!this.getUser();
  },

  getUser() {
    try {
      const raw = sessionStorage.getItem(AUTH_KEY + '_user') || localStorage.getItem(AUTH_KEY + '_user');
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  },

  getRank() {
    const user = this.getUser();
    return user ? (ROLE_RANK[user.role] ?? 0) : 0;
  },

  hasRole(requiredRole) {
    return this.getRank() >= (ROLE_RANK[requiredRole] ?? 99);
  },

  save(user, remember = false) {
    const store = remember ? localStorage : sessionStorage;
    store.setItem(AUTH_KEY + '_user', JSON.stringify(user));
  },

  clear() {
    [sessionStorage, localStorage].forEach(s => {
      s.removeItem(AUTH_KEY);
      s.removeItem(AUTH_KEY + '_user');
    });
  },

  requireAuth() {
    if (!this.isAuthenticated()) {
      window.location.href = '/login.html?redirect=' + encodeURIComponent(window.location.pathname + window.location.search);
      return false;
    }
    return true;
  },

  /** Require a minimum role to access the current page. Redirects to dashboard if insufficient. */
  requireRole(role) {
    if (!this.hasRole(role)) {
      window.location.href = '/';
      return false;
    }
    return true;
  },

  async fetch(url, options = {}) {
    const res = await fetch(url, {
      ...options,
      credentials: 'include',
      headers: {
        ...(options.headers || {}),
      },
    });
    if (res.status === 401) {
      this.handleUnauthorized();
    }
    return res;
  },

  /** Call on 401 responses to force re-login. */
  handleUnauthorized() {
    this.clear();
    window.location.href = '/login.html?expired=1';
  }
};

