import type {
  KeycloakAdapterConfig,
  TokenSet,
  TokenPayload,
  AuthState,
  UserProfile,
  SessionInfo,
} from './types';

/**
 * Keycloak Adapter for Single Page Applications
 * Provides token management, session management, and authentication utilities
 */
export class KeycloakAdapter {
  private config: Required<KeycloakAdapterConfig>;
  private tokens?: TokenSet;
  private tokenPayload?: TokenPayload;
  private refreshTimer?: number;
  private sessionCheckTimer?: number;
  private iframe?: HTMLIFrameElement;

  constructor(config: KeycloakAdapterConfig) {
    this.config = this.mergeConfig(config);
  }

  /**
   * Merge user config with defaults
   */
  private mergeConfig(config: KeycloakAdapterConfig): Required<KeycloakAdapterConfig> {
    return {
      url: config.url,
      realm: config.realm,
      clientId: config.clientId,
      redirectUri: config.redirectUri || window.location.origin,
      postLogoutRedirectUri: config.postLogoutRedirectUri || window.location.origin,
      refreshInterval: config.refreshInterval ?? 60,
      minValidity: config.minValidity ?? 70,
      enableSessionMonitoring: config.enableSessionMonitoring ?? true,
      sessionCheckInterval: config.sessionCheckInterval ?? 5,
      enableSingleSession: config.enableSingleSession ?? false,
      onSSOLogout: config.onSSOLogout || (() => {}),
      onSessionTimeout: config.onSessionTimeout || (() => {}),
      onTokenRefresh: config.onTokenRefresh || (() => {}),
      onAuthError: config.onAuthError || (() => {}),
    };
  }

  /**
   * Initialize the adapter
   */
  async init(): Promise<boolean> {
    try {
      // Check if there's a token in URL (after OAuth redirect)
      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get('code');
      const state = urlParams.get('state');

      if (code && state) {
        // Exchange code for tokens
        await this.exchangeCodeForTokens(code, state);
        // Clean URL
        window.history.replaceState({}, document.title, window.location.pathname);
        return true;
      }

      // Check for existing tokens in storage
      const storedTokens = this.loadTokensFromStorage();
      if (storedTokens) {
        this.tokens = storedTokens;
        this.tokenPayload = this.parseToken(storedTokens.accessToken);

        // Check if token is still valid
        if (this.isTokenValid()) {
          this.startTokenRefresh();
          if (this.config.enableSessionMonitoring) {
            this.startSessionMonitoring();
          }
          return true;
        }
      }

      return false;
    } catch (error) {
      this.config.onAuthError(error as Error);
      return false;
    }
  }

  /**
   * Initiate login flow
   */
  login(): void {
    const state = this.generateState();
    const nonce = this.generateNonce();

    // Store state and nonce for validation
    sessionStorage.setItem('keycloak_state', state);
    sessionStorage.setItem('keycloak_nonce', nonce);

    const authUrl = this.buildAuthUrl(state, nonce);
    window.location.href = authUrl;
  }

  /**
   * Logout the user
   */
  async logout(): Promise<void> {
    this.stopTokenRefresh();
    this.stopSessionMonitoring();
    this.clearTokens();

    const logoutUrl = `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/logout`;
    const params = new URLSearchParams({
      post_logout_redirect_uri: this.config.postLogoutRedirectUri,
      id_token_hint: this.tokens?.idToken || '',
    });

    window.location.href = `${logoutUrl}?${params.toString()}`;
  }

  /**
   * Get current authentication state
   */
  getAuthState(): AuthState {
    return {
      isAuthenticated: this.isAuthenticated(),
      tokens: this.tokens,
      tokenPayload: this.tokenPayload,
      userProfile: this.getUserProfile(),
    };
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    return !!this.tokens && this.isTokenValid();
  }

  /**
   * Get access token
   */
  getToken(): string | undefined {
    return this.tokens?.accessToken;
  }

  /**
   * Get user profile from token
   */
  getUserProfile(): UserProfile | undefined {
    if (!this.tokenPayload) return undefined;

    // Convert resource_access structure to clientRoles format
    const clientRoles: Record<string, string[]> = {};
    if (this.tokenPayload.resource_access) {
      for (const [clientId, access] of Object.entries(this.tokenPayload.resource_access)) {
        clientRoles[clientId] = access.roles;
      }
    }

    return {
      id: this.tokenPayload.sub,
      username: this.tokenPayload.preferred_username,
      email: this.tokenPayload.email,
      name: this.tokenPayload.name,
      realmRoles: this.tokenPayload.realm_access?.roles,
      clientRoles: Object.keys(clientRoles).length > 0 ? clientRoles : undefined,
    };
  }

  /**
   * Check if user has a specific role
   */
  hasRole(role: string, clientId?: string): boolean {
    if (!this.tokenPayload) return false;

    if (clientId) {
      const clientRoles = this.tokenPayload.resource_access?.[clientId]?.roles || [];
      return clientRoles.includes(role);
    }

    const realmRoles = this.tokenPayload.realm_access?.roles || [];
    return realmRoles.includes(role);
  }

  /**
   * Get session information
   */
  getSessionInfo(): SessionInfo {
    return {
      sessionId: this.tokenPayload?.sub,
      sessionState: this.tokenPayload?.session_state,
      isActive: this.isAuthenticated(),
      startedAt: this.tokens?.receivedAt,
      lastActivityAt: Date.now(),
    };
  }

  /**
   * Manually refresh tokens
   */
  async refreshToken(): Promise<boolean> {
    if (!this.tokens?.refreshToken) {
      return false;
    }

    try {
      const tokenUrl = `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/token`;
      const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: this.tokens.refreshToken,
          client_id: this.config.clientId,
        }),
      });

      if (!response.ok) {
        throw new Error('Token refresh failed');
      }

      const data = await response.json();
      this.updateTokens(data);
      this.config.onTokenRefresh(this.tokens!);
      return true;
    } catch (error) {
      this.config.onAuthError(error as Error);
      this.clearTokens();
      return false;
    }
  }

  /**
   * Build authorization URL
   */
  private buildAuthUrl(state: string, nonce: string): string {
    const authUrl = `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/auth`;
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: 'openid profile email',
      state,
      nonce,
    });
    return `${authUrl}?${params.toString()}`;
  }

  /**
   * Exchange authorization code for tokens
   */
  private async exchangeCodeForTokens(code: string, state: string): Promise<void> {
    const savedState = sessionStorage.getItem('keycloak_state');
    if (state !== savedState) {
      throw new Error('Invalid state parameter');
    }

    const tokenUrl = `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/token`;
    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.config.redirectUri,
        client_id: this.config.clientId,
      }),
    });

    if (!response.ok) {
      throw new Error('Token exchange failed');
    }

    const data = await response.json();
    this.updateTokens(data);

    sessionStorage.removeItem('keycloak_state');
    sessionStorage.removeItem('keycloak_nonce');

    this.startTokenRefresh();
    if (this.config.enableSessionMonitoring) {
      this.startSessionMonitoring();
    }
  }

  /**
   * Update tokens and save to storage
   */
  private updateTokens(data: {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    token_type: string;
    expires_in: number;
  }): void {
    this.tokens = {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      idToken: data.id_token,
      tokenType: data.token_type,
      expiresIn: data.expires_in,
      receivedAt: Date.now(),
    };

    this.tokenPayload = this.parseToken(data.access_token);
    this.saveTokensToStorage(this.tokens);
  }

  /**
   * Parse JWT token
   */
  private parseToken(token: string): TokenPayload {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid token format');
    }

    const payload = parts[1];
    const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decoded);
  }

  /**
   * Check if token is valid
   */
  private isTokenValid(): boolean {
    if (!this.tokens || !this.tokenPayload) return false;

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = this.tokenPayload.exp;
    return expiresAt > now + this.config.minValidity;
  }

  /**
   * Start automatic token refresh
   */
  private startTokenRefresh(): void {
    this.stopTokenRefresh();

    const refreshIntervalMs = this.config.refreshInterval * 1000;
    this.refreshTimer = window.setInterval(() => {
      if (!this.isTokenValid()) {
        this.refreshToken();
      }
    }, refreshIntervalMs);
  }

  /**
   * Stop automatic token refresh
   */
  private stopTokenRefresh(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = undefined;
    }
  }

  /**
   * Start session monitoring for SSO logout detection
   */
  private startSessionMonitoring(): void {
    if (!this.config.enableSessionMonitoring) return;

    this.stopSessionMonitoring();

    // Create hidden iframe for session monitoring
    this.iframe = document.createElement('iframe');
    this.iframe.style.display = 'none';
    const checkSessionUrl = `${this.config.url}/realms/${this.config.realm}/protocol/openid-connect/login-status-iframe.html`;
    this.iframe.src = checkSessionUrl;
    document.body.appendChild(this.iframe);

    // Check session periodically
    const checkIntervalMs = this.config.sessionCheckInterval * 1000;
    this.sessionCheckTimer = window.setInterval(() => {
      this.checkSession();
    }, checkIntervalMs);
  }

  /**
   * Stop session monitoring
   */
  private stopSessionMonitoring(): void {
    if (this.sessionCheckTimer) {
      clearInterval(this.sessionCheckTimer);
      this.sessionCheckTimer = undefined;
    }

    if (this.iframe) {
      document.body.removeChild(this.iframe);
      this.iframe = undefined;
    }
  }

  /**
   * Check session status
   */
  private checkSession(): void {
    if (!this.iframe || !this.tokenPayload?.session_state) return;

    const message = `${this.config.clientId} ${this.tokenPayload.session_state}`;
    this.iframe.contentWindow?.postMessage(message, this.config.url);

    // Listen for session status response
    const handleMessage = (event: MessageEvent) => {
      if (event.origin !== this.config.url) return;

      if (event.data === 'unchanged') {
        // Session is still valid
      } else if (event.data === 'changed') {
        // Session changed - trigger SSO logout
        this.config.onSSOLogout();
        this.clearTokens();
        window.removeEventListener('message', handleMessage);
      } else if (event.data === 'error') {
        // Session check error - might indicate timeout
        this.config.onSessionTimeout();
        this.clearTokens();
        window.removeEventListener('message', handleMessage);
      }
    };

    window.addEventListener('message', handleMessage);
  }

  /**
   * Save tokens to local storage
   */
  private saveTokensToStorage(tokens: TokenSet): void {
    try {
      localStorage.setItem('keycloak_tokens', JSON.stringify(tokens));
    } catch (error) {
      console.error('Failed to save tokens to storage:', error);
    }
  }

  /**
   * Load tokens from local storage
   */
  private loadTokensFromStorage(): TokenSet | null {
    try {
      const stored = localStorage.getItem('keycloak_tokens');
      return stored ? JSON.parse(stored) : null;
    } catch (error) {
      console.error('Failed to load tokens from storage:', error);
      return null;
    }
  }

  /**
   * Clear tokens from memory and storage
   */
  private clearTokens(): void {
    this.tokens = undefined;
    this.tokenPayload = undefined;
    localStorage.removeItem('keycloak_tokens');
  }

  /**
   * Generate random state for OAuth flow
   */
  private generateState(): string {
    return this.generateRandomString(32);
  }

  /**
   * Generate random nonce for OAuth flow
   */
  private generateNonce(): string {
    return this.generateRandomString(32);
  }

  /**
   * Generate random string
   */
  private generateRandomString(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);

    for (let i = 0; i < length; i++) {
      result += chars[randomValues[i] % chars.length];
    }

    return result;
  }

  /**
   * Cleanup and destroy the adapter
   */
  destroy(): void {
    this.stopTokenRefresh();
    this.stopSessionMonitoring();
  }
}
