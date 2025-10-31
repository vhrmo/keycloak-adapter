import type {
  KeycloakAdapterConfig,
  TokenSet,
  TokenPayload,
  AuthState,
  UserProfile,
  SessionInfo,
  MockUserScenario,
} from './types';

/**
 * Mock Keycloak Adapter for testing and local development
 * Simulates authentication without connecting to a real Keycloak server
 */
export class MockKeycloakAdapter {
  private config: Partial<KeycloakAdapterConfig>;
  private scenario: MockUserScenario;
  private tokens?: TokenSet;
  private tokenPayload?: TokenPayload;
  private authenticated: boolean = false;

  constructor(config: Partial<KeycloakAdapterConfig>, scenario: MockUserScenario) {
    this.config = config;
    this.scenario = scenario;
    this.authenticated = scenario.isAuthenticated ?? false;

    if (this.authenticated) {
      this.generateMockTokens();
    }
  }

  /**
   * Initialize the mock adapter
   */
  async init(): Promise<boolean> {
    if (this.authenticated) {
      this.generateMockTokens();
      return true;
    }
    return false;
  }

  /**
   * Simulate login
   */
  login(): void {
    this.authenticated = true;
    this.generateMockTokens();
  }

  /**
   * Simulate logout
   */
  async logout(): Promise<void> {
    this.authenticated = false;
    this.tokens = undefined;
    this.tokenPayload = undefined;
  }

  /**
   * Get authentication state
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
   * Check if authenticated
   */
  isAuthenticated(): boolean {
    return this.authenticated;
  }

  /**
   * Get access token
   */
  getToken(): string | undefined {
    return this.tokens?.accessToken;
  }

  /**
   * Get user profile
   */
  getUserProfile(): UserProfile | undefined {
    if (!this.authenticated || !this.tokenPayload) return undefined;

    return {
      id: this.scenario.userId,
      username: this.scenario.username,
      email: this.scenario.email,
      name: this.scenario.username,
      realmRoles: this.scenario.roles,
      clientRoles: this.scenario.clientRoles,
    };
  }

  /**
   * Check if user has a specific role
   */
  hasRole(role: string, clientId?: string): boolean {
    if (!this.authenticated) return false;

    if (clientId && this.scenario.clientRoles) {
      const clientRoles = this.scenario.clientRoles[clientId] || [];
      return clientRoles.includes(role);
    }

    return this.scenario.roles.includes(role);
  }

  /**
   * Get session information
   */
  getSessionInfo(): SessionInfo {
    return {
      sessionId: this.scenario.userId,
      sessionState: 'mock-session-state',
      isActive: this.authenticated,
      startedAt: this.tokens?.receivedAt,
      lastActivityAt: Date.now(),
    };
  }

  /**
   * Simulate token refresh
   */
  async refreshToken(): Promise<boolean> {
    if (!this.authenticated) return false;
    this.generateMockTokens();
    return true;
  }

  /**
   * Generate mock tokens
   */
  private generateMockTokens(): void {
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = 3600; // 1 hour

    // Convert clientRoles to resource_access format
    const resourceAccess: { [key: string]: { roles: string[] } } = {};
    if (this.scenario.clientRoles) {
      for (const [clientId, roles] of Object.entries(this.scenario.clientRoles)) {
        resourceAccess[clientId] = { roles };
      }
    }

    this.tokenPayload = {
      sub: this.scenario.userId,
      iat: now,
      exp: now + expiresIn,
      iss: `${this.config.url}/realms/${this.config.realm}`,
      aud: this.config.clientId || 'mock-client',
      preferred_username: this.scenario.username,
      email: this.scenario.email,
      name: this.scenario.username,
      realm_access: {
        roles: this.scenario.roles,
      },
      resource_access: Object.keys(resourceAccess).length > 0 ? resourceAccess : undefined,
      session_state: 'mock-session-state',
      ...this.scenario.customClaims,
    };

    const mockAccessToken = this.createMockJWT(this.tokenPayload);

    this.tokens = {
      accessToken: mockAccessToken,
      refreshToken: 'mock-refresh-token',
      idToken: 'mock-id-token',
      tokenType: 'Bearer',
      expiresIn,
      receivedAt: Date.now(),
    };
  }

  /**
   * Create a mock JWT token (for testing only - not secure!)
   */
  private createMockJWT(payload: TokenPayload): string {
    const header = { alg: 'RS256', typ: 'JWT' };
    const encodedHeader = btoa(JSON.stringify(header));
    const encodedPayload = btoa(JSON.stringify(payload));
    const signature = 'mock-signature';
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  /**
   * Destroy the adapter
   */
  destroy(): void {
    // No-op for mock adapter
  }
}

/**
 * Factory function to create mock adapters with predefined scenarios
 */
export class MockAdapterFactory {
  /**
   * Create a mock adapter with admin permissions
   */
  static createAdmin(config?: Partial<KeycloakAdapterConfig>): MockKeycloakAdapter {
    const scenario: MockUserScenario = {
      userId: 'admin-001',
      username: 'admin',
      email: 'admin@example.com',
      roles: ['admin', 'user', 'manage-users', 'view-reports'],
      isAuthenticated: true,
    };
    return new MockKeycloakAdapter(config || {}, scenario);
  }

  /**
   * Create a mock adapter with regular user permissions
   */
  static createUser(config?: Partial<KeycloakAdapterConfig>): MockKeycloakAdapter {
    const scenario: MockUserScenario = {
      userId: 'user-001',
      username: 'john.doe',
      email: 'john.doe@example.com',
      roles: ['user'],
      isAuthenticated: true,
    };
    return new MockKeycloakAdapter(config || {}, scenario);
  }

  /**
   * Create a mock adapter with read-only permissions
   */
  static createReadOnly(config?: Partial<KeycloakAdapterConfig>): MockKeycloakAdapter {
    const scenario: MockUserScenario = {
      userId: 'viewer-001',
      username: 'viewer',
      email: 'viewer@example.com',
      roles: ['viewer', 'read-only'],
      isAuthenticated: true,
    };
    return new MockKeycloakAdapter(config || {}, scenario);
  }

  /**
   * Create a mock adapter for an unauthenticated user
   */
  static createUnauthenticated(config?: Partial<KeycloakAdapterConfig>): MockKeycloakAdapter {
    const scenario: MockUserScenario = {
      userId: 'guest-001',
      username: 'guest',
      roles: [],
      isAuthenticated: false,
    };
    return new MockKeycloakAdapter(config || {}, scenario);
  }

  /**
   * Create a mock adapter with custom scenario
   */
  static createCustom(
    scenario: MockUserScenario,
    config?: Partial<KeycloakAdapterConfig>
  ): MockKeycloakAdapter {
    return new MockKeycloakAdapter(config || {}, scenario);
  }

  /**
   * Create a mock adapter with multiple client roles
   */
  static createWithClientRoles(config?: Partial<KeycloakAdapterConfig>): MockKeycloakAdapter {
    const scenario: MockUserScenario = {
      userId: 'multi-role-001',
      username: 'developer',
      email: 'developer@example.com',
      roles: ['user'],
      clientRoles: {
        'app-frontend': ['read', 'write'],
        'app-backend': ['api-access'],
        'reporting-service': ['generate-reports', 'view-dashboards'],
      },
      isAuthenticated: true,
    };
    return new MockKeycloakAdapter(config || {}, scenario);
  }

  /**
   * Create a mock adapter for a manager with elevated permissions
   */
  static createManager(config?: Partial<KeycloakAdapterConfig>): MockKeycloakAdapter {
    const scenario: MockUserScenario = {
      userId: 'manager-001',
      username: 'manager',
      email: 'manager@example.com',
      roles: ['user', 'manager', 'approve-requests', 'view-analytics'],
      isAuthenticated: true,
    };
    return new MockKeycloakAdapter(config || {}, scenario);
  }
}
