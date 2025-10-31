import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { KeycloakAdapter } from './KeycloakAdapter';
import type { KeycloakAdapterConfig } from './types';

describe('KeycloakAdapter', () => {
  let adapter: KeycloakAdapter;
  let config: KeycloakAdapterConfig;

  beforeEach(() => {
    // Clear storage before each test
    localStorage.clear();
    sessionStorage.clear();

    config = {
      url: 'https://keycloak.example.com',
      realm: 'test-realm',
      clientId: 'test-client',
      redirectUri: 'http://localhost:3000',
      postLogoutRedirectUri: 'http://localhost:3000',
    };

    adapter = new KeycloakAdapter(config);
  });

  afterEach(() => {
    adapter.destroy();
    localStorage.clear();
    sessionStorage.clear();
  });

  describe('Configuration', () => {
    it('should merge config with defaults', () => {
      const minimalConfig: KeycloakAdapterConfig = {
        url: 'https://keycloak.example.com',
        realm: 'test-realm',
        clientId: 'test-client',
      };

      const adapter = new KeycloakAdapter(minimalConfig);
      expect(adapter).toBeDefined();
    });
  });

  describe('Initialization', () => {
    it('should initialize without tokens', async () => {
      const isAuth = await adapter.init();
      expect(isAuth).toBe(false);
      expect(adapter.isAuthenticated()).toBe(false);
    });

    it('should not be authenticated initially', () => {
      expect(adapter.isAuthenticated()).toBe(false);
    });
  });

  describe('Login Flow', () => {
    it('should generate proper auth URL on login', () => {
      const originalLocation = window.location;
      delete (window as { location?: Location }).location;
      window.location = { href: '' } as Location;

      adapter.login();

      expect(window.location.href).toContain('https://keycloak.example.com/realms/test-realm');
      expect(window.location.href).toContain('protocol/openid-connect/auth');
      expect(window.location.href).toContain('client_id=test-client');
      expect(window.location.href).toContain('response_type=code');
      expect(window.location.href).toContain('scope=openid+profile+email');

      window.location = originalLocation;
    });

    it('should store state and nonce in session storage on login', () => {
      const originalLocation = window.location;
      delete (window as { location?: Location }).location;
      window.location = { href: '' } as Location;

      adapter.login();

      const state = sessionStorage.getItem('keycloak_state');
      const nonce = sessionStorage.getItem('keycloak_nonce');

      expect(state).toBeTruthy();
      expect(nonce).toBeTruthy();
      expect(state?.length).toBeGreaterThan(0);
      expect(nonce?.length).toBeGreaterThan(0);

      window.location = originalLocation;
    });
  });

  describe('Token Management', () => {
    it('should return undefined token when not authenticated', () => {
      const token = adapter.getToken();
      expect(token).toBeUndefined();
    });

    it('should parse JWT token correctly', () => {
      // Create a mock JWT token
      const header = { alg: 'RS256', typ: 'JWT' };
      const payload = {
        sub: 'user-123',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        iss: 'https://keycloak.example.com/realms/test-realm',
        aud: 'test-client',
        preferred_username: 'testuser',
      };

      const encodedHeader = btoa(JSON.stringify(header));
      const encodedPayload = btoa(JSON.stringify(payload));
      const mockToken = `${encodedHeader}.${encodedPayload}.mock-signature`;

      // Store the token
      const tokens = {
        accessToken: mockToken,
        tokenType: 'Bearer',
        expiresIn: 3600,
        receivedAt: Date.now(),
      };
      localStorage.setItem('keycloak_tokens', JSON.stringify(tokens));

      // Re-initialize adapter
      const newAdapter = new KeycloakAdapter(config);
      newAdapter.init();

      const profile = newAdapter.getUserProfile();
      expect(profile?.id).toBe('user-123');
      expect(profile?.username).toBe('testuser');

      newAdapter.destroy();
    });
  });

  describe('User Profile', () => {
    it('should return undefined profile when not authenticated', () => {
      const profile = adapter.getUserProfile();
      expect(profile).toBeUndefined();
    });
  });

  describe('Role Checking', () => {
    it('should return false for any role when not authenticated', () => {
      expect(adapter.hasRole('admin')).toBe(false);
      expect(adapter.hasRole('user')).toBe(false);
    });

    it('should check realm roles correctly', () => {
      // Create a mock JWT with roles
      const payload = {
        sub: 'user-123',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        iss: 'https://keycloak.example.com/realms/test-realm',
        aud: 'test-client',
        realm_access: {
          roles: ['admin', 'user'],
        },
      };

      const encodedHeader = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
      const encodedPayload = btoa(JSON.stringify(payload));
      const mockToken = `${encodedHeader}.${encodedPayload}.mock-signature`;

      const tokens = {
        accessToken: mockToken,
        tokenType: 'Bearer',
        expiresIn: 3600,
        receivedAt: Date.now(),
      };
      localStorage.setItem('keycloak_tokens', JSON.stringify(tokens));

      const newAdapter = new KeycloakAdapter(config);
      newAdapter.init();

      expect(newAdapter.hasRole('admin')).toBe(true);
      expect(newAdapter.hasRole('user')).toBe(true);
      expect(newAdapter.hasRole('super-admin')).toBe(false);

      newAdapter.destroy();
    });

    it('should check client roles correctly', () => {
      const payload = {
        sub: 'user-123',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        iss: 'https://keycloak.example.com/realms/test-realm',
        aud: 'test-client',
        resource_access: {
          'app-frontend': {
            roles: ['read', 'write'],
          },
        },
      };

      const encodedHeader = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
      const encodedPayload = btoa(JSON.stringify(payload));
      const mockToken = `${encodedHeader}.${encodedPayload}.mock-signature`;

      const tokens = {
        accessToken: mockToken,
        tokenType: 'Bearer',
        expiresIn: 3600,
        receivedAt: Date.now(),
      };
      localStorage.setItem('keycloak_tokens', JSON.stringify(tokens));

      const newAdapter = new KeycloakAdapter(config);
      newAdapter.init();

      expect(newAdapter.hasRole('read', 'app-frontend')).toBe(true);
      expect(newAdapter.hasRole('write', 'app-frontend')).toBe(true);
      expect(newAdapter.hasRole('delete', 'app-frontend')).toBe(false);

      newAdapter.destroy();
    });
  });

  describe('Session Info', () => {
    it('should return inactive session when not authenticated', () => {
      const sessionInfo = adapter.getSessionInfo();
      expect(sessionInfo.isActive).toBe(false);
    });

    it('should return active session when authenticated', () => {
      const payload = {
        sub: 'user-123',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        iss: 'https://keycloak.example.com/realms/test-realm',
        aud: 'test-client',
        session_state: 'session-123',
      };

      const encodedHeader = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
      const encodedPayload = btoa(JSON.stringify(payload));
      const mockToken = `${encodedHeader}.${encodedPayload}.mock-signature`;

      const tokens = {
        accessToken: mockToken,
        tokenType: 'Bearer',
        expiresIn: 3600,
        receivedAt: Date.now(),
      };
      localStorage.setItem('keycloak_tokens', JSON.stringify(tokens));

      const newAdapter = new KeycloakAdapter(config);
      newAdapter.init();

      const sessionInfo = newAdapter.getSessionInfo();
      expect(sessionInfo.isActive).toBe(true);
      expect(sessionInfo.sessionState).toBe('session-123');

      newAdapter.destroy();
    });
  });

  describe('Auth State', () => {
    it('should return unauthenticated state initially', () => {
      const authState = adapter.getAuthState();
      expect(authState.isAuthenticated).toBe(false);
      expect(authState.tokens).toBeUndefined();
      expect(authState.userProfile).toBeUndefined();
    });
  });

  describe('Cleanup', () => {
    it('should cleanup resources on destroy', () => {
      adapter.destroy();
      // Should not throw errors
    });
  });
});
