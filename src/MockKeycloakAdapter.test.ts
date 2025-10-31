import { describe, it, expect } from 'vitest';
import { MockAdapterFactory } from './MockKeycloakAdapter';
import type { MockUserScenario } from './types';

describe('MockKeycloakAdapter', () => {
  describe('Authentication', () => {
    it('should initialize as authenticated when scenario is authenticated', async () => {
      const adapter = MockAdapterFactory.createUser();
      const initialized = await adapter.init();

      expect(initialized).toBe(true);
      expect(adapter.isAuthenticated()).toBe(true);
    });

    it('should initialize as unauthenticated when scenario is not authenticated', async () => {
      const adapter = MockAdapterFactory.createUnauthenticated();
      const initialized = await adapter.init();

      expect(initialized).toBe(false);
      expect(adapter.isAuthenticated()).toBe(false);
    });

    it('should authenticate on login', () => {
      const adapter = MockAdapterFactory.createUnauthenticated();
      expect(adapter.isAuthenticated()).toBe(false);

      adapter.login();
      expect(adapter.isAuthenticated()).toBe(true);
    });

    it('should deauthenticate on logout', async () => {
      const adapter = MockAdapterFactory.createUser();
      expect(adapter.isAuthenticated()).toBe(true);

      await adapter.logout();
      expect(adapter.isAuthenticated()).toBe(false);
    });
  });

  describe('Token Management', () => {
    it('should provide access token when authenticated', async () => {
      const adapter = MockAdapterFactory.createUser();
      await adapter.init();

      const token = adapter.getToken();
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
    });

    it('should not provide token when not authenticated', () => {
      const adapter = MockAdapterFactory.createUnauthenticated();
      const token = adapter.getToken();
      expect(token).toBeUndefined();
    });

    it('should refresh token successfully', async () => {
      const adapter = MockAdapterFactory.createUser();
      await adapter.init();
      
      // Wait a bit to ensure timestamp changes
      await new Promise(resolve => setTimeout(resolve, 10));
      
      const refreshed = await adapter.refreshToken();

      expect(refreshed).toBe(true);
      const newToken = adapter.getToken();
      expect(newToken).toBeDefined();
      // Token should exist after refresh
      expect(typeof newToken).toBe('string');
    });
  });

  describe('User Profile', () => {
    it('should return user profile when authenticated', async () => {
      const adapter = MockAdapterFactory.createUser();
      await adapter.init();

      const profile = adapter.getUserProfile();
      expect(profile).toBeDefined();
      expect(profile?.id).toBe('user-001');
      expect(profile?.username).toBe('john.doe');
      expect(profile?.email).toBe('john.doe@example.com');
    });

    it('should return undefined profile when not authenticated', () => {
      const adapter = MockAdapterFactory.createUnauthenticated();
      const profile = adapter.getUserProfile();
      expect(profile).toBeUndefined();
    });
  });

  describe('Role Management', () => {
    it('should check realm roles correctly', async () => {
      const adapter = MockAdapterFactory.createAdmin();
      await adapter.init();

      expect(adapter.hasRole('admin')).toBe(true);
      expect(adapter.hasRole('user')).toBe(true);
      expect(adapter.hasRole('super-admin')).toBe(false);
    });

    it('should check client roles correctly', async () => {
      const adapter = MockAdapterFactory.createWithClientRoles();
      await adapter.init();

      expect(adapter.hasRole('read', 'app-frontend')).toBe(true);
      expect(adapter.hasRole('write', 'app-frontend')).toBe(true);
      expect(adapter.hasRole('delete', 'app-frontend')).toBe(false);
      expect(adapter.hasRole('api-access', 'app-backend')).toBe(true);
    });

    it('should return false for roles when not authenticated', () => {
      const adapter = MockAdapterFactory.createUnauthenticated();
      expect(adapter.hasRole('admin')).toBe(false);
      expect(adapter.hasRole('user')).toBe(false);
    });
  });

  describe('Session Management', () => {
    it('should return session info when authenticated', async () => {
      const adapter = MockAdapterFactory.createUser();
      await adapter.init();

      const sessionInfo = adapter.getSessionInfo();
      expect(sessionInfo.isActive).toBe(true);
      expect(sessionInfo.sessionId).toBe('user-001');
      expect(sessionInfo.sessionState).toBe('mock-session-state');
    });

    it('should return inactive session when not authenticated', () => {
      const adapter = MockAdapterFactory.createUnauthenticated();
      const sessionInfo = adapter.getSessionInfo();
      expect(sessionInfo.isActive).toBe(false);
    });
  });

  describe('Auth State', () => {
    it('should return complete auth state when authenticated', async () => {
      const adapter = MockAdapterFactory.createUser();
      await adapter.init();

      const authState = adapter.getAuthState();
      expect(authState.isAuthenticated).toBe(true);
      expect(authState.tokens).toBeDefined();
      expect(authState.tokenPayload).toBeDefined();
      expect(authState.userProfile).toBeDefined();
    });

    it('should return unauthenticated state when not logged in', () => {
      const adapter = MockAdapterFactory.createUnauthenticated();
      const authState = adapter.getAuthState();
      expect(authState.isAuthenticated).toBe(false);
      expect(authState.tokens).toBeUndefined();
      expect(authState.userProfile).toBeUndefined();
    });
  });

  describe('Factory Methods', () => {
    it('should create admin with correct roles', async () => {
      const adapter = MockAdapterFactory.createAdmin();
      await adapter.init();

      expect(adapter.hasRole('admin')).toBe(true);
      expect(adapter.hasRole('manage-users')).toBe(true);
    });

    it('should create regular user with correct roles', async () => {
      const adapter = MockAdapterFactory.createUser();
      await adapter.init();

      expect(adapter.hasRole('user')).toBe(true);
      expect(adapter.hasRole('admin')).toBe(false);
    });

    it('should create read-only user with correct roles', async () => {
      const adapter = MockAdapterFactory.createReadOnly();
      await adapter.init();

      expect(adapter.hasRole('viewer')).toBe(true);
      expect(adapter.hasRole('read-only')).toBe(true);
      expect(adapter.hasRole('admin')).toBe(false);
    });

    it('should create manager with correct roles', async () => {
      const adapter = MockAdapterFactory.createManager();
      await adapter.init();

      expect(adapter.hasRole('manager')).toBe(true);
      expect(adapter.hasRole('approve-requests')).toBe(true);
      expect(adapter.hasRole('user')).toBe(true);
    });

    it('should create custom scenario correctly', async () => {
      const customScenario: MockUserScenario = {
        userId: 'custom-001',
        username: 'custom-user',
        email: 'custom@example.com',
        roles: ['custom-role'],
        isAuthenticated: true,
        customClaims: {
          department: 'Engineering',
          level: 'Senior',
        },
      };

      const adapter = MockAdapterFactory.createCustom(customScenario);
      await adapter.init();

      expect(adapter.isAuthenticated()).toBe(true);
      expect(adapter.hasRole('custom-role')).toBe(true);
      const authState = adapter.getAuthState();
      expect(authState.tokenPayload?.department).toBe('Engineering');
      expect(authState.tokenPayload?.level).toBe('Senior');
    });
  });
});
