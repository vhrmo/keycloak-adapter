# Keycloak Adapter Examples

This directory contains examples demonstrating various usage scenarios of the Keycloak adapter.

## Basic Example

```typescript
import { KeycloakAdapter } from '@vhrmo/keycloak-adapter';

async function main() {
  const keycloak = new KeycloakAdapter({
    url: 'https://keycloak.example.com',
    realm: 'my-realm',
    clientId: 'my-spa-client',
  });

  const isAuthenticated = await keycloak.init();

  if (!isAuthenticated) {
    console.log('User not authenticated, redirecting to login...');
    keycloak.login();
    return;
  }

  console.log('User is authenticated!');
  const profile = keycloak.getUserProfile();
  console.log('User profile:', profile);

  // Check roles
  if (keycloak.hasRole('admin')) {
    console.log('User has admin role');
  }

  // Get token for API calls
  const token = keycloak.getToken();
  console.log('Access token:', token);

  // Logout when done
  // await keycloak.logout();
}

main();
```

## Mock Adapter for Development

```typescript
import { MockAdapterFactory } from '@vhrmo/keycloak-adapter';

// For development/testing - no real Keycloak server needed
async function devExample() {
  const adapter = MockAdapterFactory.createAdmin();
  await adapter.init();

  console.log('Authenticated:', adapter.isAuthenticated()); // true
  console.log('Has admin role:', adapter.hasRole('admin')); // true

  const profile = adapter.getUserProfile();
  console.log('Profile:', profile);
  // Output: { id: 'admin-001', username: 'admin', email: 'admin@example.com', ... }

  const token = adapter.getToken();
  console.log('Token:', token); // Mock JWT token
}

devExample();
```

## Environment-Based Setup

```typescript
import { KeycloakAdapter, MockAdapterFactory } from '@vhrmo/keycloak-adapter';

function createAdapter() {
  if (import.meta.env.DEV) {
    // Use mock adapter in development
    return MockAdapterFactory.createAdmin();
  }

  // Use real adapter in production
  return new KeycloakAdapter({
    url: import.meta.env.VITE_KEYCLOAK_URL,
    realm: import.meta.env.VITE_KEYCLOAK_REALM,
    clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID,
  });
}

const keycloak = createAdapter();
```

## Testing Different User Scenarios

```typescript
import { MockAdapterFactory } from '@vhrmo/keycloak-adapter';

async function testDifferentScenarios() {
  // Test as admin
  console.log('=== Testing as Admin ===');
  const admin = MockAdapterFactory.createAdmin();
  await admin.init();
  console.log('Can manage users:', admin.hasRole('manage-users'));

  // Test as regular user
  console.log('\n=== Testing as Regular User ===');
  const user = MockAdapterFactory.createUser();
  await user.init();
  console.log('Can manage users:', user.hasRole('manage-users')); // false

  // Test as unauthenticated
  console.log('\n=== Testing as Guest ===');
  const guest = MockAdapterFactory.createUnauthenticated();
  await guest.init();
  console.log('Is authenticated:', guest.isAuthenticated()); // false

  // Test custom scenario
  console.log('\n=== Testing Custom Scenario ===');
  const custom = MockAdapterFactory.createCustom({
    userId: 'test-001',
    username: 'tester',
    email: 'tester@example.com',
    roles: ['qa', 'tester'],
    clientRoles: {
      'test-app': ['run-tests', 'view-results'],
    },
    isAuthenticated: true,
  });
  await custom.init();
  console.log('Has QA role:', custom.hasRole('qa'));
  console.log('Can run tests:', custom.hasRole('run-tests', 'test-app'));
}

testDifferentScenarios();
```

## React Hook Example

```typescript
import { useState, useEffect } from 'react';
import { KeycloakAdapter } from '@vhrmo/keycloak-adapter';

export function useAuth() {
  const [keycloak] = useState(() => new KeycloakAdapter({
    url: import.meta.env.VITE_KEYCLOAK_URL,
    realm: import.meta.env.VITE_KEYCLOAK_REALM,
    clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID,
  }));
  const [authenticated, setAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    keycloak.init().then((auth) => {
      setAuthenticated(auth);
      setLoading(false);
    });

    return () => keycloak.destroy();
  }, []);

  return { keycloak, authenticated, loading };
}

// Usage in component
function App() {
  const { keycloak, authenticated, loading } = useAuth();

  if (loading) return <div>Loading...</div>;

  if (!authenticated) {
    return <button onClick={() => keycloak.login()}>Login</button>;
  }

  return (
    <div>
      <h1>Welcome {keycloak.getUserProfile()?.username}</h1>
      <button onClick={() => keycloak.logout()}>Logout</button>
    </div>
  );
}
```

## Session Monitoring Example

```typescript
import { KeycloakAdapter } from '@vhrmo/keycloak-adapter';

const keycloak = new KeycloakAdapter({
  url: 'https://keycloak.example.com',
  realm: 'my-realm',
  clientId: 'my-client',
  enableSessionMonitoring: true,
  sessionCheckInterval: 5, // Check every 5 seconds
  onSSOLogout: () => {
    alert('You have been logged out from another session');
    window.location.href = '/';
  },
  onSessionTimeout: () => {
    alert('Your session has expired');
    window.location.href = '/session-expired';
  },
  onTokenRefresh: (tokens) => {
    console.log('Token refreshed at', new Date());
    // Optionally save to analytics
  },
});

await keycloak.init();
```

## API Integration Example

```typescript
import { KeycloakAdapter } from '@vhrmo/keycloak-adapter';

class ApiClient {
  private keycloak: KeycloakAdapter;

  constructor(keycloak: KeycloakAdapter) {
    this.keycloak = keycloak;
  }

  async get(url: string) {
    const token = this.keycloak.getToken();
    if (!token) {
      throw new Error('Not authenticated');
    }

    const response = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    if (response.status === 401) {
      // Try to refresh token
      const refreshed = await this.keycloak.refreshToken();
      if (refreshed) {
        // Retry with new token
        return this.get(url);
      } else {
        // Redirect to login
        this.keycloak.login();
        throw new Error('Authentication required');
      }
    }

    return response.json();
  }

  async post(url: string, data: unknown) {
    const token = this.keycloak.getToken();
    if (!token) {
      throw new Error('Not authenticated');
    }

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });

    if (response.status === 401) {
      const refreshed = await this.keycloak.refreshToken();
      if (refreshed) {
        return this.post(url, data);
      } else {
        this.keycloak.login();
        throw new Error('Authentication required');
      }
    }

    return response.json();
  }
}

// Usage
const keycloak = new KeycloakAdapter({
  url: 'https://keycloak.example.com',
  realm: 'my-realm',
  clientId: 'my-client',
});

await keycloak.init();
const api = new ApiClient(keycloak);

const data = await api.get('/api/users');
console.log(data);
```

## Role-Based Access Control

```typescript
import { KeycloakAdapter } from '@vhrmo/keycloak-adapter';

const keycloak = new KeycloakAdapter({
  url: 'https://keycloak.example.com',
  realm: 'my-realm',
  clientId: 'my-client',
});

await keycloak.init();

// Check realm roles
if (keycloak.hasRole('admin')) {
  console.log('User can access admin panel');
}

// Check client-specific roles
if (keycloak.hasRole('write', 'documents-service')) {
  console.log('User can write documents');
}

// Get all roles
const profile = keycloak.getUserProfile();
console.log('Realm roles:', profile?.realmRoles);
console.log('Client roles:', profile?.clientRoles);

// Example role-based rendering
function renderAdminButton() {
  if (keycloak.hasRole('admin')) {
    return '<button>Admin Panel</button>';
  }
  return '';
}
```
