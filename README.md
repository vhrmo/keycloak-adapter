# Keycloak Adapter for Single Page Applications

A TypeScript-based Keycloak adapter for Single Page Applications (SPA) with comprehensive token management, session management, and testing utilities.

## Features

- ✅ **Token Management**: Automatic token refresh, access token handling, refresh tokens, and ID tokens
- ✅ **Session Management**: SSO logout notifications, session timeout detection, and single session enforcement
- ✅ **TypeScript First**: Full TypeScript support with comprehensive type definitions
- ✅ **Testing Utilities**: Mock adapter factory with predefined test scenarios
- ✅ **Configurable**: Vite-style configuration options with sensible defaults
- ✅ **Zero Dependencies**: No external runtime dependencies (development dependencies only)

## Installation

```bash
npm install @vhrmo/keycloak-adapter
```

## Quick Start

### Basic Usage

```typescript
import { KeycloakAdapter } from '@vhrmo/keycloak-adapter';

// Create and configure the adapter
const keycloak = new KeycloakAdapter({
  url: 'https://keycloak.example.com',
  realm: 'my-realm',
  clientId: 'my-spa-client',
  redirectUri: window.location.origin,
});

// Initialize the adapter
const isAuthenticated = await keycloak.init();

if (!isAuthenticated) {
  // Redirect to login
  keycloak.login();
} else {
  // User is authenticated
  const token = keycloak.getToken();
  const profile = keycloak.getUserProfile();
  console.log('User:', profile);
}
```

## Configuration Options

```typescript
interface KeycloakAdapterConfig {
  // Required
  url: string;                      // Keycloak server URL
  realm: string;                    // Realm name
  clientId: string;                 // Client ID

  // Optional
  redirectUri?: string;             // Default: window.location.origin
  postLogoutRedirectUri?: string;   // Default: window.location.origin
  refreshInterval?: number;         // Token refresh interval in seconds (default: 60)
  minValidity?: number;             // Min validity before refresh in seconds (default: 70)
  enableSessionMonitoring?: boolean; // Enable session monitoring (default: true)
  sessionCheckInterval?: number;    // Session check interval in seconds (default: 5)
  enableSingleSession?: boolean;    // Enable single session enforcement (default: false)

  // Callbacks
  onSSOLogout?: () => void;         // Called when SSO logout detected
  onSessionTimeout?: () => void;    // Called when session timeout detected
  onTokenRefresh?: (tokens: TokenSet) => void;  // Called after token refresh
  onAuthError?: (error: Error) => void;         // Called on auth errors
}
```

## API Reference

### Authentication Methods

#### `init(): Promise<boolean>`
Initialize the adapter and check for existing authentication.

```typescript
const isAuthenticated = await keycloak.init();
```

#### `login(): void`
Initiate the login flow by redirecting to Keycloak.

```typescript
keycloak.login();
```

#### `logout(): Promise<void>`
Logout the user and redirect to post-logout URI.

```typescript
await keycloak.logout();
```

#### `isAuthenticated(): boolean`
Check if the user is currently authenticated.

```typescript
if (keycloak.isAuthenticated()) {
  // User is logged in
}
```

### Token Management

#### `getToken(): string | undefined`
Get the current access token.

```typescript
const token = keycloak.getToken();
// Use token in API requests
fetch('/api/data', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

#### `refreshToken(): Promise<boolean>`
Manually refresh the access token.

```typescript
const refreshed = await keycloak.refreshToken();
```

#### `getAuthState(): AuthState`
Get the complete authentication state.

```typescript
const state = keycloak.getAuthState();
console.log(state.isAuthenticated);
console.log(state.tokens);
console.log(state.userProfile);
```

### User Information

#### `getUserProfile(): UserProfile | undefined`
Get the user profile from the token.

```typescript
const profile = keycloak.getUserProfile();
console.log(profile?.username);
console.log(profile?.email);
console.log(profile?.realmRoles);
```

#### `hasRole(role: string, clientId?: string): boolean`
Check if the user has a specific role.

```typescript
// Check realm role
if (keycloak.hasRole('admin')) {
  // User has admin role
}

// Check client-specific role
if (keycloak.hasRole('manage-users', 'my-app')) {
  // User has manage-users role for my-app client
}
```

### Session Management

#### `getSessionInfo(): SessionInfo`
Get information about the current session.

```typescript
const session = keycloak.getSessionInfo();
console.log(session.isActive);
console.log(session.sessionState);
```

#### `destroy(): void`
Cleanup and destroy the adapter (stops all timers and monitoring).

```typescript
keycloak.destroy();
```

## Testing with Mock Adapter

The library provides a mock adapter for testing and local development without connecting to a real Keycloak server.

### Using Predefined Scenarios

```typescript
import { MockAdapterFactory } from '@vhrmo/keycloak-adapter';

// Admin user with full permissions
const adminAdapter = MockAdapterFactory.createAdmin();

// Regular user
const userAdapter = MockAdapterFactory.createUser();

// Read-only user
const viewerAdapter = MockAdapterFactory.createReadOnly();

// Manager with elevated permissions
const managerAdapter = MockAdapterFactory.createManager();

// Unauthenticated user
const guestAdapter = MockAdapterFactory.createUnauthenticated();

// User with multiple client roles
const multiRoleAdapter = MockAdapterFactory.createWithClientRoles();
```

### Creating Custom Scenarios

```typescript
import { MockAdapterFactory } from '@vhrmo/keycloak-adapter';

const customScenario = {
  userId: 'dev-001',
  username: 'developer',
  email: 'dev@example.com',
  roles: ['user', 'developer'],
  clientRoles: {
    'my-app': ['read', 'write'],
    'api-service': ['api-access']
  },
  isAuthenticated: true,
  customClaims: {
    department: 'Engineering',
    team: 'Frontend'
  }
};

const mockAdapter = MockAdapterFactory.createCustom(customScenario);
await mockAdapter.init();
```

### Environment-Based Adapter Selection

```typescript
import { KeycloakAdapter, MockAdapterFactory } from '@vhrmo/keycloak-adapter';

const adapter = process.env.NODE_ENV === 'development'
  ? MockAdapterFactory.createAdmin()
  : new KeycloakAdapter({
      url: process.env.KEYCLOAK_URL,
      realm: process.env.KEYCLOAK_REALM,
      clientId: process.env.KEYCLOAK_CLIENT_ID,
    });

await adapter.init();
```

## Advanced Usage

### React Integration Example

```typescript
import { createContext, useContext, useEffect, useState } from 'react';
import { KeycloakAdapter } from '@vhrmo/keycloak-adapter';

const KeycloakContext = createContext<KeycloakAdapter | null>(null);

export function KeycloakProvider({ children }: { children: React.ReactNode }) {
  const [keycloak] = useState(() => new KeycloakAdapter({
    url: import.meta.env.VITE_KEYCLOAK_URL,
    realm: import.meta.env.VITE_KEYCLOAK_REALM,
    clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID,
  }));
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    keycloak.init().then(setInitialized);
    return () => keycloak.destroy();
  }, []);

  if (!initialized) {
    return <div>Loading...</div>;
  }

  return (
    <KeycloakContext.Provider value={keycloak}>
      {children}
    </KeycloakContext.Provider>
  );
}

export function useKeycloak() {
  const context = useContext(KeycloakContext);
  if (!context) {
    throw new Error('useKeycloak must be used within KeycloakProvider');
  }
  return context;
}

// Usage in components
function MyComponent() {
  const keycloak = useKeycloak();

  if (!keycloak.isAuthenticated()) {
    return <button onClick={() => keycloak.login()}>Login</button>;
  }

  const profile = keycloak.getUserProfile();

  return (
    <div>
      <p>Welcome, {profile?.username}!</p>
      <button onClick={() => keycloak.logout()}>Logout</button>
    </div>
  );
}
```

### Axios Interceptor Example

```typescript
import axios from 'axios';
import { KeycloakAdapter } from '@vhrmo/keycloak-adapter';

const keycloak = new KeycloakAdapter({
  url: 'https://keycloak.example.com',
  realm: 'my-realm',
  clientId: 'my-client',
});

await keycloak.init();

// Add token to all requests
axios.interceptors.request.use(
  (config) => {
    const token = keycloak.getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Handle token refresh on 401
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      const refreshed = await keycloak.refreshToken();
      if (refreshed) {
        // Retry the request with new token
        error.config.headers.Authorization = `Bearer ${keycloak.getToken()}`;
        return axios.request(error.config);
      } else {
        // Redirect to login
        keycloak.login();
      }
    }
    return Promise.reject(error);
  }
);
```

### Session Monitoring Example

```typescript
const keycloak = new KeycloakAdapter({
  url: 'https://keycloak.example.com',
  realm: 'my-realm',
  clientId: 'my-client',
  enableSessionMonitoring: true,
  sessionCheckInterval: 5,
  onSSOLogout: () => {
    console.log('SSO logout detected');
    window.location.href = '/logged-out';
  },
  onSessionTimeout: () => {
    console.log('Session timeout detected');
    window.location.href = '/session-expired';
  },
  onTokenRefresh: (tokens) => {
    console.log('Token refreshed', tokens);
  },
});
```

## TypeScript Types

All types are exported and available for import:

```typescript
import type {
  KeycloakAdapterConfig,
  TokenSet,
  TokenPayload,
  AuthState,
  UserProfile,
  SessionInfo,
  MockUserScenario,
} from '@vhrmo/keycloak-adapter';
```

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Lint code
npm run lint

# Format code
npm run format
```

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
