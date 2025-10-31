/**
 * Keycloak adapter configuration options
 */
export interface KeycloakAdapterConfig {
  /**
   * Keycloak server URL (e.g., 'https://keycloak.example.com')
   */
  url: string;

  /**
   * Realm name
   */
  realm: string;

  /**
   * Client ID
   */
  clientId: string;

  /**
   * Redirect URI after successful authentication
   */
  redirectUri?: string;

  /**
   * Post logout redirect URI
   */
  postLogoutRedirectUri?: string;

  /**
   * Token refresh interval in seconds (default: 60)
   */
  refreshInterval?: number;

  /**
   * Token minimum validity in seconds before refresh (default: 70)
   */
  minValidity?: number;

  /**
   * Enable session monitoring (default: true)
   */
  enableSessionMonitoring?: boolean;

  /**
   * Session check interval in seconds (default: 5)
   */
  sessionCheckInterval?: number;

  /**
   * Enable single session enforcement (default: false)
   */
  enableSingleSession?: boolean;

  /**
   * Callback invoked when SSO logout is detected
   */
  onSSOLogout?: () => void;

  /**
   * Callback invoked when session timeout is detected
   */
  onSessionTimeout?: () => void;

  /**
   * Callback invoked when token is refreshed
   */
  onTokenRefresh?: (tokens: TokenSet) => void;

  /**
   * Callback invoked on authentication errors
   */
  onAuthError?: (error: Error) => void;
}

/**
 * Token set containing all OAuth2/OIDC tokens
 */
export interface TokenSet {
  /**
   * Access token
   */
  accessToken: string;

  /**
   * Refresh token (optional)
   */
  refreshToken?: string;

  /**
   * ID token
   */
  idToken?: string;

  /**
   * Token type (usually 'Bearer')
   */
  tokenType: string;

  /**
   * Expiration time in seconds
   */
  expiresIn: number;

  /**
   * Token received timestamp
   */
  receivedAt: number;
}

/**
 * Parsed token payload
 */
export interface TokenPayload {
  /**
   * Subject (user ID)
   */
  sub: string;

  /**
   * Issued at timestamp
   */
  iat: number;

  /**
   * Expiration timestamp
   */
  exp: number;

  /**
   * Issuer
   */
  iss: string;

  /**
   * Audience
   */
  aud: string | string[];

  /**
   * Session state
   */
  session_state?: string;

  /**
   * Preferred username
   */
  preferred_username?: string;

  /**
   * Email
   */
  email?: string;

  /**
   * Name
   */
  name?: string;

  /**
   * Realm access roles
   */
  realm_access?: {
    roles: string[];
  };

  /**
   * Resource access roles
   */
  resource_access?: {
    [key: string]: {
      roles: string[];
    };
  };

  /**
   * Additional claims
   */
  [key: string]: unknown;
}

/**
 * Authentication state
 */
export interface AuthState {
  /**
   * Whether user is authenticated
   */
  isAuthenticated: boolean;

  /**
   * Current token set
   */
  tokens?: TokenSet;

  /**
   * Parsed access token payload
   */
  tokenPayload?: TokenPayload;

  /**
   * User profile information
   */
  userProfile?: UserProfile;
}

/**
 * User profile information
 */
export interface UserProfile {
  /**
   * User ID
   */
  id: string;

  /**
   * Username
   */
  username?: string;

  /**
   * Email
   */
  email?: string;

  /**
   * Full name
   */
  name?: string;

  /**
   * First name
   */
  firstName?: string;

  /**
   * Last name
   */
  lastName?: string;

  /**
   * Realm roles
   */
  realmRoles?: string[];

  /**
   * Client roles
   */
  clientRoles?: Record<string, string[]>;
}

/**
 * Session information
 */
export interface SessionInfo {
  /**
   * Session ID
   */
  sessionId?: string;

  /**
   * Session state
   */
  sessionState?: string;

  /**
   * Is session active
   */
  isActive: boolean;

  /**
   * Session started at timestamp
   */
  startedAt?: number;

  /**
   * Last activity timestamp
   */
  lastActivityAt?: number;
}

/**
 * Mock user scenario for testing
 */
export interface MockUserScenario {
  /**
   * User ID
   */
  userId: string;

  /**
   * Username
   */
  username: string;

  /**
   * Email
   */
  email?: string;

  /**
   * Roles assigned to the user
   */
  roles: string[];

  /**
   * Client-specific roles
   */
  clientRoles?: Record<string, string[]>;

  /**
   * Whether the user is authenticated
   */
  isAuthenticated?: boolean;

  /**
   * Custom claims to include in token
   */
  customClaims?: Record<string, unknown>;
}
