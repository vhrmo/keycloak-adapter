/**
 * @vhrmo/keycloak-adapter
 * A TypeScript Keycloak adapter for Single Page Applications
 */

export { KeycloakAdapter } from './KeycloakAdapter';
export { MockKeycloakAdapter, MockAdapterFactory } from './MockKeycloakAdapter';

export type {
  KeycloakAdapterConfig,
  TokenSet,
  TokenPayload,
  AuthState,
  UserProfile,
  SessionInfo,
  MockUserScenario,
} from './types';
