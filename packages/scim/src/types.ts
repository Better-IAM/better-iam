import type { CredentialInput, IamStore, ResourceRef, StoredRecord } from '@better-iam/core';

export const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
export const ENTERPRISE_SCHEMA = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
export const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
export const ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
export const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
export const LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
export const SEARCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:SearchRequest';
export const BULK_REQUEST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:BulkRequest';
export const BULK_RESPONSE_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:BulkResponse';
/** Bulk limits advertised in ServiceProviderConfig and enforced by the /Bulk endpoint. */
export const BULK_MAX_OPERATIONS = 100;
export const MAX_PAYLOAD_SIZE = 1024 * 1024;

export type ObjectValue = Record<string, unknown>;
/** A provisioning connection: one bearer token, one tenant, its own users and groups. */
export interface Connection extends StoredRecord {
  name: string;
  tokenHash: string;
  expiresAt: number;
  revoked: boolean;
  roleMappings: Record<string, string[]>;
  createdAt?: number;
  /** When the token last authenticated a request (recorded at most once a minute). */
  lastUsedAt?: number;
  /** When the token was last rotated; the previous token stops working immediately. */
  rotatedAt?: number;
}
/** Administrative view of a connection; never includes the token or its hash. */
export interface ConnectionSummary {
  id: string;
  tenantId: string;
  name: string;
  path: string;
  expiresAt: number;
  revoked: boolean;
  createdAt?: number;
  lastUsedAt?: number;
  rotatedAt?: number;
  users: number;
  groups: number;
  roleMappings: Record<string, string[]>;
}
/** Administrative view of a group an IdP pushed through a connection, with its mapped roles. */
export interface GroupSummary {
  /** The SCIM group ID (the key of `roleMappings`). */
  id: string;
  /** The local IAM group the SCIM group maintains. */
  groupId: string;
  displayName: string;
  externalId?: string;
  /** Provisioned members. */
  members: number;
  roleIds: string[];
}
export interface UserLink extends StoredRecord {
  connectionId: string;
  identityId: string;
  userName: string;
  externalId?: string;
  displayName: string;
  active: boolean;
  emails?: ObjectValue[];
  name?: ObjectValue;
  title?: string;
  /** The enterprise user extension (department, division, manager, …) as provisioned. */
  enterprise?: ObjectValue;
  version: number;
  createdAt: number;
  updatedAt: number;
}
/** The provisioned attributes handed to `mapAttributes`. */
export interface ProvisionedUser {
  userName: string;
  displayName: string;
  externalId?: string;
  active: boolean;
  title?: string;
  enterprise?: ObjectValue;
  emails?: ObjectValue[];
  name?: ObjectValue;
}
export interface GroupLink extends StoredRecord {
  connectionId: string;
  groupId: string;
  displayName: string;
  externalId?: string;
  members: string[];
  version: number;
  createdAt: number;
  updatedAt: number;
}
export type ResourceType = 'Users' | 'Groups';

export interface ScimConfig {
  store: IamStore;
  /** Must authenticate the credential and throw on a denied IAM permission. */
  authorize(credential: CredentialInput, action: string, resource: ResourceRef): Promise<unknown>;
  authenticate(credential: CredentialInput): Promise<{ identity: { id: string } }>;
  basePath?: string;
  /**
   * Where `handler` serves the JSON administration API for connections (`{adminBasePath}/connections/{list,create,
   * rotate,revoke,groups,mappings}`), default `/scim/admin`. Must be absolute and must not overlap `basePath`.
   */
  adminBasePath?: string;
  /**
   * Maps the enterprise extension's `manager.value` (a SCIM user ID, `externalId`, or `userName` of the same
   * connection) to `Identity.managerId`, back-filling reports provisioned before their manager. Managers an
   * administrator set are never cleared by SCIM. Default true.
   */
  mapManager?: boolean;
  /**
   * Maps a provisioned user's SCIM attributes (core `title`, the enterprise extension's `department`, `division`,
   * `manager`, …) to the identity attributes the product declares; return undefined to leave attributes untouched.
   */
  mapAttributes?(user: ProvisionedUser): Record<string, unknown> | undefined;
  /** Validates mapped attributes against the declared identity attributes; the server's protocol host supplies it. */
  validateIdentityAttributes?(attributes: Record<string, unknown>): Record<string, unknown>;
  /** Trusted server callback. Called transactionally only for administrator-configured role mappings. */
  syncRoleMappings?(
    tx: IamStore,
    input: {
      tenantId: string;
      connectionId: string;
      groupId: string;
      identityIds: string[];
      roleIds: string[];
      credential?: CredentialInput;
    },
  ): Promise<void>;
}
