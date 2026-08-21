// SPDX-License-Identifier: Apache-2.0

import {
  type BackendConfig,
  validateBackendConfig,
  validateBackendIdentityConfig,
} from "../config/backend-config-validation.ts";
import type { ReviewerBootstrap } from "./types.ts";

export type BackendConfigurationClient = {
  readonly getReviewerBootstrap: () => Promise<ReviewerBootstrap>;
  readonly listBuilds: () => Promise<unknown>;
  readonly verifyReviewerIdentity: () => Promise<void>;
};

export type BackendConfigVerificationDependencies = {
  readonly probeBackend: (baseUrl: string) => Promise<unknown>;
  readonly createClient: (config: BackendConfig) => BackendConfigurationClient;
};

export type BackendConfigPersistenceDependencies = BackendConfigVerificationDependencies & {
  readonly persistConfig: (config: BackendConfig) => Promise<void>;
};

export type BackendConfigActivationDependencies<
  Client extends BackendConfigurationClient = BackendConfigurationClient,
> = {
  readonly loadConfig: () => Promise<BackendConfig | null>;
  readonly createClient: (config: BackendConfig) => Client;
};

export type ActiveBackendConfig<
  Client extends BackendConfigurationClient = BackendConfigurationClient,
> = {
  readonly config: BackendConfig;
  readonly client: Client;
};

async function authenticateBackendConfig<Client extends BackendConfigurationClient>(
  candidate: BackendConfig,
  createClient: (config: BackendConfig) => Client,
): Promise<ActiveBackendConfig<Client>> {
  // The reviewer identity is always operator-declared. Prove that claim before
  // reading build launch metadata so a wrong or stale identity never reaches
  // persistence, bootstrap-derived configuration, or reviewer operations.
  const identityConfig = validateBackendIdentityConfig(candidate);
  const bootstrapClient = createClient(identityConfig);
  await bootstrapClient.verifyReviewerIdentity();
  let bootstrap: ReviewerBootstrap;
  try {
    bootstrap = await bootstrapClient.getReviewerBootstrap();
  } catch (error) {
    if (
      error === null
      || typeof error !== "object"
      || !("status" in error)
      || error.status !== 404
    ) throw error;
    // The additive build-metadata endpoint may be absent during an upgrade.
    // Validate the legacy manual scheme before exposing a final client.
    const legacyConfig = validateBackendConfig(identityConfig);
    const legacyClient = createClient(legacyConfig);
    await legacyClient.listBuilds();
    return { config: legacyConfig, client: legacyClient };
  }
  const [build] = bootstrap.builds;
  if (!build || bootstrap.builds.length !== 1) {
    throw new Error("The Tacua deployment must register exactly one reviewer build.");
  }
  if (
    bootstrap.contract_version === "tacua.reviewer-bootstrap@1.0.0"
    && bootstrap.reviewer_id !== identityConfig.reviewerId
  ) {
    // The status-only binding already succeeded. Treat disagreement from the
    // legacy migration projection as a bounded consistency failure, never as
    // an alternate source of reviewer identity.
    throw new Error("The reviewer identity does not match this deployment.");
  }
  const verifiedConfig = validateBackendConfig({
    ...identityConfig,
    targetScheme: build.launch_scheme ?? identityConfig.targetScheme,
  });
  const verifiedClient = createClient(verifiedConfig);
  return { config: verifiedConfig, client: verifiedClient };
}

export async function verifyBackendConfig(
  candidate: BackendConfig,
  dependencies: BackendConfigVerificationDependencies,
): Promise<BackendConfig> {
  const connection = validateBackendIdentityConfig(candidate);
  await dependencies.probeBackend(connection.baseUrl);
  return (await authenticateBackendConfig(connection, dependencies.createClient)).config;
}

export async function verifyAndPersistBackendConfig(
  candidate: BackendConfig,
  dependencies: BackendConfigPersistenceDependencies,
): Promise<BackendConfig> {
  const config = await verifyBackendConfig(candidate, dependencies);
  await dependencies.persistConfig(config);
  return config;
}

export async function loadVerifiedBackendConfig<Client extends BackendConfigurationClient>(
  dependencies: BackendConfigActivationDependencies<Client>,
): Promise<ActiveBackendConfig<Client> | null> {
  const candidate = await dependencies.loadConfig();
  if (candidate === null) return null;
  return authenticateBackendConfig(candidate, dependencies.createClient);
}
