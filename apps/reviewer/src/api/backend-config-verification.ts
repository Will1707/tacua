// SPDX-License-Identifier: Apache-2.0

import {
  type BackendConfig,
  validateBackendConfig,
  validateBackendConnectionConfig,
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
  // Only origin and administrator credential are trusted before bootstrap.
  // The provisional client uses the supplied identity/scheme solely to call
  // the admin-authenticated additive endpoint; no identity-bound operation is
  // performed through it.
  const provisional = validateBackendConnectionConfig(candidate);
  const bootstrapClient = createClient(provisional);
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
    // A pre-bootstrap backend cannot prove either manual field. Validate both
    // only now, then bind them before any legacy registry read.
    const legacyConfig = validateBackendConfig(provisional);
    const legacyClient = createClient(legacyConfig);
    await legacyClient.verifyReviewerIdentity();
    await legacyClient.listBuilds();
    return { config: legacyConfig, client: legacyClient };
  }
  const [build] = bootstrap.builds;
  if (!build || bootstrap.builds.length !== 1) {
    throw new Error("The Tacua deployment must register exactly one reviewer build.");
  }
  const verifiedConfig = validateBackendConfig({
    ...provisional,
    reviewerId: bootstrap.reviewer_id,
    targetScheme: build.launch_scheme ?? provisional.targetScheme,
  });
  const verifiedClient = createClient(verifiedConfig);
  await verifiedClient.verifyReviewerIdentity();
  return { config: verifiedConfig, client: verifiedClient };
}

export async function verifyBackendConfig(
  candidate: BackendConfig,
  dependencies: BackendConfigVerificationDependencies,
): Promise<BackendConfig> {
  const connection = validateBackendConnectionConfig(candidate);
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
