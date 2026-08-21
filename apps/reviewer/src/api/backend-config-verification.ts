// SPDX-License-Identifier: Apache-2.0

import {
  type BackendConfig,
  validateBackendConfig,
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

export async function verifyBackendConfig(
  candidate: BackendConfig,
  dependencies: BackendConfigVerificationDependencies,
): Promise<BackendConfig> {
  const config = validateBackendConfig(candidate);
  await dependencies.probeBackend(config.baseUrl);
  const client = dependencies.createClient(config);
  let bootstrap: ReviewerBootstrap;
  try {
    bootstrap = await client.getReviewerBootstrap();
  } catch (error) {
    if (
      error === null
      || typeof error !== "object"
      || !("status" in error)
      || error.status !== 404
    ) throw error;
    // Backends predating the additive bootstrap contract remain usable while
    // their transport 1.1 build is migrated. They retain the manual identity
    // and scheme fields because the old build registry cannot prove either.
    await client.verifyReviewerIdentity();
    await client.listBuilds();
    return config;
  }
  const [build] = bootstrap.builds;
  if (!build || bootstrap.builds.length !== 1) {
    throw new Error("The Tacua deployment must register exactly one reviewer build.");
  }
  const verifiedConfig = {
    ...config,
    reviewerId: bootstrap.reviewer_id,
    targetScheme: build.launch_scheme ?? config.targetScheme,
  };
  const verifiedClient = dependencies.createClient(verifiedConfig);
  await verifiedClient.verifyReviewerIdentity();
  return verifiedConfig;
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
  const config = validateBackendConfig(candidate);
  const client = dependencies.createClient(config);
  await client.verifyReviewerIdentity();
  return { config, client };
}
