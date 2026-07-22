// SPDX-License-Identifier: Apache-2.0

import {
  type BackendConfig,
  validateBackendConfig,
} from "../config/backend-config-validation.ts";

export type BackendConfigurationClient = {
  readonly listBuilds: () => Promise<unknown>;
};

export type BackendConfigVerificationDependencies = {
  readonly probeBackend: (baseUrl: string) => Promise<unknown>;
  readonly createClient: (config: BackendConfig) => BackendConfigurationClient;
};

export type BackendConfigPersistenceDependencies = BackendConfigVerificationDependencies & {
  readonly persistConfig: (config: BackendConfig) => Promise<void>;
};

export async function verifyBackendConfig(
  candidate: BackendConfig,
  dependencies: BackendConfigVerificationDependencies,
): Promise<BackendConfig> {
  const config = validateBackendConfig(candidate);
  await dependencies.probeBackend(config.baseUrl);
  const client = dependencies.createClient(config);
  await client.listBuilds();
  return config;
}

export async function verifyAndPersistBackendConfig(
  candidate: BackendConfig,
  dependencies: BackendConfigPersistenceDependencies,
): Promise<BackendConfig> {
  const config = await verifyBackendConfig(candidate, dependencies);
  await dependencies.persistConfig(config);
  return config;
}
