// SPDX-License-Identifier: Apache-2.0

import { createContext, type PropsWithChildren, useCallback, useEffect, useMemo, useState } from "react";

import { TacuaApiClient } from "@/api/client";
import { loadBackendConfig, type BackendConfig } from "@/config/backend-config";

type BackendContextValue = {
  readonly config: BackendConfig | null;
  readonly client: TacuaApiClient | null;
  readonly error: string | null;
  readonly loading: boolean;
  readonly reload: () => Promise<void>;
};

export const BackendContext = createContext<BackendContextValue | null>(null);

export function BackendProvider({ children }: PropsWithChildren) {
  const [config, setConfig] = useState<BackendConfig | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setConfig(await loadBackendConfig());
    } catch (caught) {
      // A credential-store failure must not silently retain an earlier client
      // or masquerade as a first-run, unconfigured installation.
      setConfig(null);
      setError(caught instanceof Error
        ? caught.message
        : "Tacua could not read the secure backend configuration.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const value = useMemo<BackendContextValue>(
    () => ({ config, client: config ? new TacuaApiClient(config) : null, error, loading, reload }),
    [config, error, loading, reload],
  );
  return <BackendContext value={value}>{children}</BackendContext>;
}
