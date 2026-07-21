// SPDX-License-Identifier: Apache-2.0

import { createContext, type PropsWithChildren, useCallback, useEffect, useMemo, useState } from "react";

import { TacuaApiClient } from "@/api/client";
import { loadBackendConfig, type BackendConfig } from "@/config/backend-config";

type BackendContextValue = {
  readonly config: BackendConfig | null;
  readonly client: TacuaApiClient | null;
  readonly loading: boolean;
  readonly reload: () => Promise<void>;
};

export const BackendContext = createContext<BackendContextValue | null>(null);

export function BackendProvider({ children }: PropsWithChildren) {
  const [config, setConfig] = useState<BackendConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setConfig(await loadBackendConfig());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const value = useMemo<BackendContextValue>(
    () => ({ config, client: config ? new TacuaApiClient(config) : null, loading, reload }),
    [config, loading, reload],
  );
  return <BackendContext value={value}>{children}</BackendContext>;
}
