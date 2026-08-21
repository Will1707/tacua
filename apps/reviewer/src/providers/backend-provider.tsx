// SPDX-License-Identifier: Apache-2.0

import { createContext, type PropsWithChildren, useCallback, useEffect, useMemo, useRef, useState } from "react";

import { loadVerifiedBackendConfig } from "@/api/backend-config-verification";
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
  const [activeBackend, setActiveBackend] = useState<{
    readonly config: BackendConfig;
    readonly client: TacuaApiClient;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const mounted = useRef(true);
  const reloadGeneration = useRef(0);
  const reload = useCallback(async () => {
    if (!mounted.current) return;
    const generation = ++reloadGeneration.current;
    setLoading(true);
    setError(null);
    setActiveBackend(null);
    try {
      const verified = await loadVerifiedBackendConfig({
        loadConfig: loadBackendConfig,
        createClient: (config) => new TacuaApiClient(config),
      });
      if (!mounted.current || generation !== reloadGeneration.current) return;
      setActiveBackend(verified === null ? null : {
        config: verified.config,
        client: verified.client,
      });
    } catch (caught) {
      if (!mounted.current || generation !== reloadGeneration.current) return;
      // A credential-store failure must not silently retain an earlier client
      // or let an unverified/stale identity reach reviewer operations.
      setActiveBackend(null);
      setError(caught instanceof Error
        ? caught.message
        : "Tacua could not verify the secure backend configuration.");
    } finally {
      if (mounted.current && generation === reloadGeneration.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    void reload();
    return () => {
      // Invalidate any verification that settles after this provider unmounts.
      mounted.current = false;
      reloadGeneration.current += 1;
    };
  }, [reload]);

  const value = useMemo<BackendContextValue>(
    () => ({
      config: activeBackend?.config ?? null,
      client: activeBackend?.client ?? null,
      error,
      loading,
      reload,
    }),
    [activeBackend, error, loading, reload],
  );
  return <BackendContext value={value}>{children}</BackendContext>;
}
