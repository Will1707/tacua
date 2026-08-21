// SPDX-License-Identifier: Apache-2.0

import {
  createContext,
  type PropsWithChildren,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Platform } from "react-native";

import { TacuaApiClient, TacuaApiError } from "@/api/client";
import type {
  ReviewerBootstrap,
  ReviewerPairingExchange,
  ReviewerPairingRequest,
  ReviewerPrincipal,
} from "@/api/types";
import { probeTacuaBackend } from "@/api/version-probe";
import {
  loadBackendConfig,
  saveBackendConfig,
  type BackendConfig,
  validateBackendConfig,
} from "@/config/backend-config";

export type BackendStatus =
  | "loading"
  | "endpoint_required"
  | "pairing_required"
  | "pairing_pending"
  | "connected"
  | "error";

export type PendingReviewerPairing = Pick<
  ReviewerPairingRequest,
  "pairing_id" | "human_code" | "device_label" | "created_at" | "expires_at"
>;

type BackendState = {
  readonly status: BackendStatus;
  readonly config: BackendConfig | null;
  readonly client: TacuaApiClient | null;
  readonly session: ReviewerPrincipal | null;
  readonly bootstrap: ReviewerBootstrap | null;
  readonly pairing: PendingReviewerPairing | null;
  readonly error: string | null;
  readonly migrationRequired: boolean;
};

export type BackendContextValue = BackendState & {
  readonly loading: boolean;
  readonly reload: () => Promise<void>;
  readonly configureEndpoint: (baseUrl: string) => Promise<void>;
  readonly beginPairing: () => Promise<void>;
  readonly cancelPairing: () => void;
  readonly disconnect: () => Promise<void>;
};

const initialState: BackendState = {
  status: "loading",
  config: null,
  client: null,
  session: null,
  bootstrap: null,
  pairing: null,
  error: null,
  migrationRequired: false,
};

function reviewerClientKind(): "web" | "native" {
  return Platform.OS === "web" ? "web" : "native";
}

function clientFor(config: BackendConfig, csrfToken?: string): TacuaApiClient {
  return new TacuaApiClient({
    baseUrl: config.baseUrl,
    clientKind: reviewerClientKind(),
    ...(config.sessionToken === null ? {} : { sessionToken: config.sessionToken }),
    ...(csrfToken === undefined ? {} : { csrfToken }),
  });
}

function message(caught: unknown, fallback: string): string {
  return caught instanceof Error ? caught.message : fallback;
}

function isApiError(caught: unknown, status: number, code?: string): caught is TacuaApiError {
  return caught instanceof TacuaApiError
    && caught.status === status
    && (code === undefined || caught.code === code);
}

function assertReviewerBinding(
  session: ReviewerPrincipal,
  bootstrap: ReviewerBootstrap,
): void {
  if (session.reviewer_id !== bootstrap.reviewer_id) {
    throw new Error("The reviewer session identity does not match the backend bootstrap identity.");
  }
}

function principalsMatch(
  exchanged: ReviewerPairingExchange,
  session: ReviewerPrincipal,
): boolean {
  return session.auth_kind === "session"
    && session.reviewer_id === exchanged.reviewer_id
    && session.session_id === exchanged.session_id
    && session.device_label === exchanged.device_label
    && session.client_kind === exchanged.client_kind
    && session.expires_at === exchanged.expires_at
    && session.csrf_token === exchanged.csrf_token
    && session.scopes.length === exchanged.scopes.length
    && session.scopes.every((scope, index) => scope === exchanged.scopes[index]);
}

class IssuedSessionCleanupError extends Error {
  constructor() {
    super("Tacua could not safely revoke the reviewer session issued during pairing.");
    this.name = "IssuedSessionCleanupError";
  }
}

function publicPairing(pairing: ReviewerPairingRequest): PendingReviewerPairing {
  return {
    pairing_id: pairing.pairing_id,
    human_code: pairing.human_code,
    device_label: pairing.device_label,
    created_at: pairing.created_at,
    expires_at: pairing.expires_at,
  };
}

function waitForPairingPoll(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 1_500));
}

export const BackendContext = createContext<BackendContextValue | null>(null);

export function BackendProvider({ children }: PropsWithChildren) {
  const [state, setState] = useState<BackendState>(initialState);
  const stateRef = useRef(state);
  const mounted = useRef(false);
  const generation = useRef(0);
  const pendingPairingToken = useRef<string | null>(null);
  const pairingRequestInFlight = useRef(false);
  stateRef.current = state;

  const activate = useCallback(async () => {
    if (!mounted.current) return;
    const activation = ++generation.current;
    pendingPairingToken.current = null;
    setState((current) => ({
      ...initialState,
      status: "loading",
      config: current.config,
    }));
    let config: BackendConfig | null = null;
    try {
      config = await loadBackendConfig();
      if (!mounted.current || activation !== generation.current) return;
      if (config === null) {
        setState({ ...initialState, status: "endpoint_required" });
        return;
      }

      await probeTacuaBackend(config.baseUrl);
      if (!mounted.current || activation !== generation.current) return;
      const bootstrapClient = clientFor(config);
      let session: ReviewerPrincipal;
      try {
        session = await bootstrapClient.getReviewerSession();
      } catch (caught) {
        if (!isApiError(caught, 401)) throw caught;
        if (!mounted.current || activation !== generation.current) return;
        const unauthenticatedConfig = config.sessionToken === null
          ? config
          : { baseUrl: config.baseUrl, sessionToken: null };
        if (config.sessionToken === null) {
          setState({
            ...initialState,
            status: "pairing_required",
            config: unauthenticatedConfig,
          });
          return;
        }
        await saveBackendConfig(unauthenticatedConfig);
        if (!mounted.current || activation !== generation.current) return;
        config = unauthenticatedConfig;
        try {
          // An explicit invalid native bearer correctly prevents the backend
          // from falling through to an injected capability. Retry once without
          // it so a valid Tailscale app capability can connect immediately.
          session = await clientFor(config).getReviewerSession();
        } catch (retryCaught) {
          if (!isApiError(retryCaught, 401)) throw retryCaught;
          if (!mounted.current || activation !== generation.current) return;
          setState({
            ...initialState,
            status: "pairing_required",
            config,
          });
          return;
        }
      }
      if (!mounted.current || activation !== generation.current) return;
      if (session.auth_kind === "legacy_admin") {
        setState({
          ...initialState,
          status: "pairing_required",
          config,
          error: "This backend still uses legacy administrator authentication. Enable reviewer pairing or Tailscale app capabilities on the server.",
          migrationRequired: true,
        });
        return;
      }
      const operationalClient = clientFor(config, session.csrf_token);
      const bootstrap = await operationalClient.getReviewerBootstrap();
      assertReviewerBinding(session, bootstrap);
      if (!mounted.current || activation !== generation.current) return;
      setState({
        ...initialState,
        status: "connected",
        config,
        client: operationalClient,
        session,
        bootstrap,
      });
    } catch (caught) {
      if (!mounted.current || activation !== generation.current) return;
      setState({
        ...initialState,
        status: "error",
        config,
        error: message(caught, "Tacua could not connect to the reviewer backend."),
      });
    }
  }, []);

  const finishPairing = useCallback(async (
    activation: number,
    config: BackendConfig,
    exchanged: ReviewerPairingExchange,
  ) => {
    const clientKind = reviewerClientKind();
    if (clientKind === "native" && !("session_token" in exchanged)) {
      throw new Error("The backend did not return a native reviewer session credential.");
    }
    if (clientKind === "web" && "session_token" in exchanged) {
      throw new Error("The backend returned a bearer credential to the web reviewer.");
    }
    const authenticatedConfig: BackendConfig = {
      baseUrl: config.baseUrl,
      sessionToken: "session_token" in exchanged ? exchanged.session_token : null,
    };
    const issuedClient = clientFor(authenticatedConfig, exchanged.csrf_token);
    let nativePersistenceStarted = false;
    let issuedSessionRevoked = false;

    const isCurrent = () => mounted.current && activation === generation.current;
    const abandonIssuedSession = async () => {
      let cleanupFailed = false;
      if (clientKind === "native" && nativePersistenceStarted) {
        try {
          await saveBackendConfig({ baseUrl: config.baseUrl, sessionToken: null });
        } catch {
          cleanupFailed = true;
        }
      }
      if (!issuedSessionRevoked) {
        try {
          await issuedClient.revokeReviewerSession();
          issuedSessionRevoked = true;
        } catch {
          cleanupFailed = true;
        }
      }
      if (cleanupFailed) throw new IssuedSessionCleanupError();
    };

    try {
      if (!isCurrent()) {
        await abandonIssuedSession();
        return;
      }
      const verificationClient = clientFor(authenticatedConfig);
      const session = await verificationClient.getReviewerSession();
      if (!isCurrent()) {
        await abandonIssuedSession();
        return;
      }
      if (!principalsMatch(exchanged, session)) {
        throw new Error("The issued reviewer session could not be verified.");
      }
      const operationalClient = clientFor(authenticatedConfig, session.csrf_token);
      const bootstrap = await operationalClient.getReviewerBootstrap();
      assertReviewerBinding(session, bootstrap);
      if (!isCurrent()) {
        await abandonIssuedSession();
        return;
      }
      if (clientKind === "native") {
        nativePersistenceStarted = true;
        await saveBackendConfig(authenticatedConfig);
        if (!isCurrent()) {
          await abandonIssuedSession();
          return;
        }
      }
      pendingPairingToken.current = null;
      setState({
        ...initialState,
        status: "connected",
        config: authenticatedConfig,
        client: operationalClient,
        session,
        bootstrap,
      });
    } catch (caught) {
      if (caught instanceof IssuedSessionCleanupError) throw caught;
      try {
        await abandonIssuedSession();
      } catch (cleanupCaught) {
        throw cleanupCaught;
      }
      throw caught;
    }
  }, []);

  const pollPairing = useCallback(async (
    activation: number,
    config: BackendConfig,
    client: TacuaApiClient,
    token: string,
  ) => {
    while (
      mounted.current
      && activation === generation.current
      && pendingPairingToken.current === token
    ) {
      try {
        const exchanged = await client.exchangePairing(token);
        await finishPairing(activation, config, exchanged);
        return;
      } catch (caught) {
        if (isApiError(caught, 409, "PAIRING_NOT_APPROVED")) {
          await waitForPairingPoll();
          continue;
        }
        if (caught instanceof IssuedSessionCleanupError) {
          if (!mounted.current) return;
          // Cleanup failure means an issued session may still be live. Invalidate
          // every newer activation too, so none can overwrite this fail-closed
          // state with a client while that uncertainty remains.
          generation.current += 1;
          pendingPairingToken.current = null;
          setState({
            ...initialState,
            status: "error",
            config,
            error: caught.message,
          });
          return;
        }
        if (!mounted.current || activation !== generation.current) return;
        pendingPairingToken.current = null;
        if (isApiError(caught, 401)) {
          setState({
            ...initialState,
            status: "pairing_required",
            config,
            error: "The pairing request expired. Request a new code to continue.",
          });
          return;
        }
        setState({
          ...initialState,
          status: "error",
          config,
          error: message(caught, "Tacua could not finish reviewer pairing."),
        });
        return;
      }
    }
  }, [finishPairing]);

  const reload = useCallback(async () => {
    await activate();
  }, [activate]);

  const configureEndpoint = useCallback(async (baseUrl: string) => {
    if (reviewerClientKind() === "web") {
      throw new Error("The web reviewer always uses its own origin.");
    }
    const config = validateBackendConfig({ baseUrl, sessionToken: null });
    await saveBackendConfig(config);
    await activate();
  }, [activate]);

  const beginPairing = useCallback(async () => {
    const current = stateRef.current;
    if (
      current.status !== "pairing_required"
      || current.config === null
      || pairingRequestInFlight.current
    ) return;
    pairingRequestInFlight.current = true;
    const pairingClient = clientFor(current.config);
    const activation = ++generation.current;
    pendingPairingToken.current = null;
    setState({
      ...initialState,
      status: "loading",
      config: current.config,
    });
    try {
      const pairing = await pairingClient.createPairingRequest(
        reviewerClientKind() === "web" ? "Tacua web reviewer" : "Tacua native reviewer",
      );
      if (!mounted.current || activation !== generation.current) return;
      pendingPairingToken.current = pairing.pairing_token;
      setState({
        ...initialState,
        status: "pairing_pending",
        config: current.config,
        pairing: publicPairing(pairing),
      });
      void pollPairing(activation, current.config, pairingClient, pairing.pairing_token);
    } catch (caught) {
      if (!mounted.current || activation !== generation.current) return;
      const legacyAdmin = isApiError(caught, 404, "NOT_FOUND");
      setState({
        ...initialState,
        status: "pairing_required",
        config: current.config,
        migrationRequired: legacyAdmin,
        error: legacyAdmin
          ? "This backend still uses legacy administrator authentication. Enable reviewer pairing or Tailscale app capabilities on the server; Tacua no longer accepts an administrator secret in the app."
          : message(caught, "Tacua could not request reviewer pairing."),
      });
    } finally {
      pairingRequestInFlight.current = false;
    }
  }, [pollPairing]);

  const cancelPairing = useCallback(() => {
    const current = stateRef.current;
    if (current.status !== "pairing_pending") return;
    generation.current += 1;
    pendingPairingToken.current = null;
    setState({
      ...initialState,
      status: "pairing_required",
      config: current.config,
    });
  }, []);

  const disconnect = useCallback(async () => {
    const current = stateRef.current;
    if (
      current.status !== "connected"
      || current.config === null
      || current.client === null
      || current.session === null
    ) return;
    if (current.session.auth_kind === "tailscale_capability") {
      setState({
        ...current,
        error: "This connection is granted by a Tailscale app capability. Remove that capability from the tailnet policy to disconnect it.",
      });
      return;
    }
    const activation = ++generation.current;
    setState({ ...current, status: "loading", error: null });
    try {
      await current.client.revokeReviewerSession();
      await saveBackendConfig({ baseUrl: current.config.baseUrl, sessionToken: null });
      if (!mounted.current || activation !== generation.current) return;
      await activate();
    } catch (caught) {
      if (!mounted.current || activation !== generation.current) return;
      setState({
        ...current,
        status: "error",
        client: null,
        session: null,
        bootstrap: null,
        error: message(caught, "Tacua could not disconnect the reviewer session."),
      });
    }
  }, [activate]);

  useEffect(() => {
    mounted.current = true;
    void activate();
    return () => {
      mounted.current = false;
      generation.current += 1;
      pendingPairingToken.current = null;
      pairingRequestInFlight.current = false;
    };
  }, [activate]);

  const value = useMemo<BackendContextValue>(() => ({
    ...state,
    loading: state.status === "loading",
    reload,
    configureEndpoint,
    beginPairing,
    cancelPairing,
    disconnect,
  }), [
    state,
    reload,
    configureEndpoint,
    beginPairing,
    cancelPairing,
    disconnect,
  ]);
  return <BackendContext value={value}>{children}</BackendContext>;
}
