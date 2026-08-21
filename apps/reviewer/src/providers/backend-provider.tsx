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
import { AppState, Platform } from "react-native";

import { TacuaApiClient, TacuaApiError } from "@/api/client";
import type {
  ReviewerBootstrap,
  ReviewerClientKind,
  ReviewerPairingExchange,
  ReviewerPairingRequest,
  ReviewerPrincipal,
} from "@/api/types";
import { probeTacuaBackend } from "@/api/version-probe";
import {
  loadBackendConfigState,
  saveBackendConfig,
  savePendingPairingCleanup,
  type BackendConfig,
  type PendingPairingCleanup,
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
  readonly cancelPairing: () => Promise<void>;
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

function clientFor(
  config: BackendConfig,
  csrfToken?: string,
  clientKind: ReviewerClientKind = reviewerClientKind(),
): TacuaApiClient {
  return new TacuaApiClient({
    baseUrl: config.baseUrl,
    clientKind,
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

class PairingCleanupError extends Error {
  constructor() {
    super("Tacua could not confirm that this pairing and any issued session were canceled. Try Cancel pairing again before requesting another code.");
    this.name = "PairingCleanupError";
  }
}

class ExistingSessionRetentionError extends Error {
  constructor() {
    super("Tacua could not safely revoke the existing reviewer session, so the previous endpoint was kept.");
    this.name = "ExistingSessionRetentionError";
  }
}

async function revokeNativeSessionBeforeEndpointReplacement(
  config: BackendConfig,
): Promise<void> {
  if (config.sessionToken === null) return;
  let session: ReviewerPrincipal;
  try {
    session = await clientFor(config).getReviewerSession();
  } catch (caught) {
    // A definitive authentication failure proves that this persisted bearer
    // no longer names a live server-side session. Transport and protocol
    // failures do not, so retain the old endpoint and credential for retry.
    if (isApiError(caught, 401)) return;
    throw new ExistingSessionRetentionError();
  }
  if (
    session.auth_kind !== "session"
    || session.session_id === null
    || session.client_kind !== "native"
    || !config.sessionToken.startsWith(`${session.session_id}.`)
  ) throw new ExistingSessionRetentionError();
  try {
    const revoked = await clientFor(config, session.csrf_token).revokeReviewerSession();
    if (
      revoked.session_id !== session.session_id
      || revoked.reviewer_id !== session.reviewer_id
      || revoked.client_kind !== "native"
    ) throw new ExistingSessionRetentionError();
  } catch (caught) {
    // The session can expire or be revoked between the principal probe and
    // DELETE. That 401 is also conclusive; an ambiguous failure is not.
    if (isApiError(caught, 401)) return;
    if (caught instanceof ExistingSessionRetentionError) throw caught;
    throw new ExistingSessionRetentionError();
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

const maximumSessionRevalidationDelay = 2_147_000_000;

export const BackendContext = createContext<BackendContextValue | null>(null);

export function BackendProvider({ children }: PropsWithChildren) {
  const [state, setState] = useState<BackendState>(initialState);
  const stateRef = useRef(state);
  const mounted = useRef(false);
  const generation = useRef(0);
  const pendingPairingToken = useRef<string | null>(null);
  const pairingRequestInFlight = useRef(false);
  const pairingCancellationInFlight = useRef<{
    readonly token: string;
    readonly clientKind: ReviewerClientKind;
    readonly promise: Promise<void>;
  } | null>(null);
  const pairingCancellationRequestInFlight = useRef<{
    readonly token: string;
    readonly clientKind: ReviewerClientKind;
    readonly promise: Promise<void>;
  } | null>(null);
  const pairingExchangeInFlight = useRef<{
    readonly token: string;
    readonly settled: Promise<void>;
  } | null>(null);
  const explicitPairingCancellationInFlight = useRef<{
    readonly token: string;
    readonly promise: Promise<void>;
  } | null>(null);
  const canceledPairingTokens = useRef(new Set<string>());
  const durablePairingCleanup = useRef<PendingPairingCleanup | null>(null);
  const pendingNativePairingPersistence = useRef<{
    readonly token: string;
    readonly settled: Promise<void>;
  } | null>(null);
  const appState = useRef(AppState.currentState);
  const expiryRevalidatedSession = useRef<string | null>(null);
  stateRef.current = state;

  const cancelPairingToken = useCallback((
    config: BackendConfig,
    token: string,
    clientKind: ReviewerClientKind,
  ): Promise<void> => {
    const active = pairingCancellationRequestInFlight.current;
    if (active !== null) {
      if (active.token === token && active.clientKind === clientKind) return active.promise;
      return Promise.reject(new PairingCleanupError());
    }

    let operation: {
      readonly token: string;
      readonly clientKind: ReviewerClientKind;
      readonly promise: Promise<void>;
    };
    const promise = clientFor(
      { baseUrl: config.baseUrl, sessionToken: null },
      undefined,
      clientKind,
    )
      .cancelPairing(token)
      .then(() => undefined)
      .catch(() => {
        throw new PairingCleanupError();
      })
      .finally(() => {
        if (pairingCancellationRequestInFlight.current === operation) {
          pairingCancellationRequestInFlight.current = null;
        }
      });
    operation = { token, clientKind, promise };
    pairingCancellationRequestInFlight.current = operation;
    return promise;
  }, []);

  const cleanPairing = useCallback((
    config: BackendConfig,
    token: string,
    clientKind: ReviewerClientKind = reviewerClientKind(),
  ): Promise<void> => {
    const cancellationKey = `${clientKind}:${token}`;
    if (canceledPairingTokens.current.has(cancellationKey)) return Promise.resolve();
    const active = pairingCancellationInFlight.current;
    if (active !== null) {
      if (active.token === token && active.clientKind === clientKind) return active.promise;
      return Promise.reject(new PairingCleanupError());
    }

    // Capture the raw exchange attempt before sending cancellation. If that
    // request has already crossed the server transaction boundary, its delayed
    // web 201 can install Set-Cookie after the first tombstone response. The
    // exchange must therefore settle inside this barrier, followed by one
    // final idempotent token cancellation, before another pairing is allowed.
    const exchange = pairingExchangeInFlight.current?.token === token
      ? pairingExchangeInFlight.current.settled
      : null;
    const currentPersistedCleanup = durablePairingCleanup.current;
    const persistedCleanup = currentPersistedCleanup?.pairingToken === token
      && currentPersistedCleanup.clientKind === clientKind
      ? currentPersistedCleanup
      : null;
    let operation: {
      readonly token: string;
      readonly clientKind: ReviewerClientKind;
      readonly promise: Promise<void>;
    };
    const promise = (async () => {
      let cancellationSucceeded = false;
      try {
        await cancelPairingToken(config, token, clientKind);
        cancellationSucceeded = true;
      } catch {
        cancellationSucceeded = false;
      }
      if (exchange !== null) {
        await exchange;
        try {
          await cancelPairingToken(config, token, clientKind);
          cancellationSucceeded = true;
        } catch {
          cancellationSucceeded = false;
        }
      }
      if (!cancellationSucceeded) throw new PairingCleanupError();
      const nativePersistence = pendingNativePairingPersistence.current?.token === token
        ? pendingNativePairingPersistence.current
        : null;
      if (nativePersistence !== null) {
        // Serialize the clearing write after the original bearer write. A
        // cancellation must never resolve while an older Secure Store write
        // can still complete later and resurrect the revoked bearer.
        await nativePersistence.settled;
      }
      if (persistedCleanup !== null || nativePersistence !== null) {
        try {
          // Cancellation is the authoritative server-side transition. Only
          // after it succeeds (and any older bearer write settles) may V5 be
          // atomically replaced with its unauthenticated state.
          await saveBackendConfig({ baseUrl: config.baseUrl, sessionToken: null });
          const currentCleanup = durablePairingCleanup.current;
          if (
            currentCleanup?.pairingToken === token
            && currentCleanup.clientKind === clientKind
          ) {
            durablePairingCleanup.current = null;
          }
          if (pendingNativePairingPersistence.current === nativePersistence) {
            pendingNativePairingPersistence.current = null;
          }
        } catch {
          throw new PairingCleanupError();
        }
      }
      canceledPairingTokens.current.add(cancellationKey);
    })().finally(() => {
      if (pairingCancellationInFlight.current === operation) {
        pairingCancellationInFlight.current = null;
      }
    });
    operation = { token, clientKind, promise };
    pairingCancellationInFlight.current = operation;
    return promise;
  }, [cancelPairingToken]);

  const activate = useCallback(async () => {
    if (!mounted.current) return;
    if (pendingPairingToken.current !== null) {
      setState((current) => ({
        ...initialState,
        status: "pairing_pending",
        config: current.config,
        pairing: current.pairing,
        error: current.error ?? "Cancel the current pairing before reconnecting.",
      }));
      return;
    }
    const activation = ++generation.current;
    setState((current) => ({
      ...initialState,
      status: "loading",
      config: current.config,
    }));
    let config: BackendConfig | null = null;
    try {
      const stored = await loadBackendConfigState();
      if (!mounted.current || activation !== generation.current) return;
      if (stored === null) {
        durablePairingCleanup.current = null;
        setState({ ...initialState, status: "endpoint_required" });
        return;
      }
      config = stored.config;
      durablePairingCleanup.current = stored.pendingPairingCleanup;
      if (stored.pendingPairingCleanup !== null) {
        // A native process may have terminated after the backend committed an
        // exchange but before the bearer reached V5. The exact token and kind
        // are the only safe cleanup authority, so recovery precedes every
        // backend probe, authentication attempt, or new pairing.
        await cleanPairing(
          config,
          stored.pendingPairingCleanup.pairingToken,
          stored.pendingPairingCleanup.clientKind,
        );
        if (!mounted.current || activation !== generation.current) return;
        config = { baseUrl: config.baseUrl, sessionToken: null };
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
  }, [cleanPairing]);

  const finishPairing = useCallback(async (
    activation: number,
    config: BackendConfig,
    pairingToken: string,
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

    const isCurrent = () => mounted.current && activation === generation.current;
    const abandonIssuedSession = async () => {
      await cleanPairing(config, pairingToken);
      if (pendingPairingToken.current === pairingToken) {
        pendingPairingToken.current = null;
      }
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
        // The bearer remains memory-only until the returned principal and
        // authoritative bootstrap have both been bound. Mark the write so a
        // concurrent cancellation can also clear an ambiguously completed
        // Secure Store update before another pairing is allowed.
        const persistenceRequest = saveBackendConfig(authenticatedConfig);
        const persistence = {
          token: pairingToken,
          settled: persistenceRequest.then(() => undefined, () => undefined),
        };
        pendingNativePairingPersistence.current = persistence;
        await persistenceRequest;
        if (!isCurrent()) {
          await abandonIssuedSession();
          return;
        }
        const persistedCleanup = durablePairingCleanup.current;
        if (
          persistedCleanup?.pairingToken === pairingToken
          && persistedCleanup.clientKind === clientKind
        ) {
          // The single V5 bearer write above atomically replaced the recovery
          // journal, so only now may its in-memory mirror be forgotten.
          durablePairingCleanup.current = null;
        }
        if (pendingNativePairingPersistence.current === persistence) {
          pendingNativePairingPersistence.current = null;
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
      if (caught instanceof PairingCleanupError) throw caught;
      try {
        await abandonIssuedSession();
      } catch (cleanupCaught) {
        throw cleanupCaught;
      }
      throw caught;
    }
  }, [cleanPairing]);

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
        const exchangeRequest = client.exchangePairing(token);
        const exchangeOperation = {
          token,
          settled: exchangeRequest.then(() => undefined, () => undefined),
        };
        pairingExchangeInFlight.current = exchangeOperation;
        let exchanged: ReviewerPairingExchange;
        try {
          exchanged = await exchangeRequest;
        } finally {
          if (pairingExchangeInFlight.current === exchangeOperation) {
            pairingExchangeInFlight.current = null;
          }
        }
        await finishPairing(activation, config, token, exchanged);
        return;
      } catch (caught) {
        if (isApiError(caught, 409, "PAIRING_NOT_APPROVED")) {
          await waitForPairingPoll();
          continue;
        }
        if (caught instanceof PairingCleanupError) {
          if (!mounted.current || activation !== generation.current) return;
          generation.current += 1;
          setState((current) => ({
            ...initialState,
            status: "pairing_pending",
            config,
            pairing: current.pairing,
            error: caught.message,
          }));
          return;
        }

        // Once an exchange request has been sent, its response can be
        // ambiguous on both native and web: the backend may have issued a
        // session before the client times out or rejects the 201 body. The
        // pairing-token cancellation endpoint is the sole cleanup authority;
        // it atomically deletes an unconsumed request or revokes the session
        // issued from that exact token (and expires the web cookie).
        const wasCurrent = mounted.current && activation === generation.current;
        const pairing = stateRef.current.pairing;
        const cleanupActivation = wasCurrent ? ++generation.current : generation.current;
        if (wasCurrent) {
          setState({
            ...initialState,
            status: "pairing_pending",
            config,
            pairing,
          });
        }
        try {
          await cleanPairing(config, token);
        } catch {
          if (
            wasCurrent
            && mounted.current
            && cleanupActivation === generation.current
            && pendingPairingToken.current === token
          ) {
            setState({
              ...initialState,
              status: "pairing_pending",
              config,
              pairing,
              error: new PairingCleanupError().message,
            });
          }
          return;
        }
        if (pendingPairingToken.current === token) {
          pendingPairingToken.current = null;
        }
        if (!wasCurrent || !mounted.current || cleanupActivation !== generation.current) return;
        setState(isApiError(caught, 401)
          ? {
            ...initialState,
            status: "pairing_required",
            config,
            error: "The pairing request expired. Request a new code to continue.",
          }
          : {
            ...initialState,
            status: "error",
            config,
            error: message(caught, "Tacua could not finish reviewer pairing."),
          });
        return;
      }
    }
  }, [cleanPairing, finishPairing]);

  const reload = useCallback(async () => {
    await activate();
  }, [activate]);

  const configureEndpoint = useCallback(async (baseUrl: string) => {
    if (reviewerClientKind() === "web") {
      throw new Error("The web reviewer always uses its own origin.");
    }
    if (
      pendingPairingToken.current !== null
      || durablePairingCleanup.current !== null
      || pairingCancellationInFlight.current !== null
    ) {
      throw new Error("Cancel the current pairing before changing the backend endpoint.");
    }
    const config = validateBackendConfig({ baseUrl, sessionToken: null });
    generation.current += 1;
    pendingPairingToken.current = null;
    setState({
      ...initialState,
      status: "loading",
      config: stateRef.current.config,
    });
    let previousConfig = stateRef.current.config;
    try {
      const previousState = await loadBackendConfigState();
      if (previousState !== null && previousState.pendingPairingCleanup !== null) {
        durablePairingCleanup.current = previousState.pendingPairingCleanup;
        throw new PairingCleanupError();
      }
      previousConfig = previousState?.config ?? null;
      if (previousConfig !== null) {
        await revokeNativeSessionBeforeEndpointReplacement(previousConfig);
      }
      await saveBackendConfig(config);
    } catch (caught) {
      if (mounted.current) {
        generation.current += 1;
        pendingPairingToken.current = null;
        setState({
          ...initialState,
          status: "error",
          config: previousConfig,
          error: caught instanceof ExistingSessionRetentionError
            ? caught.message
            : message(caught, "Tacua could not safely update the backend endpoint."),
        });
      }
      throw caught;
    }
    await activate();
  }, [activate]);

  const beginPairing = useCallback(async () => {
    const current = stateRef.current;
    if (
      current.status !== "pairing_required"
      || current.config === null
      || pairingRequestInFlight.current
      || pairingCancellationInFlight.current !== null
      || pendingPairingToken.current !== null
    ) return;
    pairingRequestInFlight.current = true;
    const clientKind = reviewerClientKind();
    const pairingClient = clientFor(current.config, undefined, clientKind);
    const activation = ++generation.current;
    pendingPairingToken.current = null;
    setState({
      ...initialState,
      status: "loading",
      config: current.config,
    });
    try {
      const pairing = await pairingClient.createPairingRequest(
        clientKind === "web" ? "Tacua web reviewer" : "Tacua native reviewer",
      );
      if (!mounted.current || activation !== generation.current) return;
      pendingPairingToken.current = pairing.pairing_token;
      if (clientKind === "native") {
        const persistedCleanup: PendingPairingCleanup = {
          pairingToken: pairing.pairing_token,
          clientKind: "native",
        };
        durablePairingCleanup.current = persistedCleanup;
        try {
          // Do not send the first exchange until the exact token and client
          // kind are durably recoverable. If this write has not committed, a
          // process exit can only abandon the short-lived unexchanged request.
          await savePendingPairingCleanup(current.config, persistedCleanup);
        } catch (persistenceError) {
          try {
            await cleanPairing(current.config, pairing.pairing_token, clientKind);
          } catch {
            if (!mounted.current || activation !== generation.current) return;
            setState({
              ...initialState,
              status: "pairing_pending",
              config: current.config,
              pairing: publicPairing(pairing),
              error: new PairingCleanupError().message,
            });
            return;
          }
          if (pendingPairingToken.current === pairing.pairing_token) {
            pendingPairingToken.current = null;
          }
          if (!mounted.current || activation !== generation.current) return;
          setState({
            ...initialState,
            status: "pairing_required",
            config: current.config,
            error: message(
              persistenceError,
              "Tacua could not securely prepare reviewer pairing.",
            ),
          });
          return;
        }
        if (!mounted.current || activation !== generation.current) {
          try {
            await cleanPairing(current.config, pairing.pairing_token, clientKind);
            if (pendingPairingToken.current === pairing.pairing_token) {
              pendingPairingToken.current = null;
            }
          } catch {
            // V5 retains the recovery token for the next provider activation.
          }
          return;
        }
      }
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
  }, [cleanPairing, pollPairing]);

  const cancelPairing = useCallback((): Promise<void> => {
    const current = stateRef.current;
    const token = pendingPairingToken.current;
    if (
      current.status !== "pairing_pending"
      || current.config === null
      || current.pairing === null
      || token === null
    ) return Promise.resolve();
    const active = explicitPairingCancellationInFlight.current;
    if (active !== null && active.token === token) return active.promise;

    const activation = ++generation.current;
    const pairing = current.pairing;
    setState({
      ...initialState,
      status: "pairing_pending",
      config: current.config,
      pairing,
    });

    let operation: { readonly token: string; readonly promise: Promise<void> };
    const promise = cleanPairing(current.config, token)
      .then(() => {
        if (pendingPairingToken.current === token) {
          pendingPairingToken.current = null;
        }
        if (!mounted.current || activation !== generation.current) return;
        setState({
          ...initialState,
          status: "pairing_required",
          config: current.config,
        });
      })
      .catch(() => {
        if (
          !mounted.current
          || activation !== generation.current
          || pendingPairingToken.current !== token
        ) return;
        setState({
          ...initialState,
          status: "pairing_pending",
          config: current.config,
          pairing,
          error: new PairingCleanupError().message,
        });
      })
      .finally(() => {
        if (explicitPairingCancellationInFlight.current === operation) {
          explicitPairingCancellationInFlight.current = null;
        }
      });
    operation = { token, promise };
    explicitPairingCancellationInFlight.current = operation;
    return promise;
  }, [cleanPairing]);

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
      pairingCancellationInFlight.current = null;
      pairingCancellationRequestInFlight.current = null;
      pairingExchangeInFlight.current = null;
      explicitPairingCancellationInFlight.current = null;
      canceledPairingTokens.current.clear();
      pendingNativePairingPersistence.current = null;
    };
  }, [activate]);

  useEffect(() => {
    const subscription = AppState.addEventListener("change", (nextState) => {
      const returnedToTacua = appState.current !== "active" && nextState === "active";
      appState.current = nextState;
      if (returnedToTacua && stateRef.current.status === "connected") void activate();
    });
    return () => subscription.remove();
  }, [activate]);

  useEffect(() => {
    if (state.status !== "connected") return;
    if (state.session?.auth_kind !== "session" || state.session.expires_at === null) {
      expiryRevalidatedSession.current = null;
      return;
    }
    const sessionExpiryKey = `${state.session.session_id}:${state.session.expires_at}`;
    if (expiryRevalidatedSession.current === sessionExpiryKey) return;
    const expiresAt = Date.parse(state.session.expires_at);
    if (!Number.isFinite(expiresAt)) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let canceled = false;
    const schedule = () => {
      if (canceled) return;
      const remaining = expiresAt - Date.now();
      timer = setTimeout(() => {
        timer = null;
        if (expiresAt > Date.now()) schedule();
        else {
          // If the browser clock is ahead of the backend, the revalidation may
          // still return this session. Mark this exact immutable session/expiry
          // pair before activating so that result cannot create a zero-delay
          // request loop. Foreground and explicit refresh remain available.
          expiryRevalidatedSession.current = sessionExpiryKey;
          void activate();
        }
      }, Math.max(0, Math.min(remaining, maximumSessionRevalidationDelay)));
    };
    schedule();
    return () => {
      canceled = true;
      if (timer !== null) clearTimeout(timer);
    };
  }, [activate, state.session, state.status]);

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
