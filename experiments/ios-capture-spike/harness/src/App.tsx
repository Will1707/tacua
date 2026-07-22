// SPDX-License-Identifier: Apache-2.0

import * as TacuaCapture from '@tacua/mobile-sdk';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Alert,
  Button,
  Platform,
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Switch,
  Text,
  View,
} from 'react-native';

const APPLICATION_ID = 'com.tacua.capturelab';
const BUILD_NUMBER = '1';

type LogEntry = Readonly<{ id: string; message: string }>;

const RESUMABLE_STATES = new Set([
  'prepared',
  'recording',
  'stopping',
  'recoverable_partial',
  'partial',
  'failed_no_verified_segments',
  'stop_failed_capture_active',
  'start_cleanup_pending',
]);

const ACTIVE_SESSION_STATES = new Set([
  'prepared',
  'recording',
  'stopping',
  'start_cleanup_pending',
  'stop_failed_capture_active',
]);

function safeMessage(error: unknown): string {
  if (error !== null && typeof error === 'object') {
    const candidate = error as { code?: unknown; message?: unknown };
    const code = typeof candidate.code === 'string' ? candidate.code : null;
    const message =
      typeof candidate.message === 'string' ? candidate.message : String(error);
    return code && !message.includes(code) ? `${code}: ${message}` : message;
  }
  return String(error);
}

function recoveryTitle(state: string): string {
  switch (state) {
    case 'recoverable_partial':
      return 'Interrupted · action required';
    case 'partial_ready_for_upload':
      return 'Verified partial';
    case 'partial':
      return 'Partial session';
    case 'completed':
      return 'Completed session';
    case 'failed_no_verified_segments':
      return 'Failed session';
    default:
      return 'Local session';
  }
}

function isWriterFinishFault(plan: string | null): boolean {
  return (
    plan === 'writer_finish_failure_1' ||
    plan === 'writer_finish_timeout_1'
  );
}

function faultSegmentDurationSeconds(plan: string | null): number {
  // This exceeds the 15-second writer watchdog and leaves one full segment
  // window for the JS event bridge to Stop after segment 0 commits.
  return isWriterFinishFault(plan) ? 30 : plan ? 2 : 10;
}

function faultInstructions(plan: string, consumed: boolean): string {
  if (consumed) {
    switch (plan) {
      case 'low_storage_start':
        return 'The Start attempt consumed this process lease, including when storage rejection created no session. Terminate and relaunch before another run.';
      case 'low_storage_writer_1':
        return 'The lease is consumed. Let rotation reach index 1 and stop partial, then terminate and relaunch before another run.';
      case 'writer_finish_failure_1':
      case 'writer_finish_timeout_1':
        return 'The lease is consumed. The harness will invoke Stop exactly once as soon as Segment 0 commits; do not tap Stop first. Relaunch before another run.';
      case 'stop_failure_once':
      case 'stop_timeout_once':
        return 'The lease is consumed. Wait for Segment 0, then tap Stop once and let Tacua retry safely. Relaunch before another run.';
      case 'stop_timeout_twice':
        return 'The lease is consumed. Wait for Segment 0 and tap Stop. After the expected rejection, tap Stop again for mandatory cleanup, then relaunch.';
      default:
        return 'The one-shot lease is consumed. Finish any active cleanup, then terminate and relaunch before another run.';
    }
  }

  switch (plan) {
    case 'low_storage_start':
      return 'Tap Start once. It should reject before ReplayKit starts or a session is created.';
    case 'low_storage_writer_1':
      return 'Start and narrate. The first two-second segment should survive; rotation should then stop partial.';
    case 'writer_finish_failure_1':
    case 'writer_finish_timeout_1':
      return 'Tap Start and narrate. The harness will invoke Stop exactly once immediately after Segment 0 commits; do not tap Stop first.';
    case 'stop_failure_once':
    case 'stop_timeout_once':
      return 'Start, wait for Segment 0, then tap Stop once. Tacua should retry safely.';
    case 'stop_timeout_twice':
      return 'Start, wait for Segment 0, and tap Stop. After the expected rejection, tap Stop again for mandatory cleanup.';
    default:
      return 'Follow the active QA fault plan and keep this synthetic harness in the foreground.';
  }
}

export default function App(): React.JSX.Element {
  const [consented, setConsented] = useState(false);
  const [status, setStatus] = useState<TacuaCapture.CaptureStatus | null>(null);
  const [recoverable, setRecoverable] = useState<
    readonly TacuaCapture.RecoverableSession[]
  >([]);
  const [busy, setBusy] = useState(false);
  const [recoveryBusy, setRecoveryBusy] = useState(true);
  const [cleanupPollingExpired, setCleanupPollingExpired] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const capabilities = useMemo(() => TacuaCapture.getCapabilities(), []);
  const faultPlan = capabilities.testFaultPlan ?? null;
  const initiallyConsumed = capabilities.testFaultLeaseConsumed === true;
  const [faultLeaseConsumed, setFaultLeaseConsumed] = useState(initiallyConsumed);
  const faultLeaseConsumedRef = useRef(initiallyConsumed);
  const activeRecoveryScansRef = useRef(0);

  const log = useCallback((message: string) => {
    console.info(`[Tacua EXP-001] ${message}`);
    setLogs((current) => [
      { id: `${Date.now()}-${Math.random()}`, message },
      ...current,
    ].slice(0, 12));
  }, []);

  const options = useCallback(
    (sessionId: string): TacuaCapture.CaptureStartOptions => ({
      sessionId,
      segmentDurationSeconds: faultSegmentDurationSeconds(faultPlan),
      organizationId: 'org_local',
      projectId: 'tacua_capture_lab',
      buildId: 'ios_1',
      handoffId: `handoff_${sessionId}`,
      handoffTokenIdentifier: `opaque_${sessionId}`,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      // Synthetic fault-campaign input only. Supported host capture uses the exact value returned
      // by createCaptureSessionPlan/resumeCaptureSessionPlan, backed by a committed START queue.
      rawMediaExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
        .toISOString()
        .replace(/\.\d{3}Z$/u, 'Z'),
      consentVersion: 'tacua-local-capture-consent-v1',
      expectedApplicationId: APPLICATION_ID,
      expectedBuildNumber: BUILD_NUMBER,
    }),
    [faultPlan],
  );

  const refreshRecovery = useCallback(async () => {
    if (activeRecoveryScansRef.current > 0) {
      return;
    }
    activeRecoveryScansRef.current += 1;
    setRecoveryBusy(true);
    try {
      const sessions = await TacuaCapture.listRecoverableSessions();
      setRecoverable(
        [...sessions].sort((left, right) =>
          (right.createdAt ?? '').localeCompare(left.createdAt ?? ''),
        ),
      );
      log(`Recovery scan: ${sessions.length} local session(s)`);
    } finally {
      activeRecoveryScansRef.current -= 1;
      if (activeRecoveryScansRef.current === 0) {
        setRecoveryBusy(false);
      }
    }
  }, [log]);

  const stop = useCallback(async () => {
    setBusy(true);
    try {
      const next = await TacuaCapture.stop();
      setStatus(next);
      log(
        `Stopped: ${next.state}, ${next.segmentCount} segment(s), ${next.gapCount} gap(s), ${next.microphoneSamplesObserved} mic sample(s), errors: ${next.errorCodes.join(', ') || 'none'}`,
      );
      try {
        await refreshRecovery();
      } catch (error) {
        log(`Stopped, but recovery refresh failed: ${safeMessage(error)}`);
      }
    } catch (error) {
      log(`Stop failed: ${safeMessage(error)}`);
    } finally {
      setBusy(false);
    }
  }, [log, refreshRecovery]);

  useEffect(() => {
    const initialStatus = TacuaCapture.getStatus();
    setStatus(initialStatus);
    if (
      faultPlan &&
      (capabilities.testFaultLeaseConsumed === true ||
        initialStatus.state !== 'idle')
    ) {
      faultLeaseConsumedRef.current = true;
      setFaultLeaseConsumed(true);
    }
    if (initialStatus.state !== 'process_cleanup_pending') {
      void refreshRecovery().catch((error: unknown) => {
        log(`Initial recovery scan failed: ${safeMessage(error)}`);
      });
    } else {
      setRecoveryBusy(false);
    }
    const subscriptions = [
      TacuaCapture.subscribe('onState', (event) => {
        setStatus(event);
        log(`State: ${event.state}`);
      }),
      TacuaCapture.subscribe('onSegment', (event) => {
        log(
          `Segment ${event.index}: ${event.byteLength} bytes, ${event.durationSeconds.toFixed(1)}s, ${event.heldVideoSamples ?? 0} held frame(s)`,
        );
      }),
      TacuaCapture.subscribe('onGap', (event) => log(`Gap: ${event.reason}`)),
      TacuaCapture.subscribe('onMarker', (event) => log(`Marker: ${event.label}`)),
      TacuaCapture.subscribe('onError', (event) => log(`${event.code}: ${event.reason}`)),
    ];
    return () => subscriptions.forEach((subscription) => subscription.remove());
  }, [capabilities.testFaultLeaseConsumed, faultPlan, log, refreshRecovery, stop]);

  useEffect(() => {
    if (
      status?.state !== 'process_cleanup_pending' ||
      cleanupPollingExpired
    ) {
      return;
    }

    let cancelled = false;
    let delayMilliseconds = 1_000;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const deadline = Date.now() + 30_000;

    const schedulePoll = () => {
      const remainingMilliseconds = deadline - Date.now();
      if (remainingMilliseconds <= 0) {
        setCleanupPollingExpired(true);
        log('Process cleanup is still pending; relaunch or retry the status check');
        return;
      }
      timer = setTimeout(() => {
        if (cancelled) return;
        const next = TacuaCapture.getStatus();
        setStatus(next);
        if (next.state !== 'process_cleanup_pending') {
          log(`Process cleanup finished: ${next.state}`);
          void refreshRecovery().catch((error: unknown) => {
            log(`Recovery scan after cleanup failed: ${safeMessage(error)}`);
          });
          return;
        }
        if (Date.now() >= deadline) {
          setCleanupPollingExpired(true);
          log('Process cleanup is still pending; relaunch or retry the status check');
          return;
        }
        delayMilliseconds = Math.min(delayMilliseconds * 2, 5_000);
        schedulePoll();
      }, Math.min(delayMilliseconds, remainingMilliseconds));
    };

    schedulePoll();
    return () => {
      cancelled = true;
      if (timer !== null) {
        clearTimeout(timer);
      }
    };
  }, [cleanupPollingExpired, log, refreshRecovery, status?.state]);

  const retryProcessCleanupStatus = useCallback(() => {
    const next = TacuaCapture.getStatus();
    setStatus(next);
    if (next.state === 'process_cleanup_pending') {
      setCleanupPollingExpired(false);
      log('Retrying the bounded process-cleanup status check');
      return;
    }
    setCleanupPollingExpired(false);
    log(`Process cleanup finished: ${next.state}`);
    void refreshRecovery().catch((error: unknown) => {
      log(`Recovery scan after cleanup failed: ${safeMessage(error)}`);
    });
  }, [log, refreshRecovery]);

  const start = async () => {
    if (!consented) return;
    if (activeRecoveryScansRef.current > 0) {
      log('Wait for the local recovery scan to finish before starting');
      return;
    }
    if (faultPlan && faultLeaseConsumedRef.current) {
      log('QA fault lease already consumed; terminate and relaunch the app');
      return;
    }
    if (faultPlan) {
      // A native lease is claimed by the start attempt itself, including a
      // fail-closed preparation rejection that never creates a session.
      faultLeaseConsumedRef.current = true;
      setFaultLeaseConsumed(true);
    }
    const sessionId = `qa_${Date.now()}`;
    setBusy(true);
    try {
      const next = await TacuaCapture.start(options(sessionId));
      setStatus(next);
      log(`Started ${sessionId}`);
    } catch (error) {
      log(`Start failed: ${safeMessage(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const mark = async () => {
    setBusy(true);
    try {
      await TacuaCapture.mark('spoken_issue');
    } catch (error) {
      log(`Mark failed: ${safeMessage(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const resumeSession = async (sessionId: string) => {
    if (faultPlan) {
      log('Resume is disabled in a fault-injection process; relaunch first');
      return;
    }
    setBusy(true);
    try {
      const next = await TacuaCapture.resume(options(sessionId));
      setStatus(next);
      log(`Resumed ${sessionId}`);
    } catch (error) {
      log(`Resume failed: ${safeMessage(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const keepPartial = async (sessionId: string) => {
    setBusy(true);
    try {
      const next = await TacuaCapture.markPartialReadyForUpload(
        options(sessionId),
      );
      log(`Kept verified partial ${sessionId}: ${next.segmentCount} segment(s)`);
      try {
        await refreshRecovery();
      } catch (error) {
        log(`Partial kept, but recovery refresh failed: ${safeMessage(error)}`);
      }
    } catch (error) {
      log(`Keep partial failed: ${safeMessage(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const deleteSession = async (sessionId: string) => {
    setBusy(true);
    try {
      await TacuaCapture.deleteSession(options(sessionId));
      log(`Deleted ${sessionId}`);
      try {
        await refreshRecovery();
      } catch (error) {
        log(`Session deleted, but recovery refresh failed: ${safeMessage(error)}`);
      }
    } catch (error) {
      log(`Delete failed: ${safeMessage(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const requestDeleteSession = (sessionId: string, segmentCount: number) => {
    Alert.alert(
      'Delete this local session?',
      `This permanently removes ${segmentCount} verified segment${segmentCount === 1 ? '' : 's'} and its metadata from this device.`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: () => void deleteSession(sessionId),
        },
      ],
    );
  };

  const recording = status?.recorderRecording === true;
  const activeSession = ACTIVE_SESSION_STATES.has(status?.state ?? '');
  const processCleanupPending = status?.state === 'process_cleanup_pending';

  return (
    <SafeAreaView style={styles.safeArea}>
      <StatusBar barStyle="light-content" />
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.eyebrow}>EXP-001 · PHYSICAL IPHONE</Text>
        <Text style={styles.title}>Tacua Capture Lab</Text>
        <Text style={styles.summary}>
          Local-only ReplayKit test. Nothing uploads. Recording stays inside this
          app until you delete it.
        </Text>

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Before recording</Text>
          <Text style={styles.body}>
            This captures this app, app audio, and microphone narration. Avoid
            personal or production data. iOS may interrupt capture when the app
            backgrounds or the phone locks.
          </Text>
          <View style={styles.consentRow}>
            <Text style={styles.consentLabel}>
              I understand and consent to this local test
            </Text>
            <Switch
              value={consented}
              onValueChange={setConsented}
              disabled={activeSession}
            />
          </View>
        </View>

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Recorder</Text>
          <Text style={styles.metric}>State: {status?.state ?? 'loading'}</Text>
          <Text style={styles.metric}>
            ReplayKit: {capabilities.available ? 'available' : 'unavailable'}
          </Text>
          <Text style={styles.metric}>
            Microphone: {capabilities.microphonePermission}
          </Text>
          {faultPlan ? (
            <>
              <Text style={styles.faultWarning}>
                {faultLeaseConsumed
                  ? `QA fault lease consumed: ${faultPlan} · relaunch required`
                  : `QA fault armed: ${faultPlan}`}
              </Text>
              <Text style={styles.faultInstructions}>
                {faultInstructions(faultPlan, faultLeaseConsumed)}
              </Text>
            </>
          ) : null}
          <Text style={styles.metric}>Segments: {status?.segmentCount ?? 0}</Text>
          <Text style={styles.metric}>Gaps: {status?.gapCount ?? 0}</Text>
          <Text style={styles.metric}>
            Mic samples: {status?.microphoneSamplesObserved ?? 0}
          </Text>
          <Text style={styles.metric}>
            Errors: {status?.errorCodes.join(', ') || 'none'}
          </Text>
          {processCleanupPending ? (
            <>
              <Text style={styles.faultWarning}>
                {cleanupPollingExpired
                  ? 'ReplayKit cleanup did not finish. Terminate and relaunch this app before starting another recording.'
                  : 'A prior module is still cleaning up ReplayKit. Tacua is checking its status for up to 30 seconds.'}
              </Text>
              {cleanupPollingExpired ? (
                <Button
                  title="Retry cleanup status"
                  onPress={retryProcessCleanupStatus}
                  disabled={busy || recoveryBusy}
                />
              ) : null}
            </>
          ) : null}
          <View style={styles.buttonGap} />
          {!activeSession ? (
            <Button
              title="Start local recording"
              onPress={() => void start()}
              disabled={
                !consented ||
                busy ||
                recoveryBusy ||
                processCleanupPending ||
                (Boolean(faultPlan) && faultLeaseConsumed)
              }
            />
          ) : (
            <>
              <Button
                title="Mark spoken issue"
                onPress={() => void mark()}
                disabled={busy || !recording}
              />
              <View style={styles.buttonGap} />
              <Button
                title="Stop and verify"
                onPress={() => void stop()}
                disabled={busy}
                color="#f97316"
              />
            </>
          )}
        </View>

        <View style={styles.card}>
          <View style={styles.rowBetween}>
            <Text style={styles.cardTitle}>Local recovery</Text>
            <Button
              title="Refresh"
              onPress={() => {
                void refreshRecovery().catch((error: unknown) => {
                  log(`Recovery scan failed: ${safeMessage(error)}`);
                });
              }}
              disabled={
                busy || recoveryBusy || activeSession || processCleanupPending
              }
            />
          </View>
          {processCleanupPending ? (
            <Text style={styles.muted}>
              Recovery actions are paused until ReplayKit cleanup finishes.
            </Text>
          ) : faultPlan ? (
            <Text style={styles.muted}>
              Resume is disabled in a fault-injection process. Keep or delete
              verified partials here, then relaunch for another capture.
            </Text>
          ) : null}
          {processCleanupPending ? null : recoverable.length === 0 ? (
            <Text style={styles.body}>No recovery metadata loaded.</Text>
          ) : (
            recoverable.map((session) => (
              <View
                key={session.sessionId}
                style={[
                  styles.sessionRow,
                  session.state === 'recoverable_partial'
                    ? styles.actionSession
                    : null,
                ]}
              >
                <View style={styles.sessionText}>
                  <Text style={styles.metric}>
                    {recoveryTitle(session.state)}
                  </Text>
                  <Text style={styles.muted}>
                    {session.state} · {session.segmentCount} segment(s)
                  </Text>
                  <Text style={styles.sessionId}>{session.sessionId}</Text>
                </View>
                <View style={styles.sessionActions}>
                  {RESUMABLE_STATES.has(session.state) ? (
                    <Button
                      title="Resume"
                      onPress={() => void resumeSession(session.sessionId)}
                      disabled={
                        busy ||
                        recoveryBusy ||
                        processCleanupPending ||
                        Boolean(faultPlan)
                      }
                    />
                  ) : null}
                  {session.state !== 'completed' &&
                  session.state !== 'partial_ready_for_upload' &&
                  session.segmentCount > 0 ? (
                    <Button
                      title="Keep partial"
                      onPress={() => void keepPartial(session.sessionId)}
                      disabled={busy || recoveryBusy || processCleanupPending}
                    />
                  ) : null}
                  <Button
                    title="Delete"
                    color="#ef4444"
                    onPress={() =>
                      requestDeleteSession(
                        session.sessionId,
                        session.segmentCount,
                      )
                    }
                    disabled={busy || recoveryBusy || processCleanupPending}
                  />
                </View>
              </View>
            ))
          )}
        </View>

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Event log</Text>
          {logs.length === 0 ? (
            <Text style={styles.body}>No events yet.</Text>
          ) : (
            logs.map((entry) => (
              <Text key={entry.id} style={styles.log}>
                {entry.message}
              </Text>
            ))
          )}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: '#0b1220' },
  content: { padding: 20, paddingBottom: 44, gap: 16 },
  eyebrow: {
    color: '#5eead4',
    fontSize: 12,
    fontWeight: '700',
    letterSpacing: 1.5,
  },
  title: { color: '#f8fafc', fontSize: 32, fontWeight: '800' },
  summary: { color: '#cbd5e1', fontSize: 16, lineHeight: 23 },
  card: {
    backgroundColor: '#172033',
    borderRadius: 16,
    padding: 16,
    gap: 8,
    borderWidth: 1,
    borderColor: '#2a3a55',
  },
  cardTitle: { color: '#f8fafc', fontSize: 18, fontWeight: '700' },
  body: { color: '#cbd5e1', fontSize: 14, lineHeight: 20 },
  muted: { color: '#94a3b8', fontSize: 12 },
  metric: {
    color: '#e2e8f0',
    fontSize: 14,
    fontVariant: ['tabular-nums'],
  },
  faultWarning: { color: '#fbbf24', fontSize: 14, fontWeight: '700' },
  faultInstructions: { color: '#fde68a', fontSize: 13, lineHeight: 18 },
  consentRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginTop: 8,
  },
  consentLabel: { color: '#f8fafc', flex: 1, fontSize: 14, fontWeight: '600' },
  buttonGap: { height: 6 },
  rowBetween: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  sessionRow: {
    borderTopWidth: 1,
    borderTopColor: '#2a3a55',
    paddingTop: 10,
    marginTop: 4,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  sessionText: { flex: 1 },
  sessionActions: { alignItems: 'flex-end', gap: 4 },
  actionSession: {
    backgroundColor: '#24324a',
    borderRadius: 10,
    paddingHorizontal: 10,
    paddingBottom: 10,
  },
  sessionId: { color: '#64748b', fontSize: 10 },
  log: {
    color: '#a7f3d0',
    fontSize: 12,
    fontFamily: Platform.select({ ios: 'Menlo', default: 'monospace' }),
  },
});
