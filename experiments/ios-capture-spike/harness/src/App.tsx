import * as TacuaCapture from '@tacua/ios-capture-spike';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
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
]);

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export default function App(): React.JSX.Element {
  const [consented, setConsented] = useState(false);
  const [status, setStatus] = useState<TacuaCapture.CaptureStatus | null>(null);
  const [recoverable, setRecoverable] = useState<
    readonly TacuaCapture.RecoverableSession[]
  >([]);
  const [busy, setBusy] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const capabilities = useMemo(() => TacuaCapture.getCapabilities(), []);

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
      segmentDurationSeconds: 10,
      organizationId: 'org_local',
      projectId: 'tacua_capture_lab',
      buildId: 'ios_1',
      handoffId: `handoff_${sessionId}`,
      handoffTokenIdentifier: `opaque_${sessionId}`,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      consentVersion: 'tacua-local-capture-consent-v1',
      expectedApplicationId: APPLICATION_ID,
      expectedBuildNumber: BUILD_NUMBER,
    }),
    [],
  );

  const refreshRecovery = useCallback(async () => {
    const sessions = await TacuaCapture.listRecoverableSessions();
    setRecoverable(sessions);
    log(`Recovery scan: ${sessions.length} local session(s)`);
  }, [log]);

  useEffect(() => {
    setStatus(TacuaCapture.getStatus());
    const subscriptions = [
      TacuaCapture.subscribe('onState', (event) => {
        setStatus(event);
        log(`State: ${event.state}`);
      }),
      TacuaCapture.subscribe('onSegment', (event) => {
        log(
          `Segment ${event.index}: ${event.byteLength} bytes, ${event.durationSeconds.toFixed(1)}s`,
        );
      }),
      TacuaCapture.subscribe('onGap', (event) => log(`Gap: ${event.reason}`)),
      TacuaCapture.subscribe('onMarker', (event) => log(`Marker: ${event.label}`)),
      TacuaCapture.subscribe('onError', (event) => log(`${event.code}: ${event.reason}`)),
    ];
    return () => subscriptions.forEach((subscription) => subscription.remove());
  }, [log]);

  const start = async () => {
    if (!consented) return;
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

  const stop = async () => {
    setBusy(true);
    try {
      const next = await TacuaCapture.stop();
      setStatus(next);
      log(
        `Stopped: ${next.state}, ${next.segmentCount} segment(s), ${next.gapCount} gap(s), ${next.microphoneSamplesObserved} mic sample(s), errors: ${next.errorCodes.join(', ') || 'none'}`,
      );
      await refreshRecovery();
    } catch (error) {
      log(`Stop failed: ${safeMessage(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const resumeSession = async (sessionId: string) => {
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
      await refreshRecovery();
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
      await refreshRecovery();
    } catch (error) {
      log(`Delete failed: ${safeMessage(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const recording = status?.recorderRecording === true;

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
              disabled={recording}
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
          <Text style={styles.metric}>Segments: {status?.segmentCount ?? 0}</Text>
          <Text style={styles.metric}>Gaps: {status?.gapCount ?? 0}</Text>
          <Text style={styles.metric}>
            Mic samples: {status?.microphoneSamplesObserved ?? 0}
          </Text>
          <Text style={styles.metric}>
            Errors: {status?.errorCodes.join(', ') || 'none'}
          </Text>
          <View style={styles.buttonGap} />
          {!recording ? (
            <Button
              title="Start local recording"
              onPress={() => void start()}
              disabled={!consented || busy}
            />
          ) : (
            <>
              <Button
                title="Mark spoken issue"
                onPress={() => void mark()}
                disabled={busy}
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
              onPress={() => void refreshRecovery()}
              disabled={busy || recording}
            />
          </View>
          {recoverable.length === 0 ? (
            <Text style={styles.body}>No recovery metadata loaded.</Text>
          ) : (
            recoverable.map((session) => (
              <View key={session.sessionId} style={styles.sessionRow}>
                <View style={styles.sessionText}>
                  <Text style={styles.metric}>{session.sessionId}</Text>
                  <Text style={styles.muted}>
                    {session.state} · {session.segmentCount} segment(s)
                  </Text>
                </View>
                <View style={styles.sessionActions}>
                  {RESUMABLE_STATES.has(session.state) ? (
                    <Button
                      title="Resume"
                      onPress={() => void resumeSession(session.sessionId)}
                      disabled={busy}
                    />
                  ) : null}
                  {session.state !== 'completed' &&
                  session.state !== 'partial_ready_for_upload' &&
                  session.segmentCount > 0 ? (
                    <Button
                      title="Keep partial"
                      onPress={() => void keepPartial(session.sessionId)}
                      disabled={busy}
                    />
                  ) : null}
                  <Button
                    title="Delete"
                    color="#ef4444"
                    onPress={() => void deleteSession(session.sessionId)}
                    disabled={busy}
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
  log: {
    color: '#a7f3d0',
    fontSize: 12,
    fontFamily: Platform.select({ ios: 'Menlo', default: 'monospace' }),
  },
});
