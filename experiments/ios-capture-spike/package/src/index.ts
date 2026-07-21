// SPDX-License-Identifier: Apache-2.0

import {
  TacuaCaptureSpikeModule,
  type CaptureCapabilities,
  type CaptureErrorEvent,
  type CaptureEventMap,
  type CaptureGapEvent,
  type CaptureMarker,
  type CaptureRecoveryOptions,
  type CaptureSegmentEvent,
  type CaptureStartOptions,
  type CaptureStatus,
  type RecoverableSession,
} from "./TacuaCaptureSpikeModule";
import { type EventSubscription } from "expo-modules-core";

export type {
  CaptureCapabilities,
  CaptureErrorEvent,
  CaptureGapEvent,
  CaptureMarker,
  CaptureRecoveryOptions,
  CaptureSegmentEvent,
  CaptureStartOptions,
  CaptureStatus,
  RecoverableSession,
};

export function getCapabilities(): CaptureCapabilities {
  return TacuaCaptureSpikeModule.getCapabilities();
}

export function getStatus(): CaptureStatus {
  return TacuaCaptureSpikeModule.getStatus();
}

export function start(options: CaptureStartOptions): Promise<CaptureStatus> {
  return TacuaCaptureSpikeModule.start(options);
}

export function resume(options: CaptureStartOptions): Promise<CaptureStatus> {
  return TacuaCaptureSpikeModule.resume(options);
}

export function stop(): Promise<CaptureStatus> {
  return TacuaCaptureSpikeModule.stop();
}

export function mark(label: string): Promise<CaptureMarker> {
  return TacuaCaptureSpikeModule.mark(label);
}

export function listRecoverableSessions(): Promise<
  readonly RecoverableSession[]
> {
  return TacuaCaptureSpikeModule.listRecoverableSessions();
}

export function markPartialReadyForUpload(
  options: CaptureRecoveryOptions,
): Promise<RecoverableSession> {
  return TacuaCaptureSpikeModule.markPartialReadyForUpload(options);
}

export function deleteSession(options: CaptureRecoveryOptions): Promise<void> {
  return TacuaCaptureSpikeModule.deleteSession(options);
}

export function subscribe<K extends keyof CaptureEventMap>(
  eventName: K,
  listener: (event: CaptureEventMap[K]) => void,
): EventSubscription {
  return TacuaCaptureSpikeModule.addListener(eventName, listener);
}
