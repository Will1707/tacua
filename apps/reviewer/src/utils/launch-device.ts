// SPDX-License-Identifier: Apache-2.0

import { Platform } from "react-native";

import { isLikelyIOSBrowser } from "@/utils/launch-device-detection";

export function shouldAttemptSameDeviceLaunch(): boolean {
  if (Platform.OS !== "web") return true;
  if (typeof navigator === "undefined") return false;
  return isLikelyIOSBrowser({
    maxTouchPoints: navigator.maxTouchPoints,
    userAgent: navigator.userAgent,
  });
}
