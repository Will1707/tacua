// SPDX-License-Identifier: Apache-2.0

import { useMemo } from "react";
import { Image, Text, View } from "react-native";

import type { LaunchQRCodeProps } from "@/components/launch-qr-code";
import { colors } from "@/theme/colors";
import { launchQRCodeDataUri } from "@/utils/launch-qr-data-uri";

export function LaunchQRCode({ launchUrl }: LaunchQRCodeProps) {
  const dataUri = useMemo(() => launchQRCodeDataUri(launchUrl), [launchUrl]);

  if (!dataUri) {
    return (
      <Text selectable accessibilityRole="alert" style={{ color: colors.orange, lineHeight: 20 }}>
        Tacua could not generate a QR code in this browser. Open this reviewer page on the QA iPhone and start the review there.
      </Text>
    );
  }
  return (
    <View style={{ alignItems: "center", paddingVertical: 4 }}>
      <Image
        accessibilityLabel="One-time QR code for opening the registered QA build on an iPhone"
        accessibilityRole="image"
        resizeMode="contain"
        source={{ uri: dataUri }}
        style={{ aspectRatio: 1, maxWidth: 320, width: "100%" }}
      />
    </View>
  );
}
