// SPDX-License-Identifier: Apache-2.0

import { Text, View } from "react-native";

import { colors } from "@/theme/colors";

type Props = { readonly value: string };

export function StatusPill({ value }: Props) {
  const normalized = value.replaceAll("_", " ");
  const tint = value === "approved" || value === "succeeded" || value === "completed"
    ? colors.green
    : value === "failed" || value === "rejected" || value === "deleted"
      ? colors.red
      : value === "queued" || value === "waiting_for_clarification" || value === "needs_clarification"
        ? colors.orange
        : colors.primary;
  return (
    <View style={{ alignSelf: "flex-start", borderColor: tint, borderWidth: 1, borderRadius: 999, paddingHorizontal: 9, paddingVertical: 4 }}>
      <Text selectable style={{ color: tint, fontSize: 12, fontWeight: "600", textTransform: "capitalize" }}>{normalized}</Text>
    </View>
  );
}
