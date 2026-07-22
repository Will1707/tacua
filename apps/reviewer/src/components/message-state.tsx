// SPDX-License-Identifier: Apache-2.0

import { Text, View } from "react-native";

import { colors } from "@/theme/colors";

type Props = { readonly title: string; readonly detail: string };

export function MessageState({ title, detail }: Props) {
  return (
    <View style={{ paddingVertical: 48, paddingHorizontal: 24, alignItems: "center", gap: 8 }}>
      <Text selectable style={{ color: colors.label, fontSize: 19, fontWeight: "700", textAlign: "center" }}>{title}</Text>
      <Text selectable style={{ color: colors.secondaryLabel, fontSize: 15, textAlign: "center", lineHeight: 21 }}>{detail}</Text>
    </View>
  );
}
