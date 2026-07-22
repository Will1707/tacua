// SPDX-License-Identifier: Apache-2.0

import type { PropsWithChildren, ReactNode } from "react";
import { Text, View } from "react-native";

import { colors } from "@/theme/colors";

type Props = PropsWithChildren<{ readonly title: string; readonly trailing?: ReactNode }>;

export function SectionCard({ title, trailing, children }: Props) {
  return (
    <View style={{ backgroundColor: colors.secondaryBackground, borderColor: colors.separator, borderWidth: 1, borderRadius: 16, borderCurve: "continuous", padding: 16, gap: 12 }}>
      <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
        <Text selectable style={{ color: colors.label, fontSize: 17, fontWeight: "700", flex: 1 }}>{title}</Text>
        {trailing}
      </View>
      {children}
    </View>
  );
}
