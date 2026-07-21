// SPDX-License-Identifier: Apache-2.0

import { ActivityIndicator, Pressable, Text } from "react-native";

import { colors } from "@/theme/colors";

type Props = {
  readonly label: string;
  readonly onPress: () => void;
  readonly disabled?: boolean;
  readonly loading?: boolean;
  readonly destructive?: boolean;
};

export function ActionButton({ label, onPress, disabled = false, loading = false, destructive = false }: Props) {
  const tint = destructive ? colors.red : colors.blue;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: disabled || loading, busy: loading }}
      disabled={disabled || loading}
      onPress={onPress}
      style={({ pressed }) => ({
        minHeight: 44,
        borderRadius: 12,
        borderCurve: "continuous",
        alignItems: "center",
        justifyContent: "center",
        paddingHorizontal: 16,
        backgroundColor: tint,
        opacity: disabled ? 0.4 : pressed ? 0.75 : 1,
      })}
    >
      {loading ? <ActivityIndicator color="white" /> : <Text style={{ color: "white", fontSize: 16, fontWeight: "700" }}>{label}</Text>}
    </Pressable>
  );
}
