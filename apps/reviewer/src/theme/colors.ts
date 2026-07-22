// SPDX-License-Identifier: Apache-2.0

import { DarkTheme, DefaultTheme, type Theme } from "expo-router/react-navigation";
import { DynamicColorIOS, Platform, type ColorValue } from "react-native";

import { palette } from "@/theme/palette";

export { palette } from "@/theme/palette";

type PaletteKey = keyof typeof palette.light;

function adaptive(key: PaletteKey): ColorValue {
  if (Platform.OS === "ios") {
    return DynamicColorIOS({ light: palette.light[key], dark: palette.dark[key] });
  }
  // Android is explicitly deferred from V1. Keep the fallback accessible and
  // deterministic until its own dynamic-colour pass is implemented.
  return palette.light[key];
}

export const colors = {
  label: adaptive("ink"),
  secondaryLabel: adaptive("secondaryInk"),
  tertiaryLabel: adaptive("tertiaryInk"),
  systemBackground: adaptive("background"),
  secondaryBackground: adaptive("surface"),
  groupedBackground: adaptive("grouped"),
  separator: adaptive("outline"),
  primary: adaptive("aqua"),
  onPrimary: adaptive("onAqua"),
  highlight: adaptive("chartreuse"),
  bark: adaptive("bark"),
  green: adaptive("chartreuse"),
  orange: adaptive("rust"),
  red: adaptive("red"),
} as const;

function navigationTheme(scheme: "light" | "dark"): Theme {
  const base = scheme === "dark" ? DarkTheme : DefaultTheme;
  const selected = palette[scheme];
  return {
    ...base,
    colors: {
      ...base.colors,
      primary: selected.aqua,
      background: selected.background,
      card: selected.surface,
      text: selected.ink,
      border: selected.outline,
      notification: selected.red,
    },
  };
}

export const tacuaNavigationThemes = {
  light: navigationTheme("light"),
  dark: navigationTheme("dark"),
} as const;
