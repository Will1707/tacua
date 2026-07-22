// SPDX-License-Identifier: Apache-2.0

import { ThemeProvider } from "expo-router/react-navigation";
import { Stack } from "expo-router/stack";
import { useColorScheme } from "react-native";
import { StatusBar } from "expo-status-bar";

import { BackendProvider } from "@/providers/backend-provider";
import { tacuaNavigationThemes } from "@/theme/colors";

export default function RootLayout() {
  const scheme = useColorScheme();
  return (
    <BackendProvider>
      <ThemeProvider value={scheme === "dark" ? tacuaNavigationThemes.dark : tacuaNavigationThemes.light}>
        <StatusBar style="auto" />
        <Stack screenOptions={{ headerBackButtonDisplayMode: "minimal" }}>
          <Stack.Screen name="index" options={{ title: "Reviews", headerLargeTitle: true }} />
          <Stack.Screen name="sessions/[session-id]" options={{ title: "Review session" }} />
          <Stack.Screen name="candidates/[candidate-id]" options={{ title: "Ticket candidate" }} />
          <Stack.Screen name="settings" options={{ title: "Self-hosted backend", presentation: "formSheet", sheetGrabberVisible: true, sheetAllowedDetents: [0.75, 1] }} />
        </Stack>
      </ThemeProvider>
    </BackendProvider>
  );
}
