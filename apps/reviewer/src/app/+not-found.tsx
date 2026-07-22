// SPDX-License-Identifier: Apache-2.0

import { Link } from "expo-router";
import { Pressable, ScrollView, Text } from "react-native";

import { MessageState } from "@/components/message-state";
import { colors } from "@/theme/colors";

export default function NotFoundRoute() {
  return (
    <ScrollView contentInsetAdjustmentBehavior="automatic" contentContainerStyle={{ padding: 20, gap: 12 }}>
      <MessageState title="Page not found" detail="This Tacua review link is not available." />
      <Link href="/" asChild>
        <Pressable accessibilityRole="link" style={{ minHeight: 44, justifyContent: "center", alignItems: "center" }}>
          <Text style={{ color: colors.primary, fontWeight: "700", textAlign: "center" }}>Return to reviews</Text>
        </Pressable>
      </Link>
    </ScrollView>
  );
}
