// SPDX-License-Identifier: Apache-2.0

import { Link } from "expo-router";
import { ScrollView, Text } from "react-native";

import { MessageState } from "@/components/message-state";
import { colors } from "@/theme/colors";

export default function NotFoundRoute() {
  return (
    <ScrollView contentInsetAdjustmentBehavior="automatic" contentContainerStyle={{ padding: 20 }}>
      <MessageState title="Page not found" detail="This Tacua review link is not available." />
      <Link href="/" style={{ color: colors.blue, fontWeight: "700", textAlign: "center" }}>Return to reviews</Link>
    </ScrollView>
  );
}
