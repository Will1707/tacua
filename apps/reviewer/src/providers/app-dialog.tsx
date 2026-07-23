// SPDX-License-Identifier: Apache-2.0

import type { PropsWithChildren } from "react";
import { Alert } from "react-native";

import type { ShowAppDialog } from "@/providers/app-dialog-types";

export function AppDialogProvider({ children }: PropsWithChildren) {
  return children;
}

export function useAppDialog(): ShowAppDialog {
  return (title, message, buttons) => {
    Alert.alert(
      title,
      message,
      buttons?.map(({ text, onPress, style }) => ({ text, onPress, style })),
    );
  };
}
