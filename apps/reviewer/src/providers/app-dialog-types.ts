// SPDX-License-Identifier: Apache-2.0

export type AppDialogButton = {
  readonly text: string;
  readonly onPress?: () => void;
  readonly style?: "default" | "cancel" | "destructive";
};

export type ShowAppDialog = (
  title: string,
  message?: string,
  buttons?: readonly AppDialogButton[],
) => void;
