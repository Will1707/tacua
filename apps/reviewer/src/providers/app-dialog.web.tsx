// SPDX-License-Identifier: Apache-2.0

import {
  createContext,
  type PropsWithChildren,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Modal, Pressable, ScrollView, Text, View } from "react-native";

import type {
  AppDialogButton,
  ShowAppDialog,
} from "@/providers/app-dialog-types";
import { colors } from "@/theme/colors";

const MAX_PENDING_DIALOGS = 8;

type Dialog = {
  readonly buttons: readonly AppDialogButton[];
  readonly id: number;
  readonly message?: string;
  readonly owner: symbol;
  readonly title: string;
};

type DialogContextValue = {
  readonly dismissOwner: (owner: symbol) => void;
  readonly show: (
    owner: symbol,
    title: string,
    message?: string,
    buttons?: readonly AppDialogButton[],
  ) => void;
};

const DialogContext = createContext<DialogContextValue | null>(null);

function normalizedButtons(
  buttons?: readonly AppDialogButton[],
): readonly AppDialogButton[] {
  if (!buttons?.length) return [{ text: "OK" }];
  return buttons.slice(0, 4).map((button) => ({
    text: button.text,
    onPress: button.onPress,
    style: button.style,
  }));
}

export function AppDialogProvider({ children }: PropsWithChildren) {
  const [dialogs, setDialogs] = useState<readonly Dialog[]>([]);
  const nextId = useRef(0);
  const active = dialogs[0] ?? null;

  const show = useCallback<DialogContextValue["show"]>(
    (owner, title, message, buttons) => {
      const dialog: Dialog = {
        buttons: normalizedButtons(buttons),
        id: nextId.current + 1,
        message,
        owner,
        title,
      };
      nextId.current = dialog.id;
      setDialogs((current) => (
        current.length >= MAX_PENDING_DIALOGS
          ? current
          : [...current, dialog]
      ));
    },
    [],
  );
  const dismissOwner = useCallback((owner: symbol) => {
    setDialogs((current) => current.filter((dialog) => dialog.owner !== owner));
  }, []);
  const value = useMemo(
    () => ({ dismissOwner, show }),
    [dismissOwner, show],
  );

  const act = useCallback((dialog: Dialog, button: AppDialogButton) => {
    setDialogs((current) => (
      current[0]?.id === dialog.id ? current.slice(1) : current
    ));
    button.onPress?.();
  }, []);
  const dismissActive = useCallback(() => {
    if (!active) return;
    const button = active.buttons.find((candidate) => candidate.style === "cancel")
      ?? active.buttons[0];
    if (button) act(active, button);
  }, [act, active]);

  return (
    <DialogContext.Provider value={value}>
      {children}
      <Modal
        animationType="fade"
        onRequestClose={dismissActive}
        transparent
        visible={active !== null}
      >
        {active ? (
          <View
            accessibilityLabel={active.title}
            accessibilityLiveRegion="assertive"
            accessibilityRole="alert"
            accessibilityViewIsModal
            style={{
              alignItems: "center",
              backgroundColor: "rgba(0, 0, 0, 0.62)",
              flex: 1,
              justifyContent: "center",
              padding: 20,
            }}
          >
            <View
              style={{
                backgroundColor: colors.secondaryBackground,
                borderColor: colors.separator,
                borderRadius: 18,
                borderWidth: 1,
                gap: 16,
                maxHeight: "85%",
                maxWidth: 520,
                padding: 20,
                width: "100%",
              }}
            >
              <ScrollView
                contentContainerStyle={{ gap: 8 }}
                keyboardShouldPersistTaps="handled"
              >
                <Text
                  accessibilityRole="header"
                  selectable
                  style={{
                    color: colors.label,
                    fontSize: 20,
                    fontWeight: "800",
                    lineHeight: 25,
                  }}
                >
                  {active.title}
                </Text>
                {active.message ? (
                  <Text
                    selectable
                    style={{
                      color: colors.secondaryLabel,
                      fontSize: 16,
                      lineHeight: 22,
                    }}
                  >
                    {active.message}
                  </Text>
                ) : null}
              </ScrollView>
              <View style={{ gap: 10 }}>
                {active.buttons.map((button, index) => {
                  const destructive = button.style === "destructive";
                  const cancel = button.style === "cancel";
                  const backgroundColor = destructive
                    ? colors.red
                    : cancel ? colors.groupedBackground : colors.primary;
                  const foreground = destructive
                    ? colors.systemBackground
                    : cancel ? colors.label : colors.onPrimary;
                  return (
                    <Pressable
                      accessibilityLabel={button.text}
                      accessibilityRole="button"
                      key={`${active.id}:${index}:${button.text}`}
                      onPress={() => act(active, button)}
                      style={({ pressed }) => ({
                        alignItems: "center",
                        backgroundColor,
                        borderColor: cancel ? colors.separator : backgroundColor,
                        borderRadius: 12,
                        borderWidth: 1,
                        justifyContent: "center",
                        minHeight: 46,
                        opacity: pressed ? 0.72 : 1,
                        paddingHorizontal: 16,
                        paddingVertical: 10,
                      })}
                    >
                      <Text
                        style={{
                          color: foreground,
                          fontSize: 16,
                          fontWeight: "800",
                          textAlign: "center",
                        }}
                      >
                        {button.text}
                      </Text>
                    </Pressable>
                  );
                })}
              </View>
            </View>
          </View>
        ) : null}
      </Modal>
    </DialogContext.Provider>
  );
}

export function useAppDialog(): ShowAppDialog {
  const context = useContext(DialogContext);
  if (!context) {
    throw new Error("AppDialogProvider is required");
  }
  const owner = useRef(Symbol("tacua-dialog-owner"));
  useEffect(
    () => () => context.dismissOwner(owner.current),
    [context],
  );
  return useCallback(
    (title, message, buttons) => (
      context.show(owner.current, title, message, buttons)
    ),
    [context],
  );
}
