// SPDX-License-Identifier: Apache-2.0

import { use } from "react";

import { BackendContext } from "@/providers/backend-provider";

export function useBackend() {
  const value = use(BackendContext);
  if (!value) throw new Error("useBackend must be used inside BackendProvider.");
  return value;
}
