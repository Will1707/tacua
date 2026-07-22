// SPDX-License-Identifier: Apache-2.0

export class AdminPageCursorError extends Error {
  constructor() {
    super("INVALID_PAGE_CURSOR");
    this.name = "AdminPageCursorError";
  }
}

export function isAdminPageCursor(value: unknown): value is string | null {
  return value === null || (
    typeof value === "string"
    && value.length >= 1
    && value.length <= 512
    && value.length % 4 !== 1
    && /^[A-Za-z0-9_-]+$/.test(value)
  );
}

export function adminPageHeaders(cursor?: string): Readonly<Record<"Tacua-Page-Cursor", string>> | undefined {
  if (cursor === undefined) return undefined;
  if (!isAdminPageCursor(cursor) || cursor === null) throw new AdminPageCursorError();
  return { "Tacua-Page-Cursor": cursor };
}
