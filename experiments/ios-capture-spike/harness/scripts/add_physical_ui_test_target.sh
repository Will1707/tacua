#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

TACUA_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TACUA_RUBY_SCRIPT="$TACUA_SCRIPT_DIRECTORY/add_physical_ui_test_target.rb"

if ruby -e 'require "xcodeproj"' >/dev/null 2>&1; then
  exec ruby "$TACUA_RUBY_SCRIPT" "$@"
fi

if command -v brew >/dev/null 2>&1; then
  TACUA_COCOAPODS_PREFIX=$(brew --prefix cocoapods 2>/dev/null || true)
  TACUA_RUBY_PREFIX=$(brew --prefix ruby 2>/dev/null || true)
  if [ -n "$TACUA_COCOAPODS_PREFIX" ] && [ -x "$TACUA_RUBY_PREFIX/bin/ruby" ]; then
    GEM_HOME="$TACUA_COCOAPODS_PREFIX/libexec" \
      exec "$TACUA_RUBY_PREFIX/bin/ruby" "$TACUA_RUBY_SCRIPT" "$@"
  fi
fi

echo "Tacua physical UI tests require the xcodeproj Ruby gem (normally installed with CocoaPods)." >&2
exit 1
