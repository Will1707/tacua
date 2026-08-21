# Expo QA-build configuration

Tacua's Expo config plugin writes the public, immutable native settings that the
iOS SDK reads. It deliberately accepts only development and preview builds; it
cannot be configured for an App Store production build.

Generate the public SDK profile with the backend config compiler first. Add the
package only to the QA application's native dependency graph, then add the
plugin to that build's Expo configuration:

```json
[
  "@tacua/mobile-sdk",
  {
    "backendOrigin": "https://qa.example.com",
    "buildVariant": "preview",
    "captureEnabled": true,
    "distribution": "testflight",
    "microphonePermission": "Example QA records your narration and this app's screen only after you approve a review session.",
    "sdkProfilePath": "./config/tacua-sdk-profile.json"
  }
]
```

`sdkProfilePath` is mandatory and resolves from the Expo project root. The
plugin reads only a bounded regular non-symlink file. It requires strict UTF-8,
one exact canonical JSON line, the frozen profile shape, valid nested build and
scope-policy pins, and valid build/transport/profile digests. It rejects
duplicate keys, floats, unsafe integers, BOMs, unknown fields, secret-bearing
field names, non-NFC/control-character text, and any post-generation edit.

This example assumes the profile uses `tacua.sdk-transport@1.2.0` and contains
`"launch_scheme":"example-tacua-qa"`. The plugin derives the native launch
scheme exclusively from that sealed transport object. A legacy V1.1 profile
has no sealed scheme and therefore still requires the explicit
`"launchScheme":"example-tacua-qa"` compatibility option; V1.2 rejects that
manual option.

`backendOrigin`, `buildVariant`, and `distribution` remain explicit so a typo or
wrong EAS profile cannot silently select another registered build; each must
exactly match the SDK profile. The profile bundle identifier must exactly match
`expo.ios.bundleIdentifier`. The plugin also rejects credentials in an origin,
origins containing a path/query/fragment, uppercase or malformed schemes,
production-like variants, and inconsistent variant/distribution pairs.
It writes these exact `Info.plist` values and fails if the app already declares a
different value:

- `TacuaCaptureEnabled`;
- `TacuaBackendOrigin`;
- `TacuaAllowInsecureLoopback`;
- `TacuaLaunchScheme`;
- `TacuaTransportPolicyVersion`;
- `TacuaCaptureBuildVariant`;
- `TacuaCaptureDistribution`;
- `TacuaSDKProfileJSON` (the canonical profile without its file LF);
- `TacuaSDKProfileDigest`;
- `TacuaMaxSegmentBytes`;
- `TacuaMaxDiagnosticBytes`;
- `TacuaMaxCompletionBytes`; and
- `NSMicrophoneUsageDescription`.

It also registers the sealed V1.2 scheme (or the explicit legacy V1.1 scheme)
in `CFBundleURLTypes`. Browser, OS-service, and Tacua reviewer schemes are
rejected so an opaque launch code cannot be routed outside the QA app. V1.2
binds that scheme to the exact registered build so another consumer does not
need to copy it independently.

The complete SDK profile, `backendOrigin`, the three transport byte limits, the
variant, and the distribution are public build metadata. The native SDK requires
the policy, scheme (for V1.2), and three integer plist pins to match the sealed
`tacua.sdk-transport@1.1.0` or `tacua.sdk-transport@1.2.0` configuration and
rejects oversized segment bytes, diagnostic-envelope bytes, or
completion-request bytes before opening the network. The generated profile
uses 3 MiB and 4 MiB as the diagnostic and completion maxima respectively;
these are also the native canonical-parser and durable-queue admission bounds,
not independently expandable server-only allowances.
Do not put an administrator token, SDK bearer credential, launch code, model
key, or another secret in plugin options or Expo public environment variables.

Plain HTTP is accepted only when all of these are true: the origin is loopback,
`allowInsecureLoopback` is explicitly `true`, and the build is a native debug
build. TestFlight and other preview builds require HTTPS.

The config plugin is a build-time guard, not a dependency uninstaller. A host
app must keep this package out of its ordinary production/App Store target or
package manifest. Merely omitting the plugin, hiding UI, or setting
`captureEnabled` to false is not an acceptable production integration. The
native runtime independently rejects a missing or inconsistent QA gate.

The repository's Capture Lab uses the same plugin in its
[Expo configuration](https://github.com/Will1707/tacua/blob/main/experiments/ios-capture-spike/harness/app.json), and the core suite exercises its
strict option parser. A native prebuild test verifies the generated plist in the
development harness.

The plugin intentionally does not expose or write
`TacuaLocalHarnessRetentionBypassEnabled`. That separate repository-harness key
is declared directly by Capture Lab and is accepted natively only in a Debug
build with the exact `com.tacua.capturelab.acceptance` bundle identifier and the
existing local-development QA gates. It cannot enable a release or another host
bundle.
