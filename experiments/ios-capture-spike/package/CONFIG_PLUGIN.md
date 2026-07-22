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
    "launchScheme": "example-tacua-qa",
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
- `TacuaCaptureBuildVariant`;
- `TacuaCaptureDistribution`;
- `TacuaSDKProfileJSON` (the canonical profile without its file LF);
- `TacuaSDKProfileDigest`; and
- `NSMicrophoneUsageDescription`.

It also registers `launchScheme` in `CFBundleURLTypes`. Use a dedicated 2–64
character scheme. Browser, OS-service, and Tacua reviewer schemes are rejected
so an opaque launch code cannot be routed outside the QA app. The reviewer app
must be configured with that same scheme.

The complete SDK profile, `backendOrigin`, the variant, and the distribution are
public build metadata.
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
