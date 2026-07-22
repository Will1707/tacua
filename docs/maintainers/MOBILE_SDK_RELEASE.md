# Mobile SDK release runbook

Tacua distributes the pre-release iOS SDK as a GitHub Release tarball. The
package remains marked `private` so `npm publish` is disabled; no npm token or
registry ownership is assumed.

The release artifact is intended only for authorized QA/development builds. Do
not add it to an App Store production dependency graph.

## One-time repository protection

Restrict creation and deletion of tags matching `mobile-sdk-v*` to Tacua
maintainers with a GitHub repository ruleset. Keep the default branch protected
and require the `Verify` workflow before merging. The release workflow also
fails unless the tag is annotated and its commit is reachable from the current
default branch, and unless GitHub Actions reports a successful default-branch
`Verify` push run for that exact commit. The workflow has read-only Actions
permission plus repository-contents write permission for release publication.
Checkout does not persist credentials; test, package, and native-build shell
steps receive no `GH_TOKEN` environment. Only the read-only verification query
and final GitHub Release shell step receive it explicitly.

## Prepare and verify a release

1. Update `experiments/ios-capture-spike/package/package.json` to the intended
   pre-1.0 version, update the matching approved-handoff SDK pin in
   `services/backend/config.template.example.json`, regenerate the checked
   config/profile examples, and update release-facing documentation.
2. Run the normal repository verification workflow on the exact commit that
   will be tagged.
3. From a clean checkout of the default branch, preview the package contents:

   ```sh
   node .github/scripts/package-mobile-sdk.mjs \
     --tag mobile-sdk-v0.1.0 \
     --dry-run
   ```

   The validator fails if the package name or tag disagrees with the version,
   npm publication is enabled, an unaudited dependency or manifest field is
   introduced, tests or credential-like files enter the tarball, or the exact
   audited runtime/config file set changes. The non-dry release path also packs
   twice with isolated npm caches and requires byte-identical archives before
   writing the checksum.

4. Create and locally verify a signed, annotated tag, then push only that tag:

   ```sh
   git tag -s mobile-sdk-v0.1.0 -m "Tacua mobile SDK 0.1.0"
   git tag -v mobile-sdk-v0.1.0
   git push origin mobile-sdk-v0.1.0
   ```

   If signed Git tags are not configured, stop and configure a signing key.
   The workflow checks that the tag is annotated, but the maintainer must verify
   its signature before pushing it; the tag ruleset controls who may push or
   delete the tag rather than replacing that local trust check.

The tag starts `.github/workflows/release-mobile-sdk.yml`. It first requires the
successful `Verify` run described above, reruns the SDK and harness checks,
builds the tarball twice with npm lifecycle scripts disabled, writes a SHA-256
checksum only after the archives match, re-verifies that checksum immediately
before upload, uploads both assets to a draft, and publishes the GitHub
prerelease only after those uploads succeed. It never authenticates to npm and
cannot publish the package there. If a failed run leaves a draft, inspect and
remove that incomplete draft before rerunning the workflow; never publish it
manually.

## Verify and consume the artifact

Download both assets from the GitHub Release and verify them in the same
directory:

```sh
shasum -a 256 -c tacua-mobile-sdk-0.1.0.tgz.sha256
```

An Expo QA app can then use the public, versioned release URL directly:

```json
{
  "dependencies": {
    "@tacua/mobile-sdk": "https://github.com/Will1707/tacua/releases/download/mobile-sdk-v0.1.0/tacua-mobile-sdk-0.1.0.tgz"
  }
}
```

Run `npm install`, commit the resulting lockfile so npm's artifact integrity is
pinned, configure the Tacua Expo plugin and sealed SDK profile, and rebuild the
native QA client. A JavaScript-only over-the-air update cannot add this native
module.

GitHub prereleases are public because Tacua is an open-source repository. Do
not include credentials, recordings, private source, production telemetry, or
customer-specific configuration in this package or its release notes.
