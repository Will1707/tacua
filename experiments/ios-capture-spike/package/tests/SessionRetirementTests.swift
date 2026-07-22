// SPDX-License-Identifier: Apache-2.0

import Darwin
import Foundation

private enum SessionRetirementTestFailure: Error { case assertion(String) }

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw SessionRetirementTestFailure.assertion(message) }
}

private func expectFailure(_ operation: () throws -> Void) throws {
  do {
    try operation()
    throw SessionRetirementTestFailure.assertion("Expected retirement failure")
  } catch is SessionRetirementTestFailure {
    throw SessionRetirementTestFailure.assertion("Expected retirement failure")
  } catch {}
}

@main
enum SessionRetirementTests {
  static func main() throws {
    try anchorsTraversalAtCanonicalHomeWithoutPrefixConfusion()
    try retiresWholeTreeWithoutFollowingLinks()
    try rejectsRedirectedOrAmbiguousSessionNames()
    try renameFsyncAmbiguityRecovers()
    try finalUnlinkFsyncAmbiguityRecovers()
    print("Tacua scoped session retirement tests passed")
  }

  private static func makeRoot(_ suffix: String) throws -> URL {
    let root = FileManager.default.temporaryDirectory
      .appendingPathComponent("tacua-retirement-\(suffix)-\(UUID().uuidString)", isDirectory: true)
      .resolvingSymlinksInPath()
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    return root
  }

  private static func anchorsTraversalAtCanonicalHomeWithoutPrefixConfusion() throws {
    let root = try makeRoot("home-anchor")
    defer { try? FileManager.default.removeItem(at: root) }
    let canonicalHome = root.appendingPathComponent("sandbox-home", isDirectory: true)
    let nested = canonicalHome.appendingPathComponent(
      "Library/Caches/TacuaCapture",
      isDirectory: true
    )
    let sibling = root.appendingPathComponent("sandbox-home-other", isDirectory: true)
    try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: sibling, withIntermediateDirectories: false)
    let homeAlias = root.appendingPathComponent("sandbox-home-alias", isDirectory: true)
    try FileManager.default.createSymbolicLink(at: homeAlias, withDestinationURL: canonicalHome)
    let resolvedHome = try canonicalExistingDirectory(canonicalHome)
    let resolvedNested = try canonicalExistingDirectory(nested)
    let resolvedSibling = try canonicalExistingDirectory(sibling)

    let nestedPlan = try TacuaScopedSessionRetirer.directoryTraversalPlan(
      for: resolvedNested,
      homeDirectory: homeAlias
    )
    try require(nestedPlan.anchorPath == resolvedHome.path, "Did not use canonical home anchor")
    try require(
      nestedPlan.relativeComponents == ["Library", "Caches", "TacuaCapture"],
      "Home-relative traversal components were incorrect"
    )

    let exactHomePlan = try TacuaScopedSessionRetirer.directoryTraversalPlan(
      for: resolvedHome,
      homeDirectory: homeAlias
    )
    try require(exactHomePlan.anchorPath == resolvedHome.path, "Exact home was not anchored")
    try require(exactHomePlan.relativeComponents.isEmpty, "Exact home traversed extra components")

    let siblingPlan = try TacuaScopedSessionRetirer.directoryTraversalPlan(
      for: resolvedSibling,
      homeDirectory: resolvedHome
    )
    try require(siblingPlan.anchorPath == "/", "Path-prefix sibling escaped the root fallback")
  }

  private static func canonicalExistingDirectory(_ directory: URL) throws -> URL {
    var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
    guard directory.path.withCString({ realpath($0, &buffer) }) != nil else {
      throw SessionRetirementTestFailure.assertion("Could not canonicalize test directory")
    }
    return URL(fileURLWithPath: String(cString: buffer), isDirectory: true)
  }

  private static func retiresWholeTreeWithoutFollowingLinks() throws {
    let root = try makeRoot("whole-tree")
    defer { try? FileManager.default.removeItem(at: root) }
    let session = root.appendingPathComponent("session_retire_001", isDirectory: true)
    let diagnostics = session.appendingPathComponent("diagnostics", isDirectory: true)
    let partials = session.appendingPathComponent("unexpected/partials", isDirectory: true)
    try FileManager.default.createDirectory(at: diagnostics, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: partials, withIntermediateDirectories: true)
    for relative in [
      "manifest.json", "backend-admission-v1.json", "recording-active.marker",
      "diagnostics/session_retire_001.diagnostics-v1.jsonl", "unexpected/partials/frame.tmp",
    ] {
      try Data(relative.utf8).write(to: session.appendingPathComponent(relative))
    }
    let protected = session.appendingPathComponent("protected.partial")
    try Data("protected".utf8).write(to: protected)
    try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: protected.path)
    let outside = root.appendingPathComponent("outside-must-survive.txt")
    try Data("outside".utf8).write(to: outside)
    try FileManager.default.createSymbolicLink(
      at: session.appendingPathComponent("outside-link"),
      withDestinationURL: outside
    )

    let retirer = try TacuaScopedSessionRetirer(sessionDirectory: session)
    try retirer.retireSession()
    try require(!FileManager.default.fileExists(atPath: session.path), "Live session survived")
    try require(
      !FileManager.default.fileExists(
        atPath: root.appendingPathComponent(".tacua-retiring-session_retire_001").path
      ),
      "Hidden retirement directory survived"
    )
    try require(
      FileManager.default.fileExists(atPath: outside.path),
      "Session symlink retirement followed and deleted its external target"
    )
    try retirer.retireSession()
    try require(FileManager.default.fileExists(atPath: outside.path), "Idempotent retry escaped scope")
  }

  private static func rejectsRedirectedOrAmbiguousSessionNames() throws {
    let root = try makeRoot("redirect")
    defer { try? FileManager.default.removeItem(at: root) }
    let outside = root.appendingPathComponent("outside", isDirectory: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
    let session = root.appendingPathComponent("session_redirect_001", isDirectory: true)
    try FileManager.default.createSymbolicLink(at: session, withDestinationURL: outside)
    let redirected = try TacuaScopedSessionRetirer(sessionDirectory: session)
    try expectFailure { try redirected.retireSession() }
    try require(FileManager.default.fileExists(atPath: outside.path), "Redirect target was removed")
    try FileManager.default.removeItem(at: session)

    try FileManager.default.createDirectory(at: session, withIntermediateDirectories: false)
    let hidden = root.appendingPathComponent(
      ".tacua-retiring-session_redirect_001",
      isDirectory: true
    )
    try FileManager.default.createDirectory(at: hidden, withIntermediateDirectories: false)
    try expectFailure { try redirected.retireSession() }
    try require(
      FileManager.default.fileExists(atPath: session.path)
        && FileManager.default.fileExists(atPath: hidden.path),
      "Ambiguous live/retiring names were destructively guessed"
    )
  }

  private static func renameFsyncAmbiguityRecovers() throws {
    let root = try makeRoot("rename-fsync")
    defer { try? FileManager.default.removeItem(at: root) }
    let session = root.appendingPathComponent("session_rename_fsync_001", isDirectory: true)
    try FileManager.default.createDirectory(at: session, withIntermediateDirectories: false)
    try Data("partial".utf8).write(to: session.appendingPathComponent("partial.tmp"))
    var calls = 0
    let failing = try TacuaScopedSessionRetirer(
      sessionDirectory: session,
      directorySynchronizer: { descriptor in
        calls += 1
        if calls == 1 { return false }
        return fsync(descriptor) == 0
      }
    )
    try expectFailure { try failing.retireSession() }
    try require(!FileManager.default.fileExists(atPath: session.path), "Rename did not happen")
    try require(
      FileManager.default.fileExists(
        atPath: root.appendingPathComponent(
          ".tacua-retiring-session_rename_fsync_001"
        ).path
      ),
      "Rename ambiguity lost the recognizable recovery directory"
    )
    try TacuaScopedSessionRetirer(sessionDirectory: session).retireSession()
    try require(
      !FileManager.default.fileExists(
        atPath: root.appendingPathComponent(
          ".tacua-retiring-session_rename_fsync_001"
        ).path
      ),
      "Retry did not scavenge the renamed session"
    )
  }

  private static func finalUnlinkFsyncAmbiguityRecovers() throws {
    let root = try makeRoot("unlink-fsync")
    defer { try? FileManager.default.removeItem(at: root) }
    let session = root.appendingPathComponent("session_unlink_fsync_001", isDirectory: true)
    try FileManager.default.createDirectory(at: session, withIntermediateDirectories: false)
    try Data("partial".utf8).write(to: session.appendingPathComponent("partial.tmp"))
    var calls = 0
    let failing = try TacuaScopedSessionRetirer(
      sessionDirectory: session,
      directorySynchronizer: { descriptor in
        calls += 1
        if calls == 4 { return false }
        return fsync(descriptor) == 0
      }
    )
    try expectFailure { try failing.retireSession() }
    try require(!FileManager.default.fileExists(atPath: session.path), "Live name returned")
    try require(
      !FileManager.default.fileExists(
        atPath: root.appendingPathComponent(
          ".tacua-retiring-session_unlink_fsync_001"
        ).path
      ),
      "Final unlink did not occur before injected parent-fsync failure"
    )
    try TacuaScopedSessionRetirer(sessionDirectory: session).retireSession()
  }
}
