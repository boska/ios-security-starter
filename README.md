# iOS Security Starter

An iOS starter project for teams that want two things from day one:

- a small passive security-check module for debugger, hook, and jailbreak signals
- a CI pipeline that builds an XCFramework and audits the produced binary

This is intentionally not a full RASP product. It is a compact starting point for teams that want a reusable Swift package plus a binary-audit workflow they can extend.

## Threat model

This starter is built around passive, local signals:

- debugger presence
- common hook / instrumentation indicators
- common jailbreak indicators

It assumes you want lightweight on-device checks and a repeatable release audit, not a complete anti-tamper platform.

## What is included

- `MobileSecurityKit` Swift package
- passive checks for debugger, suspicious injected dylibs / Frida port, and jailbreak indicators
- a simple policy layer that maps findings to `allow`, `review`, or `block`
- tests for the public report surface
- GitHub Actions CI
- release workflow that builds and publishes an XCFramework
- `make audit` binary inspection step for shipped artifacts

## Project layout

- `Sources/MobileSecurityKit`
- `Tests/MobileSecurityKitTests`
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `Makefile`

## Quick start

```bash
swift build
swift test
make xcframework
make audit
```

## Public API

```swift
import MobileSecurityKit

let report = SecurityAudit.audit()

switch report.decision {
case .allow:
    print("Environment looks clean")
case .review, .block:
    for finding in report.threats {
        print("\(finding.type): \(finding.detail)")
    }
}
```

You can also call `SecurityDetector.run(_:)` directly if you want only a subset of checks and apply your own policy instead of using `report.decision`.

## Info.plist notes

If you keep the URL-scheme-based jailbreak check enabled, add the schemes you want to query under `LSApplicationQueriesSchemes`, for example:

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
  <string>cydia</string>
  <string>sileo</string>
  <string>zbra</string>
  <string>filza</string>
  <string>activator</string>
</array>
```

Without that allowlist, `canOpenURL` checks will be incomplete on modern iOS.

## What the audit checks

The XCFramework audit currently inspects:

- DWARF debug info presence
- stack canary references
- PIE / ASLR-related flags
- code signing state
- exported symbol surface
- unexpected undefined symbols
- Objective-C metadata exposure
- bitcode presence

These checks are intentionally simple and shell-based so they are easy to adapt inside CI.

## Limitations

- These checks are heuristic and bypassable.
- A clean report does not prove a trusted device.
- A flagged report does not automatically mean malicious behavior.
- Local checks should be treated as signals and combined with app-side or server-side context.
- Some detections depend on platform behavior that can change across iOS versions.

## Intended use

Use this as a starter if you want to:

- prototype passive mobile security checks in public
- ship a binary with a repeatable audit step
- extend the detector set with your own organization-specific logic

Do not treat the built-in checks as a complete security solution. They are examples and scaffolding.

## Future phases

Phase 1 in this repo:

- stronger public documentation
- explicit limitations and setup notes
- simple policy layer on top of raw findings

Future improvements:

- confidence / severity on each finding
- richer integrity and tamper checks
- example app integration
- machine-readable audit output
- clearer separation between detector modules and policy modules
