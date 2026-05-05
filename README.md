# iOS Security Starter

An iOS starter project for teams that want two things from day one:

- a small passive security-check module for debugger, hook, and jailbreak signals
- a CI pipeline that builds an XCFramework and audits the produced binary

This is intentionally not a full RASP product. It is a compact starting point for teams that want a reusable Swift package plus a binary-audit workflow they can extend.

## What is included

- `MobileSecurityKit` Swift package
- passive checks for debugger, suspicious injected dylibs / Frida port, and jailbreak indicators
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

if SecurityAudit.isTrusted {
    print("Environment looks clean")
} else {
    for finding in report.threats {
        print("\(finding.type): \(finding.detail)")
    }
}
```

You can also call `SecurityDetector.run(_:)` directly if you want only a subset of checks.

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

## Intended use

Use this as a starter if you want to:

- prototype passive mobile security checks in public
- ship a binary with a repeatable audit step
- extend the detector set with your own organization-specific logic

Do not treat the built-in checks as a complete security solution. They are examples and scaffolding.
