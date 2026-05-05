import Foundation

// MARK: - Public Types

/// Categories of security threats the SDK checks for.
public enum SecurityCheckType: String, Sendable, CaseIterable {
    /// A debugger (lldb, gdb, Xcode) is attached to the process.
    case debuggerAttached
    /// A runtime hooking framework (Frida, Substrate, Substitute) is active.
    case hookingDetected
    /// The device is jailbroken (iOS) or has otherwise bypassed platform security.
    case jailbreakDetected
}

/// The result of a single security check.
public struct SecurityCheckResult: Sendable {
    /// Which threat category this result belongs to.
    public let type: SecurityCheckType
    /// `true` when the check found evidence of a threat.
    public let isCompromised: Bool
    /// Human-readable description of what was checked.
    public let detail: String
}

// MARK: - SecurityDetector

/// Runs passive, read-only security checks against the current process and device.
///
/// Usage:
/// ```swift
/// let report = SecurityDetector.runAll()
/// if report.isTrusted {
///     // Proceed with sensitive operations
/// } else {
///     // Handle untrusted environment
///     for finding in report.findings where finding.isCompromised {
///         print("Threat: \(finding.type.rawValue) — \(finding.detail)")
///     }
/// }
/// ```
public struct SecurityDetector: Sendable {

    /// A bundle of all check results from a single `runAll()` invocation.
    public struct Report: Sendable {
        /// Every individual check result (both passed and failed).
        public let findings: [SecurityCheckResult]

        /// `true` when no check reported a compromise.
        public var isTrusted: Bool {
            findings.allSatisfy { !$0.isCompromised }
        }

        /// Subset of findings that indicate an active threat.
        public var threats: [SecurityCheckResult] {
            findings.filter { $0.isCompromised }
        }

        /// Returns findings filtered to a specific threat category.
        public func findings(for type: SecurityCheckType) -> [SecurityCheckResult] {
            findings.filter { $0.type == type }
        }
    }

    // MARK: Public API

    /// Runs all security checks (debugger, hooking, jailbreak) and returns a consolidated report.
    ///
    /// This is a synchronous, blocking call. All checks are passive and have no side effects.
    /// Typical wall-clock time is <10 ms on device; the Frida port probe adds up to 50 ms.
    public static func runAll() -> Report {
        let findings =
            DebuggerDetector.runAll() +
            HookDetector.runAll() +
            JailbreakDetector.runAll()

        return Report(findings: findings)
    }

    /// Convenience property — returns `true` only when the environment is clean across all checks.
    public static var isTrusted: Bool {
        runAll().isTrusted
    }

    /// Runs only the checks in the specified categories.
    public static func run(_ types: Set<SecurityCheckType>) -> Report {
        var findings: [SecurityCheckResult] = []

        if types.contains(.debuggerAttached)  { findings += DebuggerDetector.runAll() }
        if types.contains(.hookingDetected)   { findings += HookDetector.runAll() }
        if types.contains(.jailbreakDetected) { findings += JailbreakDetector.runAll() }

        return Report(findings: findings)
    }
}
