import Testing
@testable import MobileSecurityKit

@Suite("SecurityDetector")
struct SecurityDetectorTests {

    // MARK: - Report structure

    @Test("runAll returns expected finding count")
    func runAllFindingCount() {
        let report = SecurityDetector.runAll()
        // 3 debugger + 3 hooking + 4 jailbreak = 10
        #expect(report.findings.count == 10)
    }

    @Test("isTrusted convenience matches report value")
    func isTrustedConvenienceMatchesReport() {
        #expect(SecurityDetector.isTrusted == SecurityDetector.runAll().isTrusted)
    }

    // MARK: - findings(for:) filtering

    @Test("findings(for:) returns only matching type", arguments: SecurityCheckType.allCases)
    func findingsFilteredByType(_ type: SecurityCheckType) {
        let findings = SecurityDetector.runAll().findings(for: type)
        #expect(!findings.isEmpty)
        #expect(findings.allSatisfy { $0.type == type })
    }

    // MARK: - Targeted run

    @Test("run(_:) with single type produces only matching findings", arguments: SecurityCheckType.allCases)
    func runSingleTypeProducesMatchingFindings(_ type: SecurityCheckType) {
        let report = SecurityDetector.run([type])
        #expect(report.findings.allSatisfy { $0.type == type })
    }

    @Test("run(_:) with empty set produces no findings")
    func runEmptySetProducesNoFindings() {
        let report = SecurityDetector.run([])
        #expect(report.findings.isEmpty)
        #expect(report.isTrusted)
    }

    @Test("run(_:) with all types matches runAll count")
    func runAllTypesMatchesRunAll() {
        let targeted = SecurityDetector.run(Set(SecurityCheckType.allCases))
        let full = SecurityDetector.runAll()
        #expect(targeted.findings.count == full.findings.count)
    }

    // MARK: - Report isTrusted logic

    @Test("isTrusted is false when any finding is compromised")
    func isTrustedFalseWhenCompromised() {
        let report = SecurityDetector.Report(findings: [
            SecurityCheckResult(type: .debuggerAttached, isCompromised: false, detail: "ok"),
            SecurityCheckResult(type: .hookingDetected,  isCompromised: true,  detail: "flagged"),
        ])
        #expect(!report.isTrusted)
    }

    @Test("isTrusted is true when all findings are clean")
    func isTrustedTrueWhenAllClean() {
        let report = SecurityDetector.Report(findings: [
            SecurityCheckResult(type: .debuggerAttached,  isCompromised: false, detail: "ok"),
            SecurityCheckResult(type: .hookingDetected,   isCompromised: false, detail: "ok"),
            SecurityCheckResult(type: .jailbreakDetected, isCompromised: false, detail: "ok"),
        ])
        #expect(report.isTrusted)
    }

    @Test("threats contains only compromised findings")
    func threatsContainsOnlyCompromised() {
        let report = SecurityDetector.Report(findings: [
            SecurityCheckResult(type: .debuggerAttached,  isCompromised: true,  detail: "bad"),
            SecurityCheckResult(type: .hookingDetected,   isCompromised: false, detail: "ok"),
            SecurityCheckResult(type: .jailbreakDetected, isCompromised: true,  detail: "bad"),
        ])
        #expect(report.threats.count == 2)
        #expect(report.threats.allSatisfy { $0.isCompromised })
    }

    @Test("report exposes compromised types and threat count")
    func reportExposesThreatSummary() {
        let report = SecurityDetector.Report(findings: [
            SecurityCheckResult(type: .debuggerAttached, isCompromised: true, detail: "bad"),
            SecurityCheckResult(type: .debuggerAttached, isCompromised: true, detail: "bad-2"),
            SecurityCheckResult(type: .jailbreakDetected, isCompromised: false, detail: "ok"),
        ])
        #expect(report.threatCount == 2)
        #expect(report.compromisedTypes == [.debuggerAttached])
        #expect(report.containsThreat(.debuggerAttached))
        #expect(!report.containsThreat(.hookingDetected))
    }

    @Test("default policy blocks debugger and hooking findings")
    func defaultPolicyBlocksStrongSignals() {
        let report = SecurityDetector.Report(findings: [
            SecurityCheckResult(type: .hookingDetected, isCompromised: true, detail: "hook"),
        ])
        #expect(report.decision == .block)
    }

    @Test("default policy marks jailbreak-only findings for review")
    func defaultPolicyReviewsJailbreakOnlySignals() {
        let report = SecurityDetector.Report(findings: [
            SecurityCheckResult(type: .jailbreakDetected, isCompromised: true, detail: "jb"),
        ])
        #expect(report.decision == .review)
    }

    @Test("default policy allows clean reports")
    func defaultPolicyAllowsCleanReports() {
        let report = SecurityDetector.Report(findings: [
            SecurityCheckResult(type: .debuggerAttached, isCompromised: false, detail: "ok"),
        ])
        #expect(report.decision == .allow)
    }

    // MARK: - SecurityCheckResult

    @Test("SecurityCheckResult stores values correctly")
    func checkResultStoresValues() {
        let result = SecurityCheckResult(
            type: .hookingDetected,
            isCompromised: true,
            detail: "frida port open"
        )
        #expect(result.type == .hookingDetected)
        #expect(result.isCompromised)
        #expect(result.detail == "frida port open")
    }

    // MARK: - SecurityCheckType

    @Test("SecurityCheckType has three cases")
    func allCasesCount() {
        #expect(SecurityCheckType.allCases.count == 3)
    }

    @Test("SecurityCheckType raw values are stable")
    func rawValuesAreStable() {
        #expect(SecurityCheckType.debuggerAttached.rawValue  == "debuggerAttached")
        #expect(SecurityCheckType.hookingDetected.rawValue   == "hookingDetected")
        #expect(SecurityCheckType.jailbreakDetected.rawValue == "jailbreakDetected")
    }
}
