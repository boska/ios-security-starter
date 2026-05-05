import Foundation

public enum SecurityAudit {
    public static func audit() -> SecurityDetector.Report {
        SecurityDetector.runAll()
    }

    public static var isTrusted: Bool {
        SecurityDetector.isTrusted
    }
}
