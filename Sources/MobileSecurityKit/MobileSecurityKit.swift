import Foundation

public enum MobileSecurityKit {
    public static func audit() -> SecurityDetector.Report {
        SecurityDetector.runAll()
    }

    public static var isTrusted: Bool {
        SecurityDetector.isTrusted
    }
}
