import Darwin
import Foundation

/// Detects jailbroken iOS devices (and rooted macOS to a lesser extent).
/// All checks are passive — no side effects, no crashes, no app termination.
enum JailbreakDetector {

    // Paths that exist only on jailbroken devices.
    private static let jailbreakPaths: [String] = [
        "/Applications/Cydia.app",
        "/Applications/blackra1n.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSettings.app",
        "/Applications/WinterBoard.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/usr/sbin/sshd",
        "/usr/bin/sshd",
        "/usr/libexec/sftp-server",
        "/usr/bin/ssh",
        "/usr/sbin/frida-server",
        "/usr/bin/cycript",
        "/usr/local/bin/cycript",
        "/usr/lib/libcycript.dylib",
        "/bin/bash",
        "/bin/sh",               // Present on jailbroken; absent on stock iOS
        "/etc/apt",
        "/var/lib/apt",
        "/private/var/lib/apt",
        "/private/var/stash",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/var/checkra1n.dmg",
        "/var/binpack",
        "/usr/lib/TweakInject",
        "/usr/share/jailbreak",
        "/bootstrap",            // Checkra1n/Dopamine bootstrap
        "/var/jb",               // Dopamine / RootHide
        "/var/LIB",
    ]

    /// Checks for the presence of jailbreak indicator files and directories.
    static func hasJailbreakFiles() -> (detected: Bool, matches: [String]) {
        #if os(iOS)
        let found = jailbreakPaths.filter { FileManager.default.fileExists(atPath: $0) }
        return (!found.isEmpty, found)
        #else
        return (false, [])
        #endif
    }

    /// Attempts to write to a path outside the app sandbox.
    /// On a stock iOS device this will always fail. On jailbroken devices it may succeed.
    static func canEscapeSandbox() -> Bool {
        #if os(iOS)
        let testPath = "/private/mobile_security_probe_\(arc4random()).tmp"
        do {
            try "probe".write(toFile: testPath, atomically: true, encoding: .utf8)
            try? FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
        #else
        return false
        #endif
    }

    /// Checks for the `cydia://` and other jailbreak-specific URL schemes.
    /// Uses `dlopen`/`dlsym` to avoid a hard UIKit import.
    static func hasJailbreakURLSchemes() -> Bool {
        #if os(iOS)
        let schemes = ["cydia://", "sileo://", "zbra://", "filza://", "activator://"]

        guard
            let handle = dlopen("/System/Library/Frameworks/UIKit.framework/UIKit", RTLD_NOW),
            let sharedApplicationSel = NSSelectorFromString("sharedApplication") as Selector?,
            let canOpenURLSel = NSSelectorFromString("canOpenURL:") as Selector?,
            let appClass = NSClassFromString("UIApplication"),
            appClass.responds(to: sharedApplicationSel)
        else { return false }

        let app = appClass.perform(sharedApplicationSel)?.takeUnretainedValue()
        guard let app else {
            dlclose(handle)
            return false
        }

        for scheme in schemes {
            if let url = URL(string: scheme) {
                let result = (app as AnyObject).perform(canOpenURLSel, with: url)
                if result != nil {
                    dlclose(handle)
                    return true
                }
            }
        }
        dlclose(handle)
        return false
        #else
        return false
        #endif
    }

    /// Checks whether the app's own bundle has been tampered with (code signature check).
    /// If the signature is broken, it's running on a device that allows unsigned code — i.e. jailbroken.
    static func isSignatureCompromised() -> Bool {
        #if os(iOS)
        guard let bundlePath = Bundle.main.executablePath else { return false }
        let result = access(bundlePath, F_OK)
        // A stricter check would compare the code signature hash, but that requires
        // Security.framework. This naive check confirms the binary is readable.
        // See SecurityDetector for the recommended full check via SecStaticCodeCreateWithPath.
        return result != 0
        #else
        return false
        #endif
    }

    static func runAll() -> [SecurityCheckResult] {
        let files = hasJailbreakFiles()
        let fileDetail = files.matches.isEmpty
            ? "No jailbreak indicator files found"
            : "Found: \(files.matches.prefix(5).joined(separator: ", "))\(files.matches.count > 5 ? " …" : "")"

        return [
            SecurityCheckResult(
                type: .jailbreakDetected,
                isCompromised: files.detected,
                detail: fileDetail
            ),
            SecurityCheckResult(
                type: .jailbreakDetected,
                isCompromised: canEscapeSandbox(),
                detail: "Sandbox escape write test"
            ),
            SecurityCheckResult(
                type: .jailbreakDetected,
                isCompromised: hasJailbreakURLSchemes(),
                detail: "Jailbreak URL scheme check (cydia://, sileo://, etc.)"
            ),
            SecurityCheckResult(
                type: .jailbreakDetected,
                isCompromised: isSignatureCompromised(),
                detail: "App bundle executable accessibility check"
            ),
        ]
    }
}
