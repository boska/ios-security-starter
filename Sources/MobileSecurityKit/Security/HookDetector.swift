import Darwin
import Foundation

/// Detects runtime hooking frameworks (Frida, Substrate, Substitute, etc.).
enum HookDetector {

    // Known dylib substrings injected by hooking frameworks.
    private static let suspiciousDylibPatterns: [String] = [
        "frida",
        "fridagadget",
        "cynject",
        "libcycript",
        "mobilesubstrate",
        "substrate",
        "substitute",
        "libhooker",
        "tweak",
        "tweetinject",
        "electra",
        "unc0ver",
        "checkra1n",
        "sslkillswitch",
        "a-bypass",
        "shadowsocks",
        "revealserver",           // Reveal app (runtime UI inspector)
        "libsparkcolors",
        "applistmanager",
    ]

    /// Scans all loaded dynamic libraries for known hooking framework names.
    static func hasSuspiciousDylibs() -> (detected: Bool, matches: [String]) {
        var matches: [String] = []
        let count = _dyld_image_count()

        for i in 0..<count {
            guard let rawName = _dyld_get_image_name(i) else { continue }
            let name = String(cString: rawName).lowercased()

            for pattern in suspiciousDylibPatterns where name.contains(pattern) {
                matches.append(String(cString: rawName))
                break
            }
        }

        return (!matches.isEmpty, matches)
    }

    /// Checks whether `DYLD_INSERT_LIBRARIES` is set, which is the primary
    /// mechanism for injecting hooking dylibs at launch.
    static func isDYLDInjectionPresent() -> Bool {
        guard let value = getenv("DYLD_INSERT_LIBRARIES") else { return false }
        return strlen(value) > 0
    }

    /// Checks for the Frida server's default TCP port (27042) being open on localhost.
    /// Frida gadget and frida-server both listen on this port by default.
    static func isFridaPortOpen() -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(27042).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        // Non-blocking connect attempt
        let flags = fcntl(sock, F_GETFL, 0)
        _ = fcntl(sock, F_SETFL, flags | O_NONBLOCK)

        let connectResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if connectResult == 0 { return true }

        // Wait briefly for connection
        var writeSet = fd_set()
        var errorSet = fd_set()
        __darwin_fd_set(sock, &writeSet)
        __darwin_fd_set(sock, &errorSet)
        var timeout = timeval(tv_sec: 0, tv_usec: 50_000) // 50 ms

        let selected = select(sock + 1, nil, &writeSet, &errorSet, &timeout)
        if selected > 0 {
            var error: Int32 = 0
            var errorLen = socklen_t(MemoryLayout<Int32>.size)
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &errorLen)
            return error == 0
        }

        return false
    }

    static func runAll() -> [SecurityCheckResult] {
        let dylibs = hasSuspiciousDylibs()
        let detail = dylibs.matches.isEmpty
            ? "No suspicious dylibs found"
            : "Found: \(dylibs.matches.joined(separator: ", "))"

        return [
            SecurityCheckResult(
                type: .hookingDetected,
                isCompromised: dylibs.detected,
                detail: detail
            ),
            SecurityCheckResult(
                type: .hookingDetected,
                isCompromised: isDYLDInjectionPresent(),
                detail: "DYLD_INSERT_LIBRARIES environment variable check"
            ),
            SecurityCheckResult(
                type: .hookingDetected,
                isCompromised: isFridaPortOpen(),
                detail: "Frida server port 27042 check"
            ),
        ]
    }
}
