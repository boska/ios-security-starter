import Darwin
import Foundation

/// Detects whether a debugger is currently attached to the process.
enum DebuggerDetector {

    /// Checks the kernel process info flags for the `P_TRACED` bit.
    /// This is the most reliable on-device check and works on both iOS and macOS.
    static func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride

        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return false }

        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    /// Tries to open `/dev/mem`. On a stock device this will fail with `EACCES`.
    /// On a jailbroken or debugger-accessible environment it may succeed.
    static func isDevMemAccessible() -> Bool {
        let fd = open("/dev/mem", O_RDONLY)
        if fd >= 0 {
            close(fd)
            return true
        }
        return false
    }

    /// Returns `true` if any debugger-related signal handlers look overridden.
    /// Specifically checks whether SIGTRAP is being caught (debuggers set this).
    static func isSIGTRAPHandled() -> Bool {
        var action = sigaction()
        sigaction(SIGTRAP, nil, &action)
        // If sa_handler is not SIG_DFL (0) or SIG_IGN (1), something installed a handler
        let handler = unsafeBitCast(action.__sigaction_u.__sa_handler, to: Int.self)
        return handler > 1
    }

    static func runAll() -> [SecurityCheckResult] {
        [
            SecurityCheckResult(
                type: .debuggerAttached,
                isCompromised: isDebuggerAttached(),
                detail: "P_TRACED kernel flag check"
            ),
            SecurityCheckResult(
                type: .debuggerAttached,
                isCompromised: isDevMemAccessible(),
                detail: "/dev/mem accessibility check"
            ),
            SecurityCheckResult(
                type: .debuggerAttached,
                isCompromised: isSIGTRAPHandled(),
                detail: "SIGTRAP signal handler check"
            ),
        ]
    }
}
