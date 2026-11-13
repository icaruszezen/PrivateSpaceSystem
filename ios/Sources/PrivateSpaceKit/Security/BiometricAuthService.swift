import Foundation
import LocalAuthentication

public enum BiometricCapability: String, Sendable, Equatable {
    case faceID
    case touchID
    case opticID
    case none

    public var displayName: String {
        switch self {
        case .faceID: return "面容 ID (Face ID)"
        case .touchID: return "触控 ID (Touch ID)"
        case .opticID: return "视网膜 ID (Optic ID)"
        case .none: return "设备锁屏密码"
        }
    }

    public var systemImage: String {
        switch self {
        case .faceID: return "faceid"
        case .touchID: return "touchid"
        case .opticID: return "opticid"
        case .none: return "lock.shield"
        }
    }
}

public enum AutoLockTimeout: Int, Codable, Sendable, CaseIterable, Identifiable {
    case immediately = 0
    case oneMinute = 60
    case fiveMinutes = 300
    case fifteenMinutes = 900

    public var id: Int { rawValue }

    public var label: String {
        switch self {
        case .immediately: return "切至后台立即锁定"
        case .oneMinute: return "离开 1 分钟后锁定"
        case .fiveMinutes: return "离开 5 分钟后锁定"
        case .fifteenMinutes: return "离开 15 分钟后锁定"
        }
    }
}

/// Native Apple `LocalAuthentication` biometric unlock coordinator (Face ID / Touch ID / Passcode fallback).
public final class BiometricAuthService: @unchecked Sendable {
    public init() {}

    public func detectCapability() -> BiometricCapability {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .none
        }
        switch context.biometryType {
        case .faceID:
            return .faceID
        case .touchID:
            return .touchID
        case .opticID:
            return .opticID
        case .none:
            return .none
        @unknown default:
            return .none
        }
    }

    public func authenticate(
        reason: String = "验证身份以解锁 PrivateSpace 加密私密空间",
        allowDevicePasscodeFallback: Bool = true
    ) async throws -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "改用管理员主密码"

        let policy: LAPolicy = allowDevicePasscodeFallback
            ? .deviceOwnerAuthentication
            : .deviceOwnerAuthenticationWithBiometrics

        var authError: NSError?
        guard context.canEvaluatePolicy(policy, error: &authError) else {
            if let authError {
                throw authError
            }
            return false
        }

        return try await context.evaluatePolicy(policy, localizedReason: reason)
    }

    public func shouldAutoLock(
        backgroundedAt: Date?,
        now: Date = Date(),
        timeout: AutoLockTimeout
    ) -> Bool {
        guard let backgroundedAt else { return false }
        if timeout == .immediately {
            return true
        }
        return now.timeIntervalSince(backgroundedAt) >= TimeInterval(timeout.rawValue)
    }
}
