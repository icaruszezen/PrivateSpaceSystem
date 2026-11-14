import PrivateSpaceKit
import SwiftUI
import UIKit
import UniformTypeIdentifiers

// MARK: - Editorial Warm Paper & Mineral Pine Design System (Zero Purple)

public enum MineralPineTheme {
    public static let accent = Color(red: 0.149, green: 0.392, blue: 0.329) // #266454 Mineral Pine
    public static let accentBright = Color(red: 0.298, green: 0.725, blue: 0.592) // Dark mode jade
    public static let amber = Color(red: 0.745, green: 0.435, blue: 0.102)
    public static let danger = Color(red: 0.761, green: 0.212, blue: 0.176)

    public static func primaryAccent(for scheme: ColorScheme) -> Color {
        scheme == .dark ? accentBright : accent
    }

    public static func pageBackground(for scheme: ColorScheme) -> Color {
        scheme == .dark
            ? Color(red: 0.078, green: 0.094, blue: 0.098)
            : Color(red: 0.969, green: 0.965, blue: 0.953)
    }

    public static func cardBackground(for scheme: ColorScheme) -> Color {
        scheme == .dark
            ? Color(red: 0.125, green: 0.145, blue: 0.153)
            : Color.white
    }

    public static func subtleFill(for scheme: ColorScheme) -> Color {
        scheme == .dark
            ? Color(red: 0.168, green: 0.192, blue: 0.200)
            : Color(red: 0.933, green: 0.925, blue: 0.906)
    }

    public static func borderColor(for scheme: ColorScheme) -> Color {
        scheme == .dark
            ? Color.white.opacity(0.10)
            : Color.black.opacity(0.08)
    }
}

public enum VaultFormatters {
    public static func formatBytes(_ bytes: Int) -> String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useBytes, .useKB, .useMB, .useGB]
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(max(0, bytes)))
    }

    public static func formatDuration(_ durationMs: Double?) -> String {
        guard let ms = durationMs, ms > 0 else { return "0:00" }
        let totalSec = Int((ms / 1000.0).rounded())
        let hrs = totalSec / 3600
        let mins = (totalSec % 3600) / 60
        let secs = totalSec % 60
        if hrs > 0 {
            return String(format: "%d:%02d:%02d", hrs, mins, secs)
        }
        return String(format: "%d:%02d", mins, secs)
    }

    public static func shortDate(_ isoString: String) -> String {
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let fallback = ISO8601DateFormatter()
        guard let date = iso.date(from: isoString) ?? fallback.date(from: isoString) else {
            return String(isoString.prefix(10))
        }
        let rel = RelativeDateTimeFormatter()
        rel.locale = Locale(identifier: "zh-Hans")
        rel.unitsStyle = .abbreviated
        return rel.localizedString(for: date, relativeTo: Date())
    }
}

/// Native iOS Haptic Feedback & Local-Only Auto-Expiring Clipboard Helper.
@MainActor
public enum IOSPlatformActions {
    public static func impactLight() {
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
    }

    public static func notifySuccess() {
        UINotificationFeedbackGenerator().notificationOccurred(.success)
    }

    /// Copies sensitive text (`password` / `TOTP`) to `UIPasteboard` restricted to local device
    /// (blocks Universal Clipboard Handoff leak) and auto-expires after `expireSeconds`.
    public static func copySecret(_ value: String, expireSeconds: Int = 30) {
        guard !value.isEmpty else { return }
        if expireSeconds > 0 {
            UIPasteboard.general.setItems(
                [[UTType.plainText.identifier: value]],
                options: [
                    .localOnly: true,
                    .expirationDate: Date().addingTimeInterval(TimeInterval(expireSeconds)),
                ]
            )
        } else {
            UIPasteboard.general.setItems(
                [[UTType.plainText.identifier: value]],
                options: [.localOnly: true]
            )
        }
        notifySuccess()
    }
}

/// Decrypted thumbnail/image view backed by `PrivateSpaceAPIClient` (`Authorization: Bearer`) + RAM cache.
public struct AuthenticatedMediaImageView: View {
    public let mediaId: String
    public let revision: Int
    public let fullResolution: Bool
    public let apiClient: PrivateSpaceAPIClient
    public var contentMode: ContentMode = .fill

    @State private var uiImage: UIImage?
    @State private var failed = false

    public init(
        mediaId: String,
        revision: Int = 1,
        fullResolution: Bool = false,
        apiClient: PrivateSpaceAPIClient,
        contentMode: ContentMode = .fill
    ) {
        self.mediaId = mediaId
        self.revision = revision
        self.fullResolution = fullResolution
        self.apiClient = apiClient
        self.contentMode = contentMode
    }

    public var body: some View {
        ZStack {
            if let uiImage {
                Image(uiImage: uiImage)
                    .resizable()
                    .aspectRatio(contentMode: contentMode)
            } else if failed {
                VStack(spacing: 6) {
                    Image(systemName: "lock.rectangle.on.rectangle")
                        .font(.system(size: 20, weight: .medium))
                        .foregroundStyle(.secondary)
                    Text("密文封面")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            } else {
                ProgressView()
                    .controlSize(.small)
            }
        }
        .task(id: "\(mediaId)-\(revision)-\(fullResolution)") {
            failed = false
            do {
                let rawData = fullResolution
                    ? try await apiClient.fetchFullMediaData(mediaId: mediaId, revision: revision)
                    : try await apiClient.fetchThumbnailData(mediaId: mediaId, revision: revision)
                if let decoded = UIImage(data: rawData) {
                    self.uiImage = decoded
                } else {
                    self.failed = true
                }
            } catch {
                self.failed = true
            }
        }
    }
}
