import PrivateSpaceKit
import SwiftUI

@main
struct PrivateSpaceIOSApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @State private var store = VaultStore()

    private var preferredScheme: ColorScheme? {
        switch store.themePreference {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }

    var body: some Scene {
        WindowGroup {
            RootContainerView(store: store)
                .preferredColorScheme(preferredScheme)
                .tint(MineralPineTheme.accent)
                .task {
                    await store.bootstrap()
                }
                .onChange(of: scenePhase) { _, newPhase in
                    Task {
                        await store.handleScenePhaseTransition(isActive: newPhase == .active)
                    }
                }
        }
    }
}

struct RootContainerView: View {
    @Bindable var store: VaultStore
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        ZStack(alignment: .top) {
            MineralPineTheme.pageBackground(for: colorScheme)
                .ignoresSafeArea()

            Group {
                switch store.phase {
                case .launching:
                    VStack(spacing: 16) {
                        ProgressView()
                            .controlSize(.large)
                        Text("正在握手加密私密空间...")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                case .serverSetup, .passwordLocked, .biometricLocked:
                    ServerConnectAndAuthView(store: store)
                case .unlocked:
                    MainTabShellView(store: store)
                }
            }

            // Toast Notification Banner
            if let toast = store.statusBanner {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                    Text(toast)
                        .font(.footnote.weight(.semibold))
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(.ultraThinMaterial, in: Capsule())
                .overlay(
                    Capsule()
                        .strokeBorder(MineralPineTheme.borderColor(for: colorScheme), lineWidth: 1)
                )
                .shadow(color: .black.opacity(0.12), radius: 12, y: 4)
                .padding(.top, 8)
                .transition(.move(edge: .top).combined(with: .opacity))
            }

            // iOS App Switcher Privacy Blur Shield (prevents sensitive snapshot leaks)
            if store.isPrivacyShieldVisible {
                PrivacyShieldOverlayView(vaultName: store.vaultName)
                    .transition(.opacity)
            }
        }
        .animation(.spring(response: 0.28, dampingFraction: 0.86), value: store.statusBanner)
        .animation(.easeInOut(duration: 0.18), value: store.isPrivacyShieldVisible)
    }
}

struct PrivacyShieldOverlayView: View {
    let vaultName: String

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.regularMaterial)
                .ignoresSafeArea()

            VStack(spacing: 14) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 46, weight: .semibold))
                    .foregroundStyle(MineralPineTheme.accent)
                Text(vaultName)
                    .font(.title3.weight(.bold))
                Text("AES-256-GCM 隐私防窥护盾已激活")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
