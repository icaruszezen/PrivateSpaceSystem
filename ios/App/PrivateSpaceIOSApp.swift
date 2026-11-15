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
                if store.isDisguiseCoverActive {
                    PSSSystemUtilityCoverView(store: store)
                } else {
                    switch store.phase {
                    case .launching:
                        VStack(spacing: 16) {
                            ProgressView()
                                .controlSize(.large)
                            Text("正在连接 PSS 服务节点...")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                    case .serverSetup, .passwordLocked, .biometricLocked:
                        ServerConnectAndAuthView(store: store)
                    case .unlocked:
                        MainTabShellView(store: store)
                    }
                }
            }

            // Toast Notification Banner
            if let toast = store.statusBanner {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill")
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

            // iOS App Switcher Neutral Suspension Shield
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

    private var displayTitle: String {
        (vaultName.isEmpty || vaultName == "PrivateSpace") ? "PSS" : vaultName
    }

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.regularMaterial)
                .ignoresSafeArea()

            VStack(spacing: 14) {
                Image(systemName: "cpu")
                    .font(.system(size: 42, weight: .semibold))
                    .foregroundStyle(MineralPineTheme.accent)
                Text(displayTitle)
                    .font(.title3.weight(.bold))
                Text("Personal System Service · 会话已挂起")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
