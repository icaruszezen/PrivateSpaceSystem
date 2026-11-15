import PrivateSpaceKit
import SwiftUI

struct ServerConnectAndAuthView: View {
    @Bindable var store: VaultStore
    @Environment(\.colorScheme) private var colorScheme

    @State private var serverInput: String = ""
    @State private var masterPassword: String = ""
    @State private var confirmPassword: String = ""
    @State private var setupVaultName: String = "PSS"
    @State private var isSubmitting = false
    @State private var editingServer = false

    private var isSetupMode: Bool {
        if case .serverSetup = store.phase { return true }
        return false
    }

    private var isBiometricPromptMode: Bool {
        if case .biometricLocked = store.phase { return true }
        return false
    }

    private var displayVaultTitle: String {
        (store.vaultName.isEmpty || store.vaultName == "PrivateSpace") ? "PSS" : store.vaultName
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Brand System Header
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        HStack(spacing: 8) {
                            Image(systemName: "cpu")
                                .font(.subheadline.weight(.bold))
                            Text("PSS · Personal System Service")
                                .font(.caption.weight(.semibold))
                        }
                        .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(
                            MineralPineTheme.primaryAccent(for: colorScheme).opacity(0.12),
                            in: Capsule()
                        )

                        Spacer()

                        Button {
                            store.isDisguiseCoverActive = true
                        } label: {
                            Label("工具页", systemImage: "function")
                                .font(.caption.weight(.semibold))
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }

                    Text(isSetupMode ? "初始化 PSS 节点" : displayVaultTitle)
                        .font(.system(size: 28, weight: .bold, design: .default))

                    Text(
                        isSetupMode
                            ? "配置自部署同步节点的主访问口令，建立多端实时增量同步连接。"
                            : "自部署多端数据同步与服务节点会话验证。"
                    )
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                    if let fp = store.keyFingerprint {
                        HStack(spacing: 6) {
                            Image(systemName: "number.square")
                                .font(.caption2)
                            Text("节点指纹 \(fp)")
                                .font(.system(.caption2, design: .monospaced))
                        }
                        .foregroundStyle(.secondary)
                    }
                }
                .padding(.top, 24)

                // Server Node Card
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Label("自部署服务节点", systemImage: "server.rack")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button(editingServer ? "连接探测" : "切换节点") {
                            if editingServer {
                                Task {
                                    await store.connectServer(serverInput)
                                    editingServer = false
                                }
                            } else {
                                serverInput = store.serverURL
                                editingServer = true
                            }
                        }
                        .font(.caption.weight(.semibold))
                    }

                    if editingServer {
                        TextField("https://pss.yourdomain.com", text: $serverInput)
                            .textInputAutocapitalization(.never)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .padding(12)
                            .background(MineralPineTheme.subtleFill(for: colorScheme), in: RoundedRectangle(cornerRadius: 10))
                    } else {
                        Text(store.serverURL)
                            .font(.system(.footnote, design: .monospaced))
                            .foregroundStyle(.primary)
                    }
                }
                .padding(16)
                .background(MineralPineTheme.cardBackground(for: colorScheme), in: RoundedRectangle(cornerRadius: 16))
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .strokeBorder(MineralPineTheme.borderColor(for: colorScheme), lineWidth: 1)
                )

                // Biometric Quick Unlock Card OR Password Form
                if isBiometricPromptMode {
                    VStack(spacing: 16) {
                        Image(systemName: store.biometricCapability.systemImage)
                            .font(.system(size: 44, weight: .regular))
                            .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                            .padding(.top, 8)

                        Text("轻触使用 \(store.biometricCapability.displayName) 验证会话")
                            .font(.headline)

                        Text("本机离线缓存受 iOS Keychain 硬件级密钥保护")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)

                        Button {
                            Task { await store.unlockWithBiometrics() }
                        } label: {
                            HStack {
                                Image(systemName: store.biometricCapability.systemImage)
                                Text("通过 \(store.biometricCapability.displayName) 继续")
                                    .fontWeight(.semibold)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(MineralPineTheme.primaryAccent(for: colorScheme))

                        Button("改用主访问口令验证") {
                            store.phase = .passwordLocked(
                                vaultName: store.vaultName,
                                fingerprint: store.keyFingerprint
                            )
                        }
                        .font(.footnote.weight(.medium))
                        .foregroundStyle(.secondary)
                    }
                    .padding(20)
                    .frame(maxWidth: .infinity)
                    .background(MineralPineTheme.cardBackground(for: colorScheme), in: RoundedRectangle(cornerRadius: 18))
                    .overlay(
                        RoundedRectangle(cornerRadius: 18)
                            .strokeBorder(MineralPineTheme.borderColor(for: colorScheme), lineWidth: 1)
                    )
                    .task {
                        await store.unlockWithBiometrics()
                    }
                } else {
                    VStack(alignment: .leading, spacing: 14) {
                        if isSetupMode {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("节点显示名称")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                TextField("PSS", text: $setupVaultName)
                                    .padding(12)
                                    .background(MineralPineTheme.subtleFill(for: colorScheme), in: RoundedRectangle(cornerRadius: 10))
                            }
                        }

                        VStack(alignment: .leading, spacing: 6) {
                            Text("主访问口令")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                            SecureField("输入至少 8 位访问口令", text: $masterPassword)
                                .textContentType(.password)
                                .padding(12)
                                .background(MineralPineTheme.subtleFill(for: colorScheme), in: RoundedRectangle(cornerRadius: 10))
                        }

                        if isSetupMode {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("确认主访问口令")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                SecureField("再次输入访问口令防止误输", text: $confirmPassword)
                                    .textContentType(.newPassword)
                                    .padding(12)
                                    .background(MineralPineTheme.subtleFill(for: colorScheme), in: RoundedRectangle(cornerRadius: 10))
                            }
                        }

                        if let err = store.errorBanner {
                            HStack(spacing: 8) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                Text(err)
                                    .font(.footnote)
                            }
                            .foregroundStyle(MineralPineTheme.danger)
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(MineralPineTheme.danger.opacity(0.10), in: RoundedRectangle(cornerRadius: 10))
                        }

                        Button {
                            submitForm()
                        } label: {
                            HStack(spacing: 8) {
                                if isSubmitting {
                                    ProgressView()
                                        .tint(.white)
                                } else {
                                    Image(systemName: isSetupMode ? "sparkles" : "arrow.right.circle.fill")
                                }
                                Text(isSetupMode ? "初始化并连接节点" : "验证并连接节点")
                                    .fontWeight(.semibold)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(MineralPineTheme.primaryAccent(for: colorScheme))
                        .disabled(isSubmitting || masterPassword.count < 8)
                    }
                    .padding(18)
                    .background(MineralPineTheme.cardBackground(for: colorScheme), in: RoundedRectangle(cornerRadius: 18))
                    .overlay(
                        RoundedRectangle(cornerRadius: 18)
                            .strokeBorder(MineralPineTheme.borderColor(for: colorScheme), lineWidth: 1)
                    )
                }

                // Spec Footer
                VStack(alignment: .leading, spacing: 6) {
                    Label("PSS Sync Protocol v2 · TLS / AEAD 实时游标同步", systemImage: "cpu")
                    Label("支持系统级 Safari / App 自动填充扩展与离线增量队列", systemImage: "key.viewfinder")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 4)
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 36)
        }
        .onAppear {
            serverInput = store.serverURL
            if case .serverSetup(let defaultName) = store.phase {
                setupVaultName = defaultName
            }
        }
    }

    private func submitForm() {
        if isSetupMode && masterPassword != confirmPassword {
            store.errorBanner = "两次输入的管理员密码不一致"
            return
        }
        isSubmitting = true
        let pwd = masterPassword
        Task {
            if isSetupMode {
                await store.initializeAdminAndUnlock(vaultNameInput: setupVaultName, masterPassword: pwd)
            } else {
                await store.loginWithMasterPassword(pwd)
            }
            masterPassword = ""
            confirmPassword = ""
            isSubmitting = false
        }
    }
}
