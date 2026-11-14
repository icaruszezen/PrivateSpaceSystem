import PrivateSpaceKit
import SwiftUI

struct ServerConnectAndAuthView: View {
    @Bindable var store: VaultStore
    @Environment(\.colorScheme) private var colorScheme

    @State private var serverInput: String = ""
    @State private var masterPassword: String = ""
    @State private var confirmPassword: String = ""
    @State private var setupVaultName: String = "PrivateSpace"
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

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Brand Security Header
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 8) {
                        Image(systemName: "lock.shield.fill")
                            .font(.subheadline.weight(.bold))
                        Text("AES-256-GCM · 信封加密 · 静态零明文")
                            .font(.caption.weight(.semibold))
                    }
                    .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(
                        MineralPineTheme.primaryAccent(for: colorScheme).opacity(0.12),
                        in: Capsule()
                    )

                    Text(isSetupMode ? "初始化自部署私密空间" : store.vaultName)
                        .font(.system(size: 28, weight: .bold, design: .default))

                    Text(
                        isSetupMode
                            ? "当前服务器尚未创建管理员密钥信封，设置唯一主密码即可生成 256 位空间主密钥 (DEK)。"
                            : "唯一管理员认证解锁 · 支持笔记、密码 (TOTP)、PSENC001 相册与流式影院多端同步。"
                    )
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                    if let fp = store.keyFingerprint {
                        HStack(spacing: 6) {
                            Image(systemName: "key.horizontal.fill")
                                .font(.caption2)
                            Text("DEK 指纹 \(fp)")
                                .font(.system(.caption2, design: .monospaced))
                        }
                        .foregroundStyle(.secondary)
                    }
                }
                .padding(.top, 24)

                // Server Node Card
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Label("自部署空间节点", systemImage: "server.rack")
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
                        TextField("https://vault.yourdomain.com", text: $serverInput)
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

                        Text("轻触使用 \(store.biometricCapability.displayName) 解锁")
                            .font(.headline)

                        Text("本地离线快照由 iOS Keychain 硬件级 AES-256-GCM 密钥保护")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)

                        Button {
                            Task { await store.unlockWithBiometrics() }
                        } label: {
                            HStack {
                                Image(systemName: store.biometricCapability.systemImage)
                                Text("通过 \(store.biometricCapability.displayName) 立即解锁")
                                    .fontWeight(.semibold)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(MineralPineTheme.primaryAccent(for: colorScheme))

                        Button("改用管理员主密码验证") {
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
                                Text("空间显示名称")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                TextField("PrivateSpace", text: $setupVaultName)
                                    .padding(12)
                                    .background(MineralPineTheme.subtleFill(for: colorScheme), in: RoundedRectangle(cornerRadius: 10))
                            }
                        }

                        VStack(alignment: .leading, spacing: 6) {
                            Text("唯一管理员主密码")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                            SecureField("输入至少 8 位高强度主密码", text: $masterPassword)
                                .textContentType(.password)
                                .padding(12)
                                .background(MineralPineTheme.subtleFill(for: colorScheme), in: RoundedRectangle(cornerRadius: 10))
                        }

                        if isSetupMode {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("确认管理员主密码")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.secondary)
                                SecureField("再次输入主密码防止误输", text: $confirmPassword)
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
                                    Image(systemName: isSetupMode ? "sparkles" : "lock.open.fill")
                                }
                                Text(isSetupMode ? "生成主密钥并初始化空间" : "解密信封并同步空间")
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

                // Cryptographic Spec Footer
                VStack(alignment: .leading, spacing: 6) {
                    Label("scrypt (N=32768) 口令派生 + HKDF-SHA256 逐记录子密钥", systemImage: "cpu")
                    Label("PSENC001 64 KiB 分块认证加密原图与 HTTP 206 流式视频", systemImage: "film.stack")
                    Label("iOS Keychain 硬件保护 + 系统级 Safari / App 自动填充扩展", systemImage: "key.viewfinder")
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
