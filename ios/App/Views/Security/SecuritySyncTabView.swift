import PrivateSpaceKit
import SwiftUI

struct SecuritySyncTabView: View {
    @Bindable var store: VaultStore
    let onInspectCipher: (String) -> Void
    @Environment(\.colorScheme) private var colorScheme

    @State private var showingPasswordRotation = false
    @State private var showingRenameAlert = false
    @State private var renamedVault = ""
    @State private var repoDraft = ""

    var body: some View {
        NavigationStack {
            List {
                // 1. Multi-Device Incremental Sync & SSE Status
                Section("多端实时增量同步 (Web / iOS / Android)") {
                    HStack {
                        Label(
                            store.sseConnected ? "SSE 实时游标流已连接" : (store.isOfflineMode ? "离线加密缓存模式" : "轮询就绪"),
                            systemImage: store.sseConnected ? "dot.radiowaves.left.and.right" : "icloud.slash"
                        )
                        .foregroundStyle(
                            store.sseConnected
                                ? MineralPineTheme.primaryAccent(for: colorScheme)
                                : .secondary
                        )
                        Spacer()
                        Text("游标 #\(store.snapshot.lastSyncSeq)")
                            .font(.system(.caption, design: .monospaced).weight(.semibold))
                    }

                    LabeledContent(
                        "本机加密离线缓存 (.pscache)",
                        value: VaultFormatters.formatBytes(store.localStore.encryptedDiskFootprintBytes())
                    )

                    if !store.snapshot.pendingOutbox.isEmpty {
                        LabeledContent("待上行离线变更队列", value: "\(store.snapshot.pendingOutbox.count) 项")
                    }

                    Button {
                        Task {
                            await store.syncDelta()
                            await store.refreshSecurityDashboard()
                            store.showToast("已拉取最新增量游标 #\(store.snapshot.lastSyncSeq)")
                        }
                    } label: {
                        HStack {
                            Label("立即执行增量同步", systemImage: "arrow.triangle.2.circlepath")
                            if store.isSyncing {
                                Spacer()
                                ProgressView()
                            }
                        }
                    }
                }

                // 1.5 Software Version & GitHub Release Auto-Update
                Section("软件版本与 GitHub 自动更新") {
                    LabeledContent("当前 iOS 客户端版本") {
                        Text("v\(store.currentAppVersion) (Build #\(store.currentAppBuild))")
                            .font(.system(.caption, design: .monospaced).weight(.semibold))
                    }

                    if let info = store.latestUpdateInfo, info.hasUpdate {
                        Button {
                            store.isShowingUpdateSheet = true
                        } label: {
                            HStack {
                                Label(
                                    info.mandatory
                                        ? "必选安全升级 v\(info.latestVersion) — 点击立即安装"
                                        : "发现新版本 v\(info.latestVersion) — 查看更新与安装",
                                    systemImage: "arrow.down.app.fill"
                                )
                                .foregroundStyle(
                                    info.mandatory
                                        ? MineralPineTheme.danger
                                        : MineralPineTheme.primaryAccent(for: colorScheme)
                                )
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }

                    Toggle(
                        isOn: Binding(
                            get: { store.autoCheckUpdatesEnabled },
                            set: { store.setAutoCheckUpdatesPreference($0) }
                        )
                    ) {
                        Label("启动与切回前台时自动检查新版本", systemImage: "sparkles")
                    }

                    Picker(
                        "版本发布通道",
                        selection: Binding(
                            get: { store.updateChannel },
                            set: { nextChannel in
                                store.setUpdateChannelPreference(nextChannel)
                                Task { await store.checkForAppUpdates(manual: false) }
                            }
                        )
                    ) {
                        ForEach(UpdateChannel.allCases) { channel in
                            Text(channel.displayName).tag(channel)
                        }
                    }

                    Picker(
                        "GitHub 分发源模式",
                        selection: Binding(
                            get: { store.updateSourceMode },
                            set: { store.setUpdateSourceModePreference($0) }
                        )
                    ) {
                        ForEach(UpdateSourceMode.allCases) { mode in
                            Text(mode.displayName).tag(mode)
                        }
                    }

                    if store.updateSourceMode == .github {
                        HStack {
                            TextField("owner/repo（如 icaruszezen/PrivateSpaceSystem）", text: $repoDraft)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                                .font(.system(.caption, design: .monospaced))
                            Button("保存") {
                                if store.setCustomGithubRepoPreference(repoDraft) {
                                    repoDraft = store.customGithubRepo
                                    store.showToast("已绑定仓库 \(store.customGithubRepo)")
                                    Task { await store.checkForAppUpdates(manual: true) }
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)
                        }
                    } else {
                        LabeledContent("服务端绑定仓库") {
                            Text(
                                store.serverUpdateConfig?.githubRepo
                                    ?? store.latestUpdateInfo?.repository
                                    ?? AppUpdateService.defaultGithubRepo
                            )
                            .font(.system(.caption, design: .monospaced))
                        }
                    }

                    Button {
                        Task { await store.checkForAppUpdates(manual: true) }
                    } label: {
                        HStack {
                            Label("立即检查 GitHub 最新版本", systemImage: "arrow.clockwise.icloud")
                            if store.isCheckingUpdate {
                                Spacer()
                                ProgressView()
                            }
                        }
                    }
                }

                // 2. iOS Hardware Biometrics, AutoFill & Privacy Shield
                Section("iOS 硬件安全、面容解锁与自动填充") {
                    Toggle(
                        isOn: Binding(
                            get: { store.biometricUnlockEnabled },
                            set: { store.setBiometricPreference($0) }
                        )
                    ) {
                        Label(
                            "启用 \(store.biometricCapability.displayName) 快速解锁",
                            systemImage: store.biometricCapability.systemImage
                        )
                    }

                    Picker(
                        "后台自动锁定策略",
                        selection: Binding(
                            get: { store.autoLockTimeout },
                            set: { store.setAutoLockPreference($0) }
                        )
                    ) {
                        ForEach(AutoLockTimeout.allCases) { option in
                            Text(option.label).tag(option)
                        }
                    }

                    Picker(
                        "界面主题外观",
                        selection: Binding(
                            get: { store.themePreference },
                            set: { store.setThemePreference($0) }
                        )
                    ) {
                        ForEach(AppThemePreference.allCases) { pref in
                            Text(pref.rawValue).tag(pref)
                        }
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Label("iOS 系统密码与 2FA 自动填充已就绪", systemImage: "key.viewfinder")
                            .font(.subheadline.weight(.medium))
                        Text("前往「系统设置 → 通用 → 自动填充与密码」勾选 PrivateSpace，即可在 Safari 与任意 App 中一键填充账号密码并自动复制动态口令。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 2)
                }

                // 3. 4-Pillar Cryptographic Storage Summary
                if let summary = store.securitySummary {
                    Section("端到端零知识加密与四维密文存储统计") {
                        LabeledContent("安全架构", value: summary.encryption.architecture ?? "ZERO_KNOWLEDGE_E2EE_V2")
                        LabeledContent("主密钥指纹 (DEK)") {
                            Text(summary.keyFingerprint)
                                .font(.system(.caption, design: .monospaced))
                        }
                        LabeledContent("密码学套件", value: summary.encryption.cipher)
                        LabeledContent("口令派生 (KDF)", value: summary.encryption.passwordKdf)
                        LabeledContent("总加密占用", value: VaultFormatters.formatBytes(summary.totalEncryptedBytes))
                        LabeledContent(
                            "密码保险箱 (\(summary.activePasswords))",
                            value: VaultFormatters.formatBytes(summary.passwordsEncryptedBytes)
                        )
                        LabeledContent(
                            "加密相册 (\(summary.activeImages))",
                            value: VaultFormatters.formatBytes(summary.imagesEncryptedBytes)
                        )
                        LabeledContent(
                            "私密视频 (\(summary.activeVideos))",
                            value: VaultFormatters.formatBytes(summary.videosEncryptedBytes)
                        )
                        LabeledContent(
                            "文本笔记 (\(summary.activeNotes))",
                            value: VaultFormatters.formatBytes(summary.notesEncryptedBytes)
                        )
                    }
                }

                // 4. Multi-Device Active Sessions
                Section("活跃多端授权会话 (\(store.activeSessions.count))") {
                    ForEach(store.activeSessions) { sess in
                        HStack {
                            Image(systemName: iconForPlatform(sess.platform))
                                .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(sess.deviceName)
                                        .font(.subheadline.weight(.medium))
                                    if sess.current {
                                        Text("本机")
                                            .font(.caption2.weight(.bold))
                                            .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 1)
                                            .background(
                                                MineralPineTheme.primaryAccent(for: colorScheme).opacity(0.12),
                                                in: Capsule()
                                            )
                                    }
                                }
                                Text("\(sess.ipAddress) · 活跃于 \(VaultFormatters.shortDate(sess.lastActiveAt))")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            if !sess.current {
                                Button("吊销", role: .destructive) {
                                    Task { await store.revokeDeviceSession(id: sess.id) }
                                }
                                .font(.caption.weight(.semibold))
                                .buttonStyle(.bordered)
                                .controlSize(.small)
                            }
                        }
                    }
                }

                // 5. Vault Administration & Lock
                Section("空间管理与会话锁定") {
                    Button {
                        renamedVault = store.vaultName
                        showingRenameAlert = true
                    } label: {
                        Label("修改空间名称（当前：\(store.vaultName)）", systemImage: "character.cursor.ibeam")
                    }

                    Button {
                        showingPasswordRotation = true
                    } label: {
                        Label("零重写轮换管理员主密码 (KEK Re-Wrap)", systemImage: "key.radiowaves.forward.fill")
                    }

                    if let sampleId = store.snapshot.passwords.keys.first
                        ?? store.snapshot.media.keys.first
                        ?? store.snapshot.notes.keys.first {
                        Button {
                            onInspectCipher(sampleId)
                        } label: {
                            Label("抽检底层 SQLite / PSENC001 原始密文信封", systemImage: "magnifyingglass.circle")
                        }
                    }

                    Button {
                        store.lockSessionLocally()
                    } label: {
                        Label("立即锁定空间（保留面容 ID 会话）", systemImage: "lock.fill")
                    }

                    Button(role: .destructive) {
                        Task { await store.logoutAndWipeDevice() }
                    } label: {
                        Label("注销此 iPhone 并擦除本地 .pscache 密文", systemImage: "rectangle.portrait.and.arrow.right")
                    }
                }
            }
            .navigationTitle("安全与同步")
            .task {
                repoDraft = store.customGithubRepo
                await store.refreshSecurityDashboard()
            }
            .refreshable {
                await store.syncDelta()
                await store.refreshSecurityDashboard()
                await store.checkForAppUpdates(manual: false)
            }
            .sheet(isPresented: $showingPasswordRotation) {
                MasterPasswordRotationSheet(store: store)
            }
            .alert("修改私密空间名称", isPresented: $showingRenameAlert) {
                TextField("空间名称", text: $renamedVault)
                Button("取消", role: .cancel) {}
                Button("保存") {
                    let trimmed = renamedVault.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !trimmed.isEmpty else { return }
                    Task { await store.renameVault(trimmed) }
                }
            }
        }
    }

    private func iconForPlatform(_ platform: DevicePlatform) -> String {
        switch platform {
        case .ios: return "iphone"
        case .android: return "candybarphone"
        case .web: return "laptopcomputer"
        case .api: return "terminal"
        }
    }
}

private struct MasterPasswordRotationSheet: View {
    @Bindable var store: VaultStore
    @Environment(\.dismiss) private var dismiss

    @State private var currentPassword = ""
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var revokeOthers = true

    var body: some View {
        NavigationStack {
            Form {
                Section("验证当前主密码") {
                    SecureField("当前唯一管理员密码", text: $currentPassword)
                }
                Section("设置新管理员主密码（仅重封装 32B DEK，海量媒体零重写）") {
                    SecureField("新主密码（至少 8 位）", text: $newPassword)
                    SecureField("确认新主密码", text: $confirmPassword)
                    Toggle("同时吊销其他所有已登录设备", isOn: $revokeOthers)
                }
            }
            .navigationTitle("轮换主密码")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("执行轮换") {
                        guard newPassword == confirmPassword else {
                            store.errorBanner = "两次输入的新密码不一致"
                            return
                        }
                        Task {
                            let ok = await store.rotateMasterPassword(
                                currentPassword: currentPassword,
                                newPassword: newPassword,
                                revokeOthers: revokeOthers
                            )
                            if ok { dismiss() }
                        }
                    }
                    .disabled(currentPassword.isEmpty || newPassword.count < 8)
                }
            }
        }
    }
}

// MARK: - Universal Cipher Envelope Inspector Sheet

struct CipherInspectorSheet: View {
    let itemId: String
    let apiClient: PrivateSpaceAPIClient
    @Environment(\.dismiss) private var dismiss

    @State private var envelope: CipherEnvelopeInspection?
    @State private var errorText: String?

    var body: some View {
        NavigationStack {
            Group {
                if let env = envelope {
                    List {
                        Section("SQLite AEAD 认证密文信封") {
                            LabeledContent("条目 ID", value: String(env.itemId.prefix(12)) + "…")
                            LabeledContent("资产类型", value: env.itemType.rawValue.uppercased())
                            LabeledContent("版本与同步游标", value: "Rev #\(env.revision) · Seq #\(env.syncSeq)")
                            LabeledContent("对称算法", value: env.algorithm)
                            LabeledContent("HKDF 域隔离上下文", value: env.hkdfContext)
                            VStack(alignment: .leading, spacing: 4) {
                                Text("绑定附加认证数据 (AAD)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Text(env.aadJson)
                                    .font(.system(.caption, design: .monospaced))
                            }
                        }

                        Section("密码学随机数与认证标签 (Hex)") {
                            MonoHexField(label: "128-bit Item Salt", hex: env.saltHex)
                            MonoHexField(label: "96-bit GCM Nonce", hex: env.nonceHex)
                            MonoHexField(label: "128-bit GCM Auth Tag", hex: env.authTagHex)
                            MonoHexField(
                                label: "密文载荷采样 (\(env.ciphertextTotalBytes) B)",
                                hex: env.ciphertextPreviewHex
                            )
                        }

                        if let chunk = env.chunkStore {
                            Section("PSENC001 分块流式媒体容器 (.psenc)") {
                                LabeledContent("容器魔数", value: chunk.formatMagic)
                                LabeledContent("分块规格", value: "\(VaultFormatters.formatBytes(chunk.chunkPlainBytes)) × \(chunk.chunkCount) 块")
                                LabeledContent("磁盘密文大小", value: VaultFormatters.formatBytes(chunk.encryptedDiskBytes))
                                MonoHexField(label: "文件密钥封装上下文 (FEK)", hex: chunk.fekWrapInfo)
                                MonoHexField(label: "明文 SHA-256 完整性摘要", hex: chunk.sha256Hex)
                            }
                        }
                    }
                } else if let errorText {
                    ContentUnavailableView("无法读取密文信封", systemImage: "exclamationmark.shield", description: Text(errorText))
                } else {
                    ProgressView("正在读取服务端原始密文信封...")
                }
            }
            .navigationTitle("底层密文信封透视")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
            }
            .task {
                do {
                    self.envelope = try await apiClient.inspectCipherEnvelope(itemId: itemId)
                } catch {
                    self.errorText = error.localizedDescription
                }
            }
        }
    }
}

private struct MonoHexField: View {
    let label: String
    let hex: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(hex)
                .font(.system(.caption2, design: .monospaced))
                .textSelection(.enabled)
        }
    }
}

// MARK: - iOS Software Auto-Update & GitHub Release Prompt Sheet

struct AppUpdatePromptSheet: View {
    @Bindable var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        NavigationStack {
            if let info = store.latestUpdateInfo {
                let actions = AppUpdateService.resolveInstallActions(from: info)
                List {
                    Section("新版本摘要") {
                        LabeledContent("发布标题", value: info.releaseName)
                        LabeledContent("版本演进") {
                            Text("v\(info.currentVersion) (#\(info.currentBuild)) → v\(info.latestVersion) (#\(info.latestBuild))")
                                .font(.system(.caption, design: .monospaced).weight(.semibold))
                                .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                        }
                        LabeledContent("GitHub 仓库") {
                            Text(info.repository)
                                .font(.system(.caption, design: .monospaced))
                        }
                        LabeledContent("发布通道", value: info.channel.displayName)
                        if info.mandatory {
                            Label("此版本包含关键安全更新，需升级后继续使用", systemImage: "exclamationmark.shield.fill")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(MineralPineTheme.danger)
                        }
                    }

                    Section("更新说明 (Release Notes)") {
                        Text(info.releaseNotes.isEmpty ? "包含端到端加密同步稳定性优化与安全修复。" : info.releaseNotes)
                            .font(.subheadline)
                            .textSelection(.enabled)
                    }

                    if let asset = info.asset {
                        Section("iOS 安装包与 SHA-256 完整性指纹") {
                            LabeledContent("文件名") {
                                Text(asset.fileName)
                                    .font(.system(.caption, design: .monospaced))
                            }
                            if let size = asset.fileSize, size > 0 {
                                LabeledContent("安装包大小", value: VaultFormatters.formatBytes(size))
                            }
                            if let sha = asset.sha256, !sha.isEmpty {
                                MonoHexField(label: "SHA-256 校验摘要", hex: sha)
                                Button {
                                    IOSPlatformActions.copySecret(sha, expireSeconds: 120)
                                    store.showToast("已复制安装包 SHA-256 校验值")
                                } label: {
                                    Label("复制 SHA-256 校验值", systemImage: "doc.on.doc")
                                        .font(.caption.weight(.semibold))
                                }
                            }
                        }
                    }

                    Section("选择安装方式") {
                        ForEach(Array(actions.enumerated()), id: \.offset) { idx, action in
                            Button {
                                openURL(action.url)
                            } label: {
                                HStack(spacing: 12) {
                                    Image(systemName: action.systemImage)
                                        .font(.title3)
                                        .foregroundStyle(
                                            idx == 0
                                                ? MineralPineTheme.primaryAccent(for: colorScheme)
                                                : .secondary
                                        )
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(action.title)
                                            .font(.subheadline.weight(idx == 0 ? .bold : .medium))
                                            .foregroundStyle(.primary)
                                        Text(action.subtitle)
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    Image(systemName: "arrow.up.right")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                .padding(.vertical, 3)
                            }
                        }

                        if !info.mandatory && info.hasUpdate {
                            Button(role: .cancel) {
                                store.skipUpdateVersion(info.latestVersion)
                                dismiss()
                            } label: {
                                Label("忽略 v\(info.latestVersion) 版本提醒", systemImage: "eye.slash")
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                .navigationTitle("发现新版本 v\(info.latestVersion)")
                .navigationBarTitleDisplayMode(.inline)
                .interactiveDismissDisabled(info.mandatory)
                .toolbar {
                    if !info.mandatory {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("稍后") { dismiss() }
                        }
                    }
                }
            } else {
                ContentUnavailableView("暂无可用更新信息", systemImage: "checkmark.seal")
            }
        }
    }
}

