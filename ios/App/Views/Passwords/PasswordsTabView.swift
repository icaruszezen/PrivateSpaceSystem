import PrivateSpaceKit
import SwiftUI

struct PasswordsTabView: View {
    @Bindable var store: VaultStore
    let onInspectCipher: (String) -> Void
    @Environment(\.colorScheme) private var colorScheme

    @State private var searchQuery: String = ""
    @State private var selectedCategory: PasswordCategory?
    @State private var auditFilter: PasswordAuditFilter = .none
    @State private var selectedPassword: PasswordItem?
    @State private var showingEditor = false
    @State private var editingTarget: PasswordItem?
    @State private var showingGenerator = false
    @State private var showingCsvImport = false

    var body: some View {
        NavigationStack {
            let items = store.filteredPasswords(
                query: searchQuery,
                category: selectedCategory,
                auditFilter: auditFilter
            )
            let audit = store.passwordAudit

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    // Vault Security Health Audit Card
                    VaultHealthBannerCard(
                        audit: audit,
                        activeFilter: $auditFilter
                    )

                    // Category Horizontal Filter Bar
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            FilterChipButton(
                                title: "全部类型",
                                icon: "square.grid.2x2",
                                isSelected: selectedCategory == nil && auditFilter != .trash
                            ) {
                                selectedCategory = nil
                                if auditFilter == .trash { auditFilter = .none }
                            }

                            ForEach(PasswordCategory.allCases) { cat in
                                FilterChipButton(
                                    title: cat.displayName,
                                    icon: cat.systemImage,
                                    isSelected: selectedCategory == cat
                                ) {
                                    selectedCategory = (selectedCategory == cat) ? nil : cat
                                }
                            }

                            FilterChipButton(
                                title: "回收站",
                                icon: "trash",
                                isSelected: auditFilter == .trash
                            ) {
                                auditFilter = (auditFilter == .trash) ? .none : .trash
                            }
                        }
                    }

                    // Password Items List
                    if items.isEmpty {
                        ContentUnavailableView(
                            "暂无匹配的加密凭据",
                            systemImage: "key.slash",
                            description: Text("点击右上角 + 创建新账号密码，或通过 CSV 批量导入")
                        )
                        .padding(.vertical, 36)
                    } else {
                        TimelineView(.periodic(from: .now, by: 1.0)) { context in
                            VStack(spacing: 10) {
                                ForEach(items) { item in
                                    PasswordRowCard(
                                        item: item,
                                        now: context.date,
                                        expireSeconds: store.clipboardAutoExpireSeconds,
                                        onTap: { selectedPassword = item },
                                        onCopyToast: { msg in store.showToast(msg) }
                                    )
                                }
                            }
                        }
                    }
                }
                .padding(16)
            }
            .background(MineralPineTheme.pageBackground(for: colorScheme))
            .navigationTitle("密码保险箱")
            .searchable(text: $searchQuery, prompt: "搜索站点、账号、域名或标签")
            .refreshable {
                await store.syncDelta()
            }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Menu {
                        Button {
                            showingGenerator = true
                        } label: {
                            Label("随机密码与助记词生成器", systemImage: "dice.fill")
                        }
                        Button {
                            showingCsvImport = true
                        } label: {
                            Label("CSV 批量加密导入", systemImage: "square.and.arrow.down")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        editingTarget = nil
                        showingEditor = true
                    } label: {
                        Image(systemName: "plus.circle.fill")
                            .font(.title3)
                    }
                }
            }
            .sheet(item: $selectedPassword) { item in
                let liveItem = store.snapshot.passwords[item.id] ?? item
                PasswordDetailSheet(
                    item: liveItem,
                    store: store,
                    onEdit: {
                        selectedPassword = nil
                        editingTarget = liveItem
                        showingEditor = true
                    },
                    onInspectCipher: {
                        let targetId = liveItem.id
                        selectedPassword = nil
                        onInspectCipher(targetId)
                    }
                )
            }
            .sheet(isPresented: $showingEditor) {
                PasswordEditorSheet(store: store, existing: editingTarget)
            }
            .sheet(isPresented: $showingGenerator) {
                PasswordGeneratorSheet(
                    expireSeconds: store.clipboardAutoExpireSeconds,
                    onUsePassword: nil,
                    onCopied: { store.showToast("高熵随机口令已复制（30秒自动清除）") }
                )
            }
            .sheet(isPresented: $showingCsvImport) {
                PasswordCsvImportSheet(store: store)
            }
        }
    }
}

private struct VaultHealthBannerCard: View {
    let audit: VaultPasswordAuditReport
    @Binding var activeFilter: PasswordAuditFilter
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("密码安全健康度")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    HStack(alignment: .firstTextBaseline, spacing: 4) {
                        Text("\(audit.healthScore)")
                            .font(.system(size: 28, weight: .bold, design: .rounded))
                            .foregroundStyle(
                                audit.healthScore >= 85
                                    ? MineralPineTheme.primaryAccent(for: colorScheme)
                                    : MineralPineTheme.amber
                            )
                        Text("/ 100 · 共 \(audit.totalCount) 项有效凭据")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if activeFilter != .none {
                    Button("清除筛选") {
                        activeFilter = .none
                    }
                    .font(.caption.weight(.semibold))
                }
            }

            HStack(spacing: 8) {
                AuditMetricPill(
                    title: "弱口令",
                    count: audit.weakIds.count,
                    active: activeFilter == .weak,
                    tint: MineralPineTheme.danger
                ) {
                    activeFilter = (activeFilter == .weak) ? .none : .weak
                }
                AuditMetricPill(
                    title: "重复密码",
                    count: audit.reusedIds.count,
                    active: activeFilter == .reused,
                    tint: MineralPineTheme.amber
                ) {
                    activeFilter = (activeFilter == .reused) ? .none : .reused
                }
                AuditMetricPill(
                    title: "缺 2FA",
                    count: audit.missingTotpIds.count,
                    active: activeFilter == .missing2FA,
                    tint: MineralPineTheme.primaryAccent(for: colorScheme)
                ) {
                    activeFilter = (activeFilter == .missing2FA) ? .none : .missing2FA
                }
            }
        }
        .padding(14)
        .background(MineralPineTheme.cardBackground(for: colorScheme), in: RoundedRectangle(cornerRadius: 16))
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .strokeBorder(MineralPineTheme.borderColor(for: colorScheme), lineWidth: 1)
        )
    }
}

private struct AuditMetricPill: View {
    let title: String
    let count: Int
    let active: Bool
    let tint: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                Text(title)
                    .font(.caption2.weight(.medium))
                Text("\(count)")
                    .font(.caption.weight(.bold))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 7)
            .background(active ? tint.opacity(0.20) : tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 9))
            .overlay(
                RoundedRectangle(cornerRadius: 9)
                    .strokeBorder(active ? tint : .clear, lineWidth: 1)
            )
            .foregroundStyle(count > 0 ? tint : .secondary)
        }
        .buttonStyle(.plain)
    }
}

struct FilterChipButton: View {
    let title: String
    let icon: String?
    let isSelected: Bool
    let action: () -> Void
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                if let icon {
                    Image(systemName: icon)
                        .font(.caption2)
                }
                Text(title)
                    .font(.caption.weight(.semibold))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background(
                isSelected
                    ? MineralPineTheme.primaryAccent(for: colorScheme)
                    : MineralPineTheme.cardBackground(for: colorScheme),
                in: Capsule()
            )
            .foregroundStyle(isSelected ? Color.white : Color.primary)
            .overlay(
                Capsule()
                    .strokeBorder(
                        isSelected ? .clear : MineralPineTheme.borderColor(for: colorScheme),
                        lineWidth: 1
                    )
            )
        }
        .buttonStyle(.plain)
    }
}

private struct PasswordRowCard: View {
    let item: PasswordItem
    let now: Date
    let expireSeconds: Int
    let onTap: () -> Void
    let onCopyToast: (String) -> Void
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        let totp = item.totpSecret.isEmpty ? nil : (try? TotpGenerator.generateTotp(item.totpSecret, date: now))

        Button(action: onTap) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 12) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 11)
                            .fill(MineralPineTheme.primaryAccent(for: colorScheme).opacity(0.12))
                            .frame(width: 40, height: 40)
                        Image(systemName: item.category.systemImage)
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                    }

                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 5) {
                            Text(item.title)
                                .font(.subheadline.weight(.semibold))
                                .foregroundStyle(.primary)
                                .lineLimit(1)
                            if item.isPinned {
                                Image(systemName: "pin.fill")
                                    .font(.caption2)
                                    .foregroundStyle(MineralPineTheme.amber)
                            }
                        }
                        Text(item.username.isEmpty ? (item.url.isEmpty ? item.category.displayName : item.url) : item.username)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }

                    Spacer()

                    Button {
                        IOSPlatformActions.copySecret(item.password, expireSeconds: expireSeconds)
                        onCopyToast("已复制「\(item.title)」密码（\(expireSeconds)秒自动销毁）")
                    } label: {
                        Image(systemName: "doc.on.doc")
                            .font(.subheadline)
                            .padding(8)
                            .background(MineralPineTheme.subtleFill(for: colorScheme), in: Circle())
                    }
                    .buttonStyle(.plain)
                }

                if let totp {
                    HStack {
                        HStack(spacing: 8) {
                            TotpCountdownRing(
                                progress: totp.progress,
                                remainingSeconds: totp.remainingSeconds
                            )
                            Text(totp.formattedCode)
                                .font(.system(.callout, design: .monospaced).weight(.bold))
                                .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                        }

                        Spacer()

                        Button {
                            IOSPlatformActions.copySecret(totp.code, expireSeconds: expireSeconds)
                            onCopyToast("动态验证码 \(totp.formattedCode) 已复制")
                        } label: {
                            Text("复制 2FA")
                                .font(.caption2.weight(.semibold))
                                .padding(.horizontal, 10)
                                .padding(.vertical, 5)
                                .background(
                                    MineralPineTheme.primaryAccent(for: colorScheme).opacity(0.12),
                                    in: Capsule()
                                )
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.top, 4)
                }
            }
            .padding(14)
            .background(MineralPineTheme.cardBackground(for: colorScheme), in: RoundedRectangle(cornerRadius: 15))
            .overlay(
                RoundedRectangle(cornerRadius: 15)
                    .strokeBorder(MineralPineTheme.borderColor(for: colorScheme), lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }
}

struct TotpCountdownRing: View {
    let progress: Double
    let remainingSeconds: Int
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        ZStack {
            Circle()
                .stroke(Color.secondary.opacity(0.2), lineWidth: 2.6)
            Circle()
                .trim(from: 0, to: CGFloat(1.0 - progress))
                .stroke(
                    remainingSeconds <= 5
                        ? MineralPineTheme.danger
                        : MineralPineTheme.primaryAccent(for: colorScheme),
                    style: StrokeStyle(lineWidth: 2.6, lineCap: .round)
                )
                .rotationEffect(.degrees(-90))
            Text("\(remainingSeconds)")
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .foregroundStyle(.secondary)
        }
        .frame(width: 24, height: 24)
    }
}

// MARK: - Password Detail Sheet

struct PasswordDetailSheet: View {
    let item: PasswordItem
    @Bindable var store: VaultStore
    let onEdit: () -> Void
    let onInspectCipher: () -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var revealPassword = false
    @State private var revealedFieldIds = Set<String>()

    var body: some View {
        NavigationStack {
            let strength = PasswordSecurityEngine.evaluatePasswordEntropy(item.password)

            List {
                Section("核心凭据") {
                    if !item.username.isEmpty {
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("用户名 / 邮箱")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Text(item.username)
                                    .font(.body)
                                    .textSelection(.enabled)
                            }
                            Spacer()
                            Button("复制") {
                                IOSPlatformActions.copySecret(item.username, expireSeconds: 0)
                                store.showToast("已复制用户名")
                            }
                            .font(.caption.weight(.semibold))
                        }
                    }

                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("加密口令")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Button(revealPassword ? "隐藏" : "显示") {
                                revealPassword.toggle()
                            }
                            .font(.caption.weight(.semibold))
                            Button("复制") {
                                IOSPlatformActions.copySecret(
                                    item.password,
                                    expireSeconds: store.clipboardAutoExpireSeconds
                                )
                                store.showToast("已复制口令（\(store.clipboardAutoExpireSeconds)秒后剪贴板自动清除）")
                            }
                            .font(.caption.weight(.semibold))
                        }
                        Text(revealPassword ? item.password : String(repeating: "•", count: min(20, max(10, item.password.count))))
                            .font(.system(.body, design: .monospaced))

                        HStack(spacing: 6) {
                            Text("熵强度：\(strength.label) (\(strength.entropyBits) bits)")
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(strength.score >= 3 ? MineralPineTheme.accent : MineralPineTheme.amber)
                        }
                    }

                    if !item.totpSecret.isEmpty {
                        TimelineView(.periodic(from: .now, by: 1.0)) { context in
                            if let totp = try? TotpGenerator.generateTotp(item.totpSecret, date: context.date) {
                                HStack {
                                    TotpCountdownRing(progress: totp.progress, remainingSeconds: totp.remainingSeconds)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("动态两步验证码 (RFC 6238)")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                        Text(totp.formattedCode)
                                            .font(.system(.title3, design: .monospaced).weight(.bold))
                                    }
                                    Spacer()
                                    Button("复制验证码") {
                                        IOSPlatformActions.copySecret(
                                            totp.code,
                                            expireSeconds: store.clipboardAutoExpireSeconds
                                        )
                                        store.showToast("2FA 验证码已复制")
                                    }
                                    .font(.caption.weight(.semibold))
                                }
                            }
                        }
                    }

                    if !item.url.isEmpty {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("关联站点")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Text(item.url)
                                    .font(.footnote)
                                    .lineLimit(1)
                            }
                            Spacer()
                            if let targetURL = URL(string: item.url.contains("://") ? item.url : "https://\(item.url)") {
                                Link("打开", destination: targetURL)
                                    .font(.caption.weight(.semibold))
                            }
                        }
                    }
                }

                if !item.customFields.isEmpty {
                    Section("自定义加密字段") {
                        ForEach(item.customFields) { field in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(field.label)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    Text(
                                        (!field.hidden || revealedFieldIds.contains(field.id))
                                            ? field.value
                                            : "••••••••••••"
                                    )
                                    .font(.system(.footnote, design: .monospaced))
                                }
                                Spacer()
                                if field.hidden {
                                    Button(revealedFieldIds.contains(field.id) ? "隐藏" : "查看") {
                                        if revealedFieldIds.contains(field.id) {
                                            revealedFieldIds.remove(field.id)
                                        } else {
                                            revealedFieldIds.insert(field.id)
                                        }
                                    }
                                    .font(.caption)
                                }
                                Button("复制") {
                                    IOSPlatformActions.copySecret(
                                        field.value,
                                        expireSeconds: store.clipboardAutoExpireSeconds
                                    )
                                    store.showToast("已复制字段「\(field.label)」")
                                }
                                .font(.caption.weight(.semibold))
                            }
                        }
                    }
                }

                if !item.notes.isEmpty {
                    Section("加密备注") {
                        Text(item.notes)
                            .font(.footnote)
                    }
                }

                if !item.history.isEmpty {
                    Section("历史口令版本 (\(item.history.count))") {
                        ForEach(item.history, id: \.changedAt) { hist in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(hist.password)
                                        .font(.system(.caption, design: .monospaced))
                                    Text(VaultFormatters.shortDate(hist.changedAt))
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("复制") {
                                    IOSPlatformActions.copySecret(
                                        hist.password,
                                        expireSeconds: store.clipboardAutoExpireSeconds
                                    )
                                    store.showToast("已复制历史口令")
                                }
                                .font(.caption)
                            }
                        }
                    }
                }

                Section("加密审计与操作") {
                    Button {
                        Task {
                            await store.updatePassword(
                                id: item.id,
                                patch: UpdatePasswordRequest(isPinned: !item.isPinned)
                            )
                        }
                    } label: {
                        Label(item.isPinned ? "取消置顶" : "置顶该凭据", systemImage: "pin")
                    }

                    Button {
                        onInspectCipher()
                    } label: {
                        Label("透视 SQLite AES-256-GCM 密文信封 (Rev #\(item.revision))", systemImage: "lock.doc")
                    }

                    if item.isTrashed {
                        Button {
                            Task {
                                await store.updatePassword(id: item.id, patch: UpdatePasswordRequest(isTrashed: false))
                                dismiss()
                            }
                        } label: {
                            Label("从回收站恢复", systemImage: "arrow.uturn.backward")
                        }

                        Button(role: .destructive) {
                            Task {
                                await store.deletePasswordPermanently(id: item.id)
                                dismiss()
                            }
                        } label: {
                            Label("彻底销毁密文记录", systemImage: "trash.slash.fill")
                        }
                    } else {
                        Button(role: .destructive) {
                            Task {
                                await store.updatePassword(id: item.id, patch: UpdatePasswordRequest(isTrashed: true))
                                dismiss()
                            }
                        } label: {
                            Label("移入回收站", systemImage: "trash")
                        }
                    }
                }
            }
            .navigationTitle(item.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("编辑") { onEdit() }
                }
            }
        }
    }
}

// MARK: - Create / Edit Password Sheet

struct PasswordEditorSheet: View {
    @Bindable var store: VaultStore
    let existing: PasswordItem?
    @Environment(\.dismiss) private var dismiss

    @State private var title: String = ""
    @State private var username: String = ""
    @State private var password: String = ""
    @State private var url: String = ""
    @State private var totpSecret: String = ""
    @State private var category: PasswordCategory = .login
    @State private var notes: String = ""
    @State private var tagsText: String = ""
    @State private var customFields: [PasswordCustomField] = []
    @State private var showingGenerator = false

    var body: some View {
        NavigationStack {
            Form {
                Section("账号信息") {
                    TextField("标题（如 GitHub / AWS Root）", text: $title)
                    TextField("用户名 / 邮箱 / 手机号", text: $username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("关联网址（用于 iOS 自动填充域名匹配）", text: $url)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                    Picker("分类", selection: $category) {
                        ForEach(PasswordCategory.allCases) { cat in
                            Text(cat.displayName).tag(cat)
                        }
                    }
                }

                Section("高强度口令与两步验证 (2FA)") {
                    HStack {
                        TextField("密码口令", text: $password)
                            .font(.system(.body, design: .monospaced))
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button {
                            showingGenerator = true
                        } label: {
                            Label("生成", systemImage: "dice.fill")
                                .font(.caption.weight(.semibold))
                        }
                    }

                    let report = PasswordSecurityEngine.evaluatePasswordEntropy(password)
                    if !password.isEmpty {
                        Text("口令评估：\(report.label) · \(report.entropyBits) bits")
                            .font(.caption)
                            .foregroundStyle(report.score >= 3 ? MineralPineTheme.accent : MineralPineTheme.amber)
                    }

                    TextField("TOTP Base32 密钥或 otpauth:// 链接", text: $totpSecret)
                        .font(.system(.footnote, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section("自定义隐藏字段") {
                    ForEach($customFields) { $field in
                        VStack(alignment: .leading, spacing: 6) {
                            TextField("字段名（如 恢复码 / PIN）", text: $field.label)
                                .font(.caption.weight(.semibold))
                            TextField("字段内容", text: $field.value)
                                .font(.system(.footnote, design: .monospaced))
                            Toggle("默认掩码隐藏", isOn: $field.hidden)
                                .font(.caption)
                        }
                    }
                    .onDelete { offsets in
                        customFields.remove(atOffsets: offsets)
                    }

                    Button {
                        customFields.append(PasswordCustomField(label: "", value: "", hidden: true))
                    } label: {
                        Label("添加自定义加密字段", systemImage: "plus.circle")
                    }
                }

                Section("标签与备注") {
                    TextField("标签（逗号分隔）", text: $tagsText)
                    TextField("加密备注", text: $notes, axis: .vertical)
                        .lineLimit(3...6)
                }
            }
            .navigationTitle(existing == nil ? "新建加密凭据" : "编辑凭据")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("加密保存") {
                        saveEntry()
                    }
                    .disabled(title.trimmingCharacters(in: .whitespaces).isEmpty && url.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .sheet(isPresented: $showingGenerator) {
                PasswordGeneratorSheet(
                    expireSeconds: store.clipboardAutoExpireSeconds,
                    onUsePassword: { generated in password = generated },
                    onCopied: { store.showToast("已复制生成口令") }
                )
            }
            .onAppear {
                guard let existing else {
                    if password.isEmpty {
                        password = PasswordSecurityEngine.generateSecurePassword()
                    }
                    return
                }
                title = existing.title
                username = existing.username
                password = existing.password
                url = existing.url
                totpSecret = existing.totpSecret
                category = existing.category
                notes = existing.notes
                tagsText = existing.tags.joined(separator: ", ")
                customFields = existing.customFields
            }
        }
    }

    private func saveEntry() {
        let tags = tagsText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        let cleanedFields = customFields.filter { !$0.label.isEmpty || !$0.value.isEmpty }

        Task {
            if let existing {
                await store.updatePassword(
                    id: existing.id,
                    patch: UpdatePasswordRequest(
                        title: title,
                        username: username,
                        password: password,
                        url: url,
                        totpSecret: totpSecret,
                        category: category,
                        notes: notes,
                        tags: tags,
                        customFields: cleanedFields,
                        expectedRevision: existing.revision
                    )
                )
            } else {
                _ = await store.createPassword(
                    CreatePasswordRequest(
                        title: title.isEmpty ? url : title,
                        username: username,
                        password: password,
                        url: url,
                        totpSecret: totpSecret,
                        category: category,
                        notes: notes,
                        tags: tags,
                        customFields: cleanedFields
                    )
                )
            }
            dismiss()
        }
    }
}

// MARK: - CSPRNG Password & Passphrase Generator Sheet

struct PasswordGeneratorSheet: View {
    let expireSeconds: Int
    let onUsePassword: ((String) -> Void)?
    let onCopied: () -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var mode: Int = 0 // 0 = Random CSPRNG, 1 = Memorable Passphrase
    @State private var length: Double = 22
    @State private var uppercase = true
    @State private var lowercase = true
    @State private var digits = true
    @State private var symbols = true
    @State private var excludeAmbiguous = true

    @State private var wordCount: Double = 4
    @State private var capitalize = true
    @State private var includeNumber = true
    @State private var generatedValue: String = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("生成模式", selection: $mode) {
                        Text("CSPRNG 随机字符").tag(0)
                        Text("易记助记词组").tag(1)
                    }
                    .pickerStyle(.segmented)
                    .onChange(of: mode) { _, _ in regenerate() }

                    VStack(alignment: .leading, spacing: 8) {
                        Text(generatedValue)
                            .font(.system(.title3, design: .monospaced).weight(.semibold))
                            .textSelection(.enabled)
                        let entropy = PasswordSecurityEngine.evaluatePasswordEntropy(generatedValue)
                        Text("强度：\(entropy.label) · 约 \(entropy.entropyBits) bits 熵")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 6)

                    HStack {
                        Button {
                            regenerate()
                        } label: {
                            Label("重新投骰", systemImage: "arrow.clockwise")
                        }
                        Spacer()
                        Button {
                            IOSPlatformActions.copySecret(generatedValue, expireSeconds: expireSeconds)
                            onCopied()
                        } label: {
                            Label("复制口令", systemImage: "doc.on.doc")
                                .fontWeight(.semibold)
                        }
                    }
                }

                if mode == 0 {
                    Section("字符集参数") {
                        Stepper("长度：\(Int(length)) 位", value: $length, in: 8...64, step: 1)
                            .onChange(of: length) { _, _ in regenerate() }
                        Toggle("大写字母 (A-Z)", isOn: $uppercase).onChange(of: uppercase) { _, _ in regenerate() }
                        Toggle("小写字母 (a-z)", isOn: $lowercase).onChange(of: lowercase) { _, _ in regenerate() }
                        Toggle("数字 (0-9)", isOn: $digits).onChange(of: digits) { _, _ in regenerate() }
                        Toggle("特殊符号 (!@#$...)", isOn: $symbols).onChange(of: symbols) { _, _ in regenerate() }
                        Toggle("排除易混淆字符 (0/O/1/l/I)", isOn: $excludeAmbiguous)
                            .onChange(of: excludeAmbiguous) { _, _ in regenerate() }
                    }
                } else {
                    Section("助记词参数") {
                        Stepper("词数：\(Int(wordCount)) 个单词", value: $wordCount, in: 3...8, step: 1)
                            .onChange(of: wordCount) { _, _ in regenerate() }
                        Toggle("首字母大写", isOn: $capitalize).onChange(of: capitalize) { _, _ in regenerate() }
                        Toggle("附加随机数字", isOn: $includeNumber).onChange(of: includeNumber) { _, _ in regenerate() }
                    }
                }
            }
            .navigationTitle("密码生成器")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("关闭") { dismiss() }
                }
                if let onUsePassword {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("填入该密码") {
                            onUsePassword(generatedValue)
                            dismiss()
                        }
                    }
                }
            }
            .onAppear { regenerate() }
        }
    }

    private func regenerate() {
        if mode == 0 {
            generatedValue = PasswordSecurityEngine.generateSecurePassword(
                PasswordGeneratorOptions(
                    length: Int(length),
                    uppercase: uppercase,
                    lowercase: lowercase,
                    digits: digits,
                    symbols: symbols,
                    excludeAmbiguous: excludeAmbiguous
                )
            )
        } else {
            generatedValue = PasswordSecurityEngine.generateMemorablePassphrase(
                PassphraseGeneratorOptions(
                    wordCount: Int(wordCount),
                    separator: "-",
                    capitalize: capitalize,
                    includeNumber: includeNumber
                )
            )
        }
    }
}

// MARK: - CSV Batch Import Sheet

struct PasswordCsvImportSheet: View {
    @Bindable var store: VaultStore
    @Environment(\.dismiss) private var dismiss
    @State private var csvContent: String = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("粘贴 Apple 密码 / Chrome / 1Password / Bitwarden CSV") {
                    TextField(
                        "name,url,username,password,totp\nGitHub,https://github.com,me@dev.io,Secret!123,JBSWY3DPEHPK3PXP",
                        text: $csvContent,
                        axis: .vertical
                    )
                    .font(.system(.caption, design: .monospaced))
                    .lineLimit(8...16)
                }
                Section {
                    let previewCount = PasswordSecurityEngine.parsePasswordCsv(csvContent).count
                    Text("已识别可导入条目：\(previewCount) 条（入库后全量 AES-256-GCM 静态加密）")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("CSV 批量导入")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("加密导入") {
                        Task {
                            let count = await store.importPasswordCsv(csvContent)
                            if count > 0 { dismiss() }
                        }
                    }
                    .disabled(csvContent.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }
}
