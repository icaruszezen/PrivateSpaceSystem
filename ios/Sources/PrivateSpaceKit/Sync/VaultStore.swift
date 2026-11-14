import Foundation
import Observation

public enum VaultLifecyclePhase: Equatable, Sendable {
    case launching
    case serverSetup(vaultName: String)
    case passwordLocked(vaultName: String, fingerprint: String?)
    case biometricLocked(vaultName: String, fingerprint: String?)
    case unlocked
}

public enum NoteListFilter: String, CaseIterable, Identifiable, Sendable {
    case all = "全部"
    case pinned = "置顶"
    case archived = "归档"
    case trash = "回收站"

    public var id: String { rawValue }
}

public enum NoteSortMode: String, CaseIterable, Identifiable, Sendable {
    case updated = "最近编辑"
    case created = "创建时间"
    case title = "标题排序"

    public var id: String { rawValue }
}

public enum PasswordAuditFilter: String, CaseIterable, Identifiable, Sendable {
    case none = "全部凭据"
    case weak = "弱口令"
    case reused = "重复密码"
    case missing2FA = "未启用 2FA"
    case trash = "回收站"

    public var id: String { rawValue }
}

public enum AppThemePreference: String, Codable, CaseIterable, Identifiable, Sendable {
    case system = "跟随系统"
    case light = "暖纸浅色"
    case dark = "墨玉深色"

    public var id: String { rawValue }
}

public struct UploadTaskStatus: Identifiable, Equatable, Sendable {
    public let id: String
    public let filename: String
    public var progress: Double
}

/// Primary `@Observable` state & synchronization coordinator for the PrivateSpace iOS SwiftUI App.
@MainActor
@Observable
public final class VaultStore {
    private static let keychainServerURLKey = "server_base_url"
    private static let keychainSessionTokenKey = "device_session_token"
    private static let keychainBiometricEnabledKey = "biometric_unlock_enabled"
    private static let keychainAutoLockTimeoutKey = "auto_lock_timeout_seconds"
    private static let keychainThemeKey = "app_theme_preference"

    public var phase: VaultLifecyclePhase = .launching
    public var serverURL: String
    public var vaultName: String = "PrivateSpace"
    public var keyFingerprint: String?
    public var snapshot: MobileVaultSnapshot = MobileVaultSnapshot()

    // Live Sync & Network Telemetry
    public var sseConnected: Bool = false
    public var isSyncing: Bool = false
    public var isOfflineMode: Bool = false
    public var statusBanner: String?
    public var errorBanner: String?
    public var activeUploads: [UploadTaskStatus] = []

    // Security & Privacy Settings
    public var biometricCapability: BiometricCapability = .none
    public var biometricUnlockEnabled: Bool = true
    public var autoLockTimeout: AutoLockTimeout = .oneMinute
    public var clipboardAutoExpireSeconds: Int = 30
    public var themePreference: AppThemePreference = .system
    public var isPrivacyShieldVisible: Bool = false

    // Security Dashboard Cache
    public var securitySummary: VaultSecuritySummary?
    public var activeSessions: [SessionInfo] = []

    public let apiClient: PrivateSpaceAPIClient
    public let localStore: EncryptedLocalVaultStore
    public let secretStore: SecretStoreProtocol
    public let biometricService: BiometricAuthService

    private var backgroundedAt: Date?
    private var sseTask: Task<Void, Never>?

    public init(
        defaultServerURL: String = "http://127.0.0.1:8080",
        deviceName: String = "iPhone · PrivateSpace iOS",
        secretStore: SecretStoreProtocol = AppleKeychainStore(),
        localStore: EncryptedLocalVaultStore? = nil,
        biometricService: BiometricAuthService = BiometricAuthService(),
        urlSession: URLSession? = nil
    ) {
        let savedServer = (try? secretStore.readString(forKey: Self.keychainServerURLKey)) ?? defaultServerURL
        let savedToken = try? secretStore.readString(forKey: Self.keychainSessionTokenKey)

        self.serverURL = savedServer
        self.secretStore = secretStore
        self.localStore = localStore ?? EncryptedLocalVaultStore(secretStore: secretStore)
        self.biometricService = biometricService
        self.biometricCapability = biometricService.detectCapability()
        self.apiClient = PrivateSpaceAPIClient(
            baseURLString: savedServer,
            sessionToken: savedToken,
            deviceName: deviceName,
            urlSession: urlSession
        )

        if let bioStr = try? secretStore.readString(forKey: Self.keychainBiometricEnabledKey) {
            self.biometricUnlockEnabled = (bioStr == "true")
        }
        if let timeoutStr = try? secretStore.readString(forKey: Self.keychainAutoLockTimeoutKey),
           let seconds = Int(timeoutStr),
           let parsedTimeout = AutoLockTimeout(rawValue: seconds) {
            self.autoLockTimeout = parsedTimeout
        }
        if let themeStr = try? secretStore.readString(forKey: Self.keychainThemeKey),
           let parsedTheme = AppThemePreference(rawValue: themeStr) {
            self.themePreference = parsedTheme
        }
    }

    // MARK: - Boot, Server Probe, Setup, Login & Biometric Unlock

    public func bootstrap() async {
        biometricCapability = biometricService.detectCapability()
        let savedToken = try? secretStore.readString(forKey: Self.keychainSessionTokenKey)
        await apiClient.updateServerURL(serverURL)
        await apiClient.setSessionToken(savedToken)

        // Preload encrypted local snapshot metadata if available
        if let cached = try? localStore.loadSnapshot() {
            self.vaultName = cached.vaultName
            self.keyFingerprint = cached.keyFingerprint
        }

        do {
            let status = try await apiClient.getAuthStatus()
            self.vaultName = status.vaultName
            self.keyFingerprint = status.keyFingerprint
            self.isOfflineMode = false

            if !status.initialized {
                self.phase = .serverSetup(vaultName: status.vaultName)
                return
            }

            if status.authenticated, savedToken != nil {
                if biometricUnlockEnabled && biometricCapability != .none {
                    self.phase = .biometricLocked(vaultName: status.vaultName, fingerprint: status.keyFingerprint)
                } else {
                    try await unlockFromCachedAndSync()
                }
            } else {
                try? secretStore.deleteData(forKey: Self.keychainSessionTokenKey)
                await apiClient.setSessionToken(nil)
                self.phase = .passwordLocked(vaultName: status.vaultName, fingerprint: status.keyFingerprint)
            }
        } catch {
            // Offline cold boot: if a valid session token & local encrypted cache exist, allow biometric offline access!
            if savedToken != nil, (try? localStore.loadSnapshot()) != nil {
                self.isOfflineMode = true
                if biometricUnlockEnabled && biometricCapability != .none {
                    self.phase = .biometricLocked(vaultName: vaultName, fingerprint: keyFingerprint)
                } else if let cached = try? localStore.loadSnapshot() {
                    self.snapshot = cached
                    self.phase = .unlocked
                    showToast("处于离线加密缓存模式（游标 #\(cached.lastSyncSeq)）")
                }
            } else {
                self.phase = .passwordLocked(vaultName: vaultName, fingerprint: keyFingerprint)
                self.errorBanner = error.localizedDescription
            }
        }
    }

    public func connectServer(_ newServerURL: String) async {
        let normalized = PrivateSpaceAPIClient.normalizeBaseURL(newServerURL)
        self.serverURL = normalized
        try? secretStore.writeString(normalized, forKey: Self.keychainServerURLKey)
        await apiClient.updateServerURL(normalized)
        errorBanner = nil
        await bootstrap()
    }

    public func initializeAdminAndUnlock(vaultNameInput: String, masterPassword: String) async {
        errorBanner = nil
        do {
            let normalized = PrivateSpaceAPIClient.normalizeBaseURL(serverURL)
            self.serverURL = normalized
            try? secretStore.writeString(normalized, forKey: Self.keychainServerURLKey)
            await apiClient.updateServerURL(normalized)

            let auth = try await apiClient.setupAdmin(
                password: masterPassword,
                vaultName: vaultNameInput.trimmingCharacters(in: .whitespacesAndNewlines)
            )
            try persistSessionAndEnterVault(auth)
            await syncDelta()
            startRealtimeSyncStream()
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    public func loginWithMasterPassword(_ masterPassword: String) async {
        errorBanner = nil
        do {
            let normalized = PrivateSpaceAPIClient.normalizeBaseURL(serverURL)
            self.serverURL = normalized
            try? secretStore.writeString(normalized, forKey: Self.keychainServerURLKey)
            await apiClient.updateServerURL(normalized)

            let auth = try await apiClient.login(password: masterPassword)
            try persistSessionAndEnterVault(auth)
            await syncDelta()
            startRealtimeSyncStream()
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    public func unlockWithBiometrics() async {
        errorBanner = nil
        do {
            let passed = try await biometricService.authenticate(
                reason: "使用 \(biometricCapability.displayName) 解锁 \(vaultName)"
            )
            guard passed else { return }
            try await unlockFromCachedAndSync()
        } catch {
            errorBanner = "生物识别未通过，可输入管理员主密码解锁"
        }
    }

    private func persistSessionAndEnterVault(_ auth: AuthSessionResponse) throws {
        try secretStore.writeString(auth.token, forKey: Self.keychainSessionTokenKey)
        self.vaultName = auth.vaultName
        self.keyFingerprint = auth.keyFingerprint
        if let cached = try? localStore.loadSnapshot() {
            self.snapshot = cached
        } else {
            self.snapshot = MobileVaultSnapshot(
                vaultName: auth.vaultName,
                keyFingerprint: auth.keyFingerprint
            )
        }
        self.snapshot.vaultName = auth.vaultName
        self.snapshot.keyFingerprint = auth.keyFingerprint
        try localStore.saveSnapshot(self.snapshot)
        self.phase = .unlocked
    }

    private func unlockFromCachedAndSync() async throws {
        if let cached = try localStore.loadSnapshot() {
            self.snapshot = cached
        }
        self.phase = .unlocked
        await syncDelta()
        startRealtimeSyncStream()
    }

    // MARK: - Scene Lifecycle, App Switcher Privacy Blur & Auto-Lock

    public func handleScenePhaseTransition(isActive: Bool) async {
        if !isActive {
            isPrivacyShieldVisible = true
            backgroundedAt = Date()
            stopRealtimeSyncStream()
        } else {
            isPrivacyShieldVisible = false
            if phase == .unlocked,
               biometricService.shouldAutoLock(
                   backgroundedAt: backgroundedAt,
                   now: Date(),
                   timeout: autoLockTimeout
               ) {
                lockSessionLocally()
            } else if phase == .unlocked {
                backgroundedAt = nil
                await syncDelta()
                startRealtimeSyncStream()
            }
        }
    }

    /// Locks the UI in-memory (wiping RAM caches) while preserving Keychain session for Face ID re-unlock.
    public func lockSessionLocally() {
        stopRealtimeSyncStream()
        VolatileMediaMemoryCache.shared.clearAll()
        snapshot = MobileVaultSnapshot(vaultName: vaultName, keyFingerprint: keyFingerprint)
        securitySummary = nil
        activeSessions = []
        if biometricUnlockEnabled && biometricCapability != .none,
           (try? secretStore.readString(forKey: Self.keychainSessionTokenKey)) != nil {
            phase = .biometricLocked(vaultName: vaultName, fingerprint: keyFingerprint)
        } else {
            phase = .passwordLocked(vaultName: vaultName, fingerprint: keyFingerprint)
        }
    }

    /// Revokes the device session on server, shreds local `.pscache` encrypted files, and clears Keychain token.
    public func logoutAndWipeDevice() async {
        stopRealtimeSyncStream()
        await apiClient.logout()
        try? secretStore.deleteData(forKey: Self.keychainSessionTokenKey)
        localStore.shredLocalCache()
        VolatileMediaMemoryCache.shared.clearAll()
        snapshot = MobileVaultSnapshot()
        securitySummary = nil
        activeSessions = []
        phase = .passwordLocked(vaultName: vaultName, fingerprint: keyFingerprint)
        showToast("已注销当前设备并安全擦除本地加密缓存")
    }

    public func setBiometricPreference(_ enabled: Bool) {
        biometricUnlockEnabled = enabled
        try? secretStore.writeString(enabled ? "true" : "false", forKey: Self.keychainBiometricEnabledKey)
    }

    public func setAutoLockPreference(_ timeout: AutoLockTimeout) {
        autoLockTimeout = timeout
        try? secretStore.writeString(String(timeout.rawValue), forKey: Self.keychainAutoLockTimeoutKey)
    }

    public func setThemePreference(_ pref: AppThemePreference) {
        themePreference = pref
        try? secretStore.writeString(pref.rawValue, forKey: Self.keychainThemeKey)
    }

    // MARK: - Monotonic `since_seq` Delta Sync + Offline Outbox Replay + SSE Stream

    public func syncDelta() async {
        guard phase == .unlocked, !isSyncing else { return }
        isSyncing = true
        defer { isSyncing = false }

        await flushOutboxIfNeeded()

        do {
            let delta = try await apiClient.pullSync(sinceSeq: snapshot.lastSyncSeq)
            var next = snapshot

            for n in delta.notes { next.notes[n.id] = n }
            for p in delta.passwords { next.passwords[p.id] = p }
            for m in delta.media { next.media[m.id] = m }
            for a in delta.albums { next.albums[a.id] = a }

            for tomb in delta.deleted {
                next.notes.removeValue(forKey: tomb.id)
                next.passwords.removeValue(forKey: tomb.id)
                next.media.removeValue(forKey: tomb.id)
                next.albums.removeValue(forKey: tomb.id)
            }

            next.lastSyncSeq = delta.latestSyncSeq
            next.syncedAt = delta.serverTime
            next.vaultName = vaultName
            next.keyFingerprint = keyFingerprint

            self.snapshot = next
            self.isOfflineMode = false
            try? localStore.saveSnapshot(next)
        } catch PrivateSpaceClientError.unauthorized(let msg) {
            errorBanner = msg
            try? secretStore.deleteData(forKey: Self.keychainSessionTokenKey)
            phase = .passwordLocked(vaultName: vaultName, fingerprint: keyFingerprint)
        } catch {
            self.isOfflineMode = true
        }
    }

    private func flushOutboxIfNeeded() async {
        guard !snapshot.pendingOutbox.isEmpty else { return }
        var remaining: [OutboxOperation] = []
        let decoder = JSONDecoder()

        for op in snapshot.pendingOutbox {
            do {
                switch op.kind {
                case .createNote:
                    let req = try decoder.decode(CreateNoteRequest.self, from: op.payloadJson)
                    let saved = try await apiClient.createNote(req)
                    snapshot.notes[saved.id] = saved
                case .updateNote:
                    guard let id = op.targetItemId else { continue }
                    let req = try decoder.decode(UpdateNoteRequest.self, from: op.payloadJson)
                    let saved = try await apiClient.updateNote(id: id, patch: req)
                    snapshot.notes[saved.id] = saved
                case .createPassword:
                    let req = try decoder.decode(CreatePasswordRequest.self, from: op.payloadJson)
                    let saved = try await apiClient.createPassword(req)
                    snapshot.passwords[saved.id] = saved
                case .updatePassword:
                    guard let id = op.targetItemId else { continue }
                    let req = try decoder.decode(UpdatePasswordRequest.self, from: op.payloadJson)
                    let saved = try await apiClient.updatePassword(id: id, patch: req)
                    snapshot.passwords[saved.id] = saved
                }
            } catch PrivateSpaceClientError.networkUnavailable {
                remaining.append(op)
            } catch {
                // Conflict or validation error: skip bad outbox item and let server delta reconcile
                errorBanner = error.localizedDescription
            }
        }

        snapshot.pendingOutbox = remaining
        try? localStore.saveSnapshot(snapshot)
    }

    public func startRealtimeSyncStream() {
        sseTask?.cancel()
        sseTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                do {
                    let stream = try await self.apiClient.subscribeSyncEvents()
                    for try await message in stream {
                        if Task.isCancelled { break }
                        switch message {
                        case .connected(let ev):
                            self.sseConnected = true
                            self.isOfflineMode = false
                            if ev.latestSyncSeq > self.snapshot.lastSyncSeq {
                                await self.syncDelta()
                            }
                        case .cursorChanged(let ev):
                            self.sseConnected = true
                            if ev.latestSyncSeq > self.snapshot.lastSyncSeq {
                                await self.syncDelta()
                            }
                        }
                    }
                } catch {
                    self.sseConnected = false
                }
                if Task.isCancelled { break }
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
        }
    }

    public func stopRealtimeSyncStream() {
        sseTask?.cancel()
        sseTask = nil
        sseConnected = false
    }

    // MARK: - Derived Collections & Filters

    public var passwordAudit: VaultPasswordAuditReport {
        PasswordSecurityEngine.auditPasswordVault(Array(snapshot.passwords.values))
    }

    public func filteredPasswords(
        query: String,
        category: PasswordCategory?,
        auditFilter: PasswordAuditFilter
    ) -> [PasswordItem] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let audit = passwordAudit
        let weakSet = Set(audit.weakIds)
        let reusedSet = Set(audit.reusedIds)
        let missing2FASet = Set(audit.missingTotpIds)

        return snapshot.passwords.values
            .filter { item in
                if auditFilter == .trash {
                    guard item.isTrashed else { return false }
                } else {
                    guard !item.isTrashed else { return false }
                }
                if let category, item.category != category {
                    return false
                }
                switch auditFilter {
                case .weak where !weakSet.contains(item.id): return false
                case .reused where !reusedSet.contains(item.id): return false
                case .missing2FA where !missing2FASet.contains(item.id): return false
                default: break
                }
                if !q.isEmpty {
                    let hay = "\(item.title) \(item.username) \(item.url) \(item.tags.joined(separator: " "))".lowercased()
                    if !hay.contains(q) { return false }
                }
                return true
            }
            .sorted { a, b in
                if a.isPinned != b.isPinned { return a.isPinned && !b.isPinned }
                return a.updatedAt > b.updatedAt
            }
    }

    public func filteredNotes(
        query: String,
        filter: NoteListFilter,
        tag: String?,
        sort: NoteSortMode
    ) -> [NoteItem] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return snapshot.notes.values
            .filter { note in
                if let tag {
                    guard !note.isTrashed && note.tags.contains(tag) else { return false }
                } else {
                    switch filter {
                    case .all: guard !note.isTrashed && !note.isArchived else { return false }
                    case .pinned: guard !note.isTrashed && !note.isArchived && note.isPinned else { return false }
                    case .archived: guard !note.isTrashed && note.isArchived else { return false }
                    case .trash: guard note.isTrashed else { return false }
                    }
                }
                if !q.isEmpty {
                    let hay = "\(note.title) \(note.content) \(note.tags.joined(separator: " "))".lowercased()
                    if !hay.contains(q) { return false }
                }
                return true
            }
            .sorted { a, b in
                if !a.isTrashed && !b.isTrashed && a.isPinned != b.isPinned {
                    return a.isPinned && !b.isPinned
                }
                switch sort {
                case .title: return a.title.localizedCompare(b.title) == .orderedAscending
                case .created: return a.createdAt > b.createdAt
                case .updated: return a.updatedAt > b.updatedAt
                }
            }
    }

    public func filteredMedia(
        kind: MediaKind,
        albumId: String?,
        showTrash: Bool,
        onlyPinned: Bool,
        query: String
    ) -> [MediaItem] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let targetType: VaultItemType = kind == .video ? .video : .image
        return snapshot.media.values
            .filter { m in
                guard m.itemType == targetType else { return false }
                if showTrash {
                    guard m.isTrashed else { return false }
                } else {
                    guard !m.isTrashed else { return false }
                }
                if onlyPinned && !m.isPinned { return false }
                if let albumId, m.albumId != albumId { return false }
                if !q.isEmpty {
                    let hay = "\(m.title) \(m.originalFilename) \(m.description) \(m.tags.joined(separator: " "))".lowercased()
                    if !hay.contains(q) { return false }
                }
                return true
            }
            .sorted { a, b in
                if a.isPinned != b.isPinned { return a.isPinned && !b.isPinned }
                return a.createdAt > b.createdAt
            }
    }

    public var allNoteTags: [String] {
        var counts: [String: Int] = [:]
        for n in snapshot.notes.values where !n.isTrashed {
            for t in n.tags { counts[t, default: 0] += 1 }
        }
        return counts.keys.sorted { (counts[$0] ?? 0) > (counts[$1] ?? 0) }
    }

    public var sortedAlbums: [MediaAlbum] {
        snapshot.albums.values.sorted { $0.updatedAt > $1.updatedAt }
    }

    // MARK: - CRUD Mutations (with Optimistic Local Cache Persistence & Offline Outbox)

    @discardableResult
    public func createNote(_ req: CreateNoteRequest) async -> NoteItem? {
        let clientId = req.id ?? UUID().uuidString.lowercased()
        var payload = req
        payload.id = clientId

        do {
            let created = try await apiClient.createNote(payload)
            snapshot.notes[created.id] = created
            snapshot.lastSyncSeq = max(snapshot.lastSyncSeq, created.syncSeq)
            try? localStore.saveSnapshot(snapshot)
            showToast("已加密保存笔记")
            return created
        } catch PrivateSpaceClientError.networkUnavailable {
            let now = ISO8601DateFormatter().string(from: Date())
            let content = payload.content ?? ""
            let localItem = NoteItem(
                id: clientId,
                title: payload.title ?? "",
                content: content,
                excerpt: String(content.prefix(120)),
                tags: payload.tags ?? [],
                format: payload.format ?? .markdown,
                wordCount: content.count,
                isPinned: payload.isPinned ?? false,
                createdAt: now,
                updatedAt: now
            )
            snapshot.notes[clientId] = localItem
            if let encoded = try? JSONEncoder().encode(payload) {
                snapshot.pendingOutbox.append(OutboxOperation(kind: .createNote, payloadJson: encoded))
            }
            try? localStore.saveSnapshot(snapshot)
            showToast("已加密存入离线队列，联网后自动同步")
            return localItem
        } catch {
            errorBanner = error.localizedDescription
            return nil
        }
    }

    public func updateNote(id: String, patch: UpdateNoteRequest) async {
        do {
            let updated = try await apiClient.updateNote(id: id, patch: patch)
            snapshot.notes[updated.id] = updated
            snapshot.lastSyncSeq = max(snapshot.lastSyncSeq, updated.syncSeq)
            try? localStore.saveSnapshot(snapshot)
        } catch PrivateSpaceClientError.networkUnavailable {
            if var existing = snapshot.notes[id] {
                if let title = patch.title { existing.title = title }
                if let content = patch.content {
                    existing.content = content
                    existing.excerpt = String(content.prefix(120))
                    existing.wordCount = content.count
                }
                if let tags = patch.tags { existing.tags = tags }
                if let isPinned = patch.isPinned { existing.isPinned = isPinned }
                if let isArchived = patch.isArchived { existing.isArchived = isArchived }
                if let isTrashed = patch.isTrashed { existing.isTrashed = isTrashed }
                existing.updatedAt = ISO8601DateFormatter().string(from: Date())
                snapshot.notes[id] = existing
                if let encoded = try? JSONEncoder().encode(patch) {
                    snapshot.pendingOutbox.append(
                        OutboxOperation(kind: .updateNote, targetItemId: id, payloadJson: encoded)
                    )
                }
                try? localStore.saveSnapshot(snapshot)
                showToast("离线修改已加密暂存")
            }
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    public func deleteNotePermanently(id: String) async {
        do {
            try await apiClient.deleteNotePermanently(id: id)
            snapshot.notes.removeValue(forKey: id)
            try? localStore.saveSnapshot(snapshot)
            showToast("笔记密文已彻底销毁")
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    public func createPassword(_ req: CreatePasswordRequest) async -> PasswordItem? {
        do {
            let created = try await apiClient.createPassword(req)
            snapshot.passwords[created.id] = created
            snapshot.lastSyncSeq = max(snapshot.lastSyncSeq, created.syncSeq)
            try? localStore.saveSnapshot(snapshot)
            showToast("凭据已通过 AES-256-GCM 加密入库")
            return created
        } catch {
            errorBanner = error.localizedDescription
            return nil
        }
    }

    public func updatePassword(id: String, patch: UpdatePasswordRequest) async {
        do {
            let updated = try await apiClient.updatePassword(id: id, patch: patch)
            snapshot.passwords[updated.id] = updated
            snapshot.lastSyncSeq = max(snapshot.lastSyncSeq, updated.syncSeq)
            try? localStore.saveSnapshot(snapshot)
            showToast("密码凭据已更新")
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    public func importPasswordCsv(_ csvText: String) async -> Int {
        let parsed = PasswordSecurityEngine.parsePasswordCsv(csvText)
        guard !parsed.isEmpty else {
            errorBanner = "未从 CSV 中解析出有效账号密码行"
            return 0
        }
        do {
            let imported = try await apiClient.importPasswords(parsed)
            for item in imported {
                snapshot.passwords[item.id] = item
                snapshot.lastSyncSeq = max(snapshot.lastSyncSeq, item.syncSeq)
            }
            try? localStore.saveSnapshot(snapshot)
            showToast("成功导入 \(imported.count) 条加密密码")
            return imported.count
        } catch {
            errorBanner = error.localizedDescription
            return 0
        }
    }

    public func deletePasswordPermanently(id: String) async {
        do {
            try await apiClient.deletePasswordPermanently(id: id)
            snapshot.passwords.removeValue(forKey: id)
            try? localStore.saveSnapshot(snapshot)
            showToast("密码密文已从数据库彻底擦除")
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    public func uploadMediaData(
        data: Data,
        filename: String,
        mimeType: String,
        kind: MediaKind,
        title: String? = nil,
        albumId: String? = nil,
        tags: [String] = []
    ) async {
        let taskId = UUID().uuidString
        activeUploads.append(UploadTaskStatus(id: taskId, filename: filename, progress: 0.04))
        defer {
            activeUploads.removeAll { $0.id == taskId }
        }

        do {
            let media = try await apiClient.uploadMediaResumable(
                data: data,
                filename: filename,
                mimeType: mimeType,
                kind: kind,
                title: title,
                albumId: albumId,
                tags: tags,
                chunkBytes: 512 * 1024
            ) { [weak self] uploaded, total in
                Task { @MainActor in
                    guard let self,
                          let idx = self.activeUploads.firstIndex(where: { $0.id == taskId }) else { return }
                    self.activeUploads[idx].progress = min(0.98, Double(uploaded) / Double(max(1, total)))
                }
            }
            snapshot.media[media.id] = media
            snapshot.lastSyncSeq = max(snapshot.lastSyncSeq, media.syncSeq)
            try? localStore.saveSnapshot(snapshot)
            showToast("已分块加密入库：\(media.title)")
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    public func createAlbum(name: String, kind: String = "mixed") async {
        do {
            let album = try await apiClient.createAlbum(CreateAlbumRequest(name: name, kind: kind))
            snapshot.albums[album.id] = album
            snapshot.lastSyncSeq = max(snapshot.lastSyncSeq, album.syncSeq)
            try? localStore.saveSnapshot(snapshot)
            showToast("加密相册「\(album.name)」已创建")
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    public func deleteAlbum(id: String) async {
        do {
            try await apiClient.deleteAlbum(id: id)
            snapshot.albums.removeValue(forKey: id)
            try? localStore.saveSnapshot(snapshot)
            showToast("加密相册分组已移除")
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    public func updateMedia(id: String, patch: UpdateMediaRequest) async {
        do {
            let updated = try await apiClient.updateMedia(id: id, patch: patch)
            snapshot.media[updated.id] = updated
            snapshot.lastSyncSeq = max(snapshot.lastSyncSeq, updated.syncSeq)
            try? localStore.saveSnapshot(snapshot)
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    public func deleteMediaPermanently(id: String) async {
        do {
            try await apiClient.deleteMediaPermanently(id: id)
            snapshot.media.removeValue(forKey: id)
            try? localStore.saveSnapshot(snapshot)
            showToast(".psenc 密文块已安全覆写并销毁")
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    // MARK: - Security Dashboard & Sessions

    public func refreshSecurityDashboard() async {
        do {
            async let summaryReq = apiClient.getSecuritySummary()
            async let sessionsReq = apiClient.listSessions()
            let (summary, sessions) = try await (summaryReq, sessionsReq)
            self.securitySummary = summary
            self.activeSessions = sessions
        } catch {
            // Keep cached state if offline
        }
    }

    public func revokeDeviceSession(id: String) async {
        do {
            try await apiClient.revokeSession(id: id)
            activeSessions.removeAll { $0.id == id }
            showToast("已吊销目标设备会话")
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    public func rotateMasterPassword(
        currentPassword: String,
        newPassword: String,
        revokeOthers: Bool
    ) async -> Bool {
        do {
            let res = try await apiClient.changeMasterPassword(
                ChangePasswordRequest(
                    currentPassword: currentPassword,
                    newPassword: newPassword,
                    revokeOtherSessions: revokeOthers
                )
            )
            self.keyFingerprint = res.keyFingerprint
            showToast("主密码信封轮换成功（底层密文零重写）")
            await refreshSecurityDashboard()
            return true
        } catch {
            errorBanner = error.localizedDescription
            return false
        }
    }

    public func renameVault(_ name: String) async {
        do {
            let updatedName = try await apiClient.updateVaultName(name)
            self.vaultName = updatedName
            self.snapshot.vaultName = updatedName
            try? localStore.saveSnapshot(snapshot)
            showToast("空间名称已更新")
        } catch {
            errorBanner = error.localizedDescription
        }
    }

    public func showToast(_ message: String) {
        self.statusBanner = message
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 2_600_000_000)
            if self.statusBanner == message {
                self.statusBanner = nil
            }
        }
    }
}
