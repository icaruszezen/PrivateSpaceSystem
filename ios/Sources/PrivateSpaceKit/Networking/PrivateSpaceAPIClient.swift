import CryptoKit
import Foundation

public enum SyncStreamMessage: Sendable, Equatable {
    case connected(SyncCursorEvent)
    case cursorChanged(SyncCursorEvent)
}

private struct UploadSessionDecryptedMeta: Codable, Sendable {
    let filename: String
    let mimeType: String
    let title: String?
    let albumId: String?
    let tags: [String]
    let description: String
    let sha256: String
    let takenAt: String
}

/// Thread-safe volatile RAM cache for decrypted thumbnails (`NSCache`), wiped immediately on lock.
public final class VolatileMediaMemoryCache: @unchecked Sendable {
    public static let shared = VolatileMediaMemoryCache()
    private let cache = NSCache<NSString, NSData>()

    public init(maxBytes: Int = 48 * 1024 * 1024) {
        cache.totalCostLimit = maxBytes
    }

    public func data(forKey key: String) -> Data? {
        cache.object(forKey: key as NSString) as Data?
    }

    public func insert(_ data: Data, forKey key: String) {
        cache.setObject(data as NSData, forKey: key as NSString, cost: data.count)
    }

    public func clearAll() {
        cache.removeAllObjects()
    }
}

/// Zero-Knowledge E2EE v2 Network, Resumable PSENC001 Upload, HTTP 206 Range Decryption & SSE Client for iOS.
/// Uses `URLSessionConfiguration.ephemeral` so network responses never leak into `URLCache` SQLite on disk.
public actor PrivateSpaceAPIClient {
    private var baseURLString: String
    private var sessionToken: String?
    private var masterDek: Data?
    private let deviceName: String
    private let session: URLSession
    private let streamSession: URLSession

    public init(
        baseURLString: String,
        sessionToken: String? = nil,
        masterDek: Data? = nil,
        deviceName: String = "iPhone · PrivateSpace iOS",
        urlSession: URLSession? = nil
    ) {
        self.baseURLString = Self.normalizeBaseURL(baseURLString)
        self.sessionToken = sessionToken
        self.masterDek = (masterDek?.count == 32) ? masterDek : nil
        self.deviceName = deviceName

        if let urlSession {
            self.session = urlSession
            self.streamSession = urlSession
        } else {
            let config = URLSessionConfiguration.ephemeral
            config.requestCachePolicy = .reloadIgnoringLocalCacheData
            config.urlCache = nil
            config.httpCookieAcceptPolicy = .never
            config.httpShouldSetCookies = false
            config.timeoutIntervalForRequest = 30
            config.timeoutIntervalForResource = 300
            self.session = URLSession(configuration: config)

            let sseConfig = URLSessionConfiguration.ephemeral
            sseConfig.requestCachePolicy = .reloadIgnoringLocalCacheData
            sseConfig.urlCache = nil
            sseConfig.httpCookieAcceptPolicy = .never
            sseConfig.timeoutIntervalForRequest = 300
            sseConfig.timeoutIntervalForResource = 86_400
            self.streamSession = URLSession(configuration: sseConfig)
        }
    }

    public static func normalizeBaseURL(_ raw: String) -> String {
        var trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        while trimmed.hasSuffix("/") {
            trimmed.removeLast()
        }
        if !trimmed.isEmpty && !trimmed.contains("://") {
            trimmed = "https://\(trimmed)"
        }
        return trimmed
    }

    public func updateServerURL(_ raw: String) {
        self.baseURLString = Self.normalizeBaseURL(raw)
    }

    public func getBaseURLString() -> String {
        baseURLString
    }

    public func setSessionToken(_ token: String?) {
        self.sessionToken = token
    }

    public func getSessionToken() -> String? {
        sessionToken
    }

    public func setMasterDek(_ dek: Data?) {
        self.masterDek = (dek?.count == 32) ? dek : nil
    }

    public func getMasterDek() -> Data? {
        masterDek
    }

    public func hasUnlockedMasterKey() -> Bool {
        masterDek?.count == 32
    }

    private func requireUnlockedDek() throws -> Data {
        guard let dek = masterDek, dek.count == 32 else {
            throw PrivateSpaceClientError.vaultLocked
        }
        return dek
    }

    // MARK: - Core JSON Request Helper

    private func makeURL(_ path: String) throws -> URL {
        guard !baseURLString.isEmpty, let url = URL(string: "\(baseURLString)\(path)") else {
            throw PrivateSpaceClientError.invalidServerURL(baseURLString)
        }
        return url
    }

    private func buildRequest(
        path: String,
        method: String = "GET",
        bodyData: Data? = nil,
        contentType: String? = nil,
        accept: String = "application/json",
        extraHeaders: [String: String] = [:]
    ) throws -> URLRequest {
        let url = try makeURL(path)
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue(accept, forHTTPHeaderField: "Accept")
        req.setValue("PrivateSpace-IOS/2.0 (\(deviceName))", forHTTPHeaderField: "User-Agent")

        if let token = sessionToken, !token.isEmpty {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let bodyData {
            req.httpBody = bodyData
            req.setValue(contentType ?? "application/json", forHTTPHeaderField: "Content-Type")
        }
        for (headerKey, headerVal) in extraHeaders {
            req.setValue(headerVal, forHTTPHeaderField: headerKey)
        }
        return req
    }

    private func performJSON<T: Decodable>(
        path: String,
        method: String = "GET",
        bodyData: Data? = nil
    ) async throws -> T {
        let req = try buildRequest(path: path, method: method, bodyData: bodyData)
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw PrivateSpaceClientError.networkUnavailable(error.localizedDescription)
        }

        guard let http = response as? HTTPURLResponse else {
            throw PrivateSpaceClientError.networkUnavailable("非 HTTP 响应")
        }

        if !(200...299).contains(http.statusCode) {
            throw decodeAPIError(status: http.statusCode, data: data)
        }

        return try JSONDecoder().decode(T.self, from: data)
    }

    private func decodeAPIError(status: Int, data: Data) -> PrivateSpaceClientError {
        let parsed = try? JSONDecoder().decode(ApiErrorBody.self, from: data)
        let code = parsed?.error?.code ?? "HTTP_\(status)"
        let message = parsed?.error?.message ?? "请求失败 (HTTP \(status))"

        switch status {
        case 401:
            return .unauthorized(message)
        case 403 where code == "VAULT_NOT_INITIALIZED":
            return .vaultNotInitialized(message)
        case 409:
            return .conflict(message)
        case 429:
            return .rateLimited(message)
        default:
            return .serverError(status: status, code: code, message: message)
        }
    }

    // MARK: - 1. Zero-Knowledge Auth, Setup, Sessions & Security Summary

    public func getAuthParams() async throws -> AuthParamsResponse {
        try await performJSON(path: "/api/v1/auth/params")
    }

    public func getAuthStatus() async throws -> AuthStatusResponse {
        try await performJSON(path: "/api/v1/auth/status")
    }

    public func getAuthEnvelope() async throws -> AuthEnvelopeResponse {
        try await performJSON(path: "/api/v1/auth/envelope")
    }

    public func setupAdmin(
        password: String,
        vaultName: String?,
        iterations: Int = VaultE2EECrypto.defaultPbkdf2Iterations
    ) async throws -> AuthSessionResponse {
        let bundle = try VaultE2EECrypto.createZeroKnowledgeMasterBundle(
            password: password,
            iterations: iterations
        )
        let payload = ZeroKnowledgeSetupRequest(
            vaultName: vaultName,
            kdfSalt: bundle.kdfSalt,
            kdfParams: bundle.kdfParams,
            authKey: bundle.authKey,
            wrappedDek: bundle.wrappedDek,
            keyFingerprint: bundle.keyFingerprint,
            deviceName: deviceName,
            platform: .ios
        )
        let body = try JSONEncoder().encode(payload)
        let auth: AuthSessionResponse = try await performJSON(
            path: "/api/v1/auth/setup",
            method: "POST",
            bodyData: body
        )
        self.sessionToken = auth.token
        self.masterDek = bundle.dek
        return auth
    }

    public func login(password: String) async throws -> AuthSessionResponse {
        let params = try await getAuthParams()
        guard params.initialized,
              let kdfSalt = params.kdfSalt,
              let kdfParams = params.kdfParams else {
            throw PrivateSpaceClientError.vaultNotInitialized("私密空间尚未初始化")
        }

        let derived = try VaultE2EECrypto.deriveMasterKeysFromPassword(
            password: password,
            kdfSaltBase64: kdfSalt,
            kdfParams: kdfParams
        )
        let payload = ZeroKnowledgeLoginRequest(
            authKey: derived.authKeyBase64,
            deviceName: deviceName,
            platform: .ios
        )
        let body = try JSONEncoder().encode(payload)
        let auth: AuthSessionResponse = try await performJSON(
            path: "/api/v1/auth/login",
            method: "POST",
            bodyData: body
        )
        let dek = try VaultE2EECrypto.unwrapMasterDek(wrappedDek: auth.wrappedDek, kek: derived.kek)
        self.sessionToken = auth.token
        self.masterDek = dek
        return auth
    }

    public func logout() async {
        struct OkResp: Decodable { let ok: Bool }
        _ = try? await performJSON(path: "/api/v1/auth/logout", method: "POST") as OkResp
        self.sessionToken = nil
        self.masterDek = nil
    }

    public func changeMasterPassword(_ input: ChangePasswordRequest) async throws -> ChangePasswordResponse {
        let envelope = try await getAuthEnvelope()
        let unlocked = try VaultE2EECrypto.unlockZeroKnowledgeMasterBundle(
            password: input.currentPassword,
            kdfSaltBase64: envelope.kdfSalt,
            kdfParams: envelope.kdfParams,
            wrappedDek: envelope.wrappedDek
        )
        let rotated = try VaultE2EECrypto.createZeroKnowledgeMasterBundle(
            password: input.newPassword,
            existingDek: unlocked.dek,
            iterations: envelope.kdfParams.iterations
        )
        let wireReq = ZeroKnowledgeChangePasswordRequest(
            currentAuthKey: unlocked.authKey,
            newAuthKey: rotated.authKey,
            newKdfSalt: rotated.kdfSalt,
            newKdfParams: rotated.kdfParams,
            newWrappedDek: rotated.wrappedDek,
            keyFingerprint: rotated.keyFingerprint,
            revokeOtherSessions: input.revokeOtherSessions
        )
        let body = try JSONEncoder().encode(wireReq)
        let resp: ChangePasswordResponse = try await performJSON(
            path: "/api/v1/auth/change-password",
            method: "POST",
            bodyData: body
        )
        self.masterDek = unlocked.dek
        return resp
    }

    public func updateVaultName(_ vaultName: String) async throws -> String {
        struct Resp: Decodable { let vaultName: String }
        let body = try JSONEncoder().encode(UpdateVaultSettingsRequest(vaultName: vaultName))
        let res: Resp = try await performJSON(
            path: "/api/v1/auth/settings",
            method: "PATCH",
            bodyData: body
        )
        return res.vaultName
    }

    public func getSecuritySummary() async throws -> VaultSecuritySummary {
        try await performJSON(path: "/api/v1/auth/security")
    }

    public func listSessions() async throws -> [SessionInfo] {
        struct Resp: Decodable { let sessions: [SessionInfo] }
        let res: Resp = try await performJSON(path: "/api/v1/auth/sessions")
        return res.sessions
    }

    public func revokeSession(id: String) async throws {
        struct Resp: Decodable { let ok: Bool }
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        _ = try await performJSON(path: "/api/v1/auth/sessions/\(encoded)", method: "DELETE") as Resp
    }

    // MARK: - 2. Zero-Knowledge Encrypted Text Notes

    public func createNote(_ input: CreateNoteRequest) async throws -> NoteItem {
        let dek = try requireUnlockedDek()
        let id = (input.id?.isEmpty == false) ? input.id! : UUID().uuidString.lowercased()
        let rawContent = input.content ?? ""
        let summary = VaultE2EECrypto.summarizeNoteText(title: input.title ?? "", content: rawContent)
        let payload = NoteDecryptedPayload(
            title: summary.cleanTitle,
            content: rawContent,
            excerpt: summary.excerpt,
            tags: VaultE2EECrypto.normalizeTags(input.tags ?? []),
            format: input.format ?? .markdown,
            wordCount: summary.wordCount
        )
        let envelope = try VaultE2EECrypto.encryptItemPayload(
            dek: dek,
            itemId: id,
            itemType: .note,
            revision: 1,
            payload: payload
        )
        let wireReq = CreateEncryptedItemRequest(
            id: id,
            isPinned: input.isPinned ?? false,
            revision: 1,
            envelope: envelope
        )
        struct Resp: Decodable { let item: EncryptedVaultRecordDto }
        let body = try JSONEncoder().encode(wireReq)
        let res: Resp = try await performJSON(path: "/api/v1/notes", method: "POST", bodyData: body)
        return try VaultE2EECrypto.hydrateDecryptedNote(dek: dek, record: res.item)
    }

    public func updateNote(id: String, patch: UpdateNoteRequest) async throws -> NoteItem {
        let dek = try requireUnlockedDek()
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        struct GetResp: Decodable { let item: EncryptedVaultRecordDto }
        let fetched: GetResp = try await performJSON(path: "/api/v1/notes/\(encoded)")
        let current = try VaultE2EECrypto.hydrateDecryptedNote(dek: dek, record: fetched.item)

        let nextContent = patch.content ?? current.content
        let nextRawTitle = patch.title ?? current.title
        let summary = VaultE2EECrypto.summarizeNoteText(title: nextRawTitle, content: nextContent)
        let nextPayload = NoteDecryptedPayload(
            title: summary.cleanTitle,
            content: nextContent,
            excerpt: summary.excerpt,
            tags: patch.tags.map(VaultE2EECrypto.normalizeTags) ?? current.tags,
            format: patch.format ?? current.format,
            wordCount: summary.wordCount
        )
        let nextRevision = current.revision + 1
        let envelope = try VaultE2EECrypto.encryptItemPayload(
            dek: dek,
            itemId: id,
            itemType: .note,
            revision: nextRevision,
            payload: nextPayload
        )
        let wirePatch = UpdateEncryptedItemRequest(
            isPinned: patch.isPinned,
            isArchived: patch.isArchived,
            isTrashed: patch.isTrashed,
            expectedRevision: patch.expectedRevision ?? current.revision,
            revision: nextRevision,
            envelope: envelope
        )
        let body = try JSONEncoder().encode(wirePatch)
        let updated: GetResp = try await performJSON(
            path: "/api/v1/notes/\(encoded)",
            method: "PATCH",
            bodyData: body
        )
        return try VaultE2EECrypto.hydrateDecryptedNote(dek: dek, record: updated.item)
    }

    public func deleteNotePermanently(id: String) async throws {
        struct Resp: Decodable { let ok: Bool }
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        _ = try await performJSON(path: "/api/v1/notes/\(encoded)", method: "DELETE") as Resp
    }

    public func emptyNoteTrash() async throws -> Int {
        struct Resp: Decodable { let ok: Bool; let purgedCount: Int }
        let res: Resp = try await performJSON(path: "/api/v1/notes/trash", method: "DELETE")
        return res.purgedCount
    }

    // MARK: - 3. Zero-Knowledge Encrypted Passwords & 2FA

    public func createPassword(_ input: CreatePasswordRequest) async throws -> PasswordItem {
        let dek = try requireUnlockedDek()
        let id = (input.id?.isEmpty == false) ? input.id! : UUID().uuidString.lowercased()
        let nowIso = ISO8601DateFormatter().string(from: Date())
        let payload = PasswordDecryptedPayload(
            title: input.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "未命名账号" : input.title.trimmingCharacters(in: .whitespacesAndNewlines),
            username: (input.username ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
            password: input.password,
            url: (input.url ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
            totpSecret: (input.totpSecret ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
            category: input.category ?? .login,
            notes: input.notes ?? "",
            tags: VaultE2EECrypto.normalizeTags(input.tags ?? []),
            customFields: VaultE2EECrypto.sanitizeCustomFields(input.customFields ?? []),
            history: [],
            passwordChangedAt: nowIso
        )
        let envelope = try VaultE2EECrypto.encryptItemPayload(
            dek: dek,
            itemId: id,
            itemType: .password,
            revision: 1,
            payload: payload
        )
        let wireReq = CreateEncryptedItemRequest(
            id: id,
            isPinned: input.isPinned ?? false,
            revision: 1,
            envelope: envelope
        )
        struct Resp: Decodable { let item: EncryptedVaultRecordDto }
        let body = try JSONEncoder().encode(wireReq)
        let res: Resp = try await performJSON(path: "/api/v1/passwords", method: "POST", bodyData: body)
        return try VaultE2EECrypto.hydrateDecryptedPassword(dek: dek, record: res.item)
    }

    public func importPasswords(_ entries: [ImportPasswordEntryInput]) async throws -> [PasswordItem] {
        let dek = try requireUnlockedDek()
        let nowIso = ISO8601DateFormatter().string(from: Date())
        var encryptedItems: [CreateEncryptedItemRequest] = []
        encryptedItems.reserveCapacity(entries.count)

        for entry in entries {
            let id = UUID().uuidString.lowercased()
            let payload = PasswordDecryptedPayload(
                title: entry.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "导入账号" : entry.title.trimmingCharacters(in: .whitespacesAndNewlines),
                username: (entry.username ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
                password: entry.password,
                url: (entry.url ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
                totpSecret: (entry.totpSecret ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
                category: entry.category ?? .login,
                notes: entry.notes ?? "",
                tags: VaultE2EECrypto.normalizeTags(entry.tags ?? []),
                customFields: [],
                history: [],
                passwordChangedAt: nowIso
            )
            let envelope = try VaultE2EECrypto.encryptItemPayload(
                dek: dek,
                itemId: id,
                itemType: .password,
                revision: 1,
                payload: payload
            )
            encryptedItems.append(CreateEncryptedItemRequest(id: id, isPinned: false, revision: 1, envelope: envelope))
        }

        struct Resp: Decodable { let items: [EncryptedVaultRecordDto]; let count: Int }
        let body = try JSONEncoder().encode(BatchCreateEncryptedItemsRequest(items: encryptedItems))
        let res: Resp = try await performJSON(
            path: "/api/v1/passwords/import",
            method: "POST",
            bodyData: body
        )
        return try res.items.map { try VaultE2EECrypto.hydrateDecryptedPassword(dek: dek, record: $0) }
    }

    public func updatePassword(id: String, patch: UpdatePasswordRequest) async throws -> PasswordItem {
        let dek = try requireUnlockedDek()
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        struct GetResp: Decodable { let item: EncryptedVaultRecordDto }
        let fetched: GetResp = try await performJSON(path: "/api/v1/passwords/\(encoded)")
        let current = try VaultE2EECrypto.hydrateDecryptedPassword(dek: dek, record: fetched.item)

        let nowIso = ISO8601DateFormatter().string(from: Date())
        let nextPassword = patch.password ?? current.password
        var nextHistory = current.history
        var nextChangedAt = current.passwordChangedAt
        if let updatedPwd = patch.password, updatedPwd != current.password {
            nextHistory.insert(
                PasswordHistoryEntry(password: current.password, changedAt: current.passwordChangedAt),
                at: 0
            )
            if nextHistory.count > 10 {
                nextHistory = Array(nextHistory.prefix(10))
            }
            nextChangedAt = nowIso
        }

        let nextTitle = (patch.title ?? current.title).trimmingCharacters(in: .whitespacesAndNewlines)
        let nextPayload = PasswordDecryptedPayload(
            title: nextTitle.isEmpty ? "未命名账号" : nextTitle,
            username: (patch.username ?? current.username).trimmingCharacters(in: .whitespacesAndNewlines),
            password: nextPassword,
            url: (patch.url ?? current.url).trimmingCharacters(in: .whitespacesAndNewlines),
            totpSecret: (patch.totpSecret ?? current.totpSecret).trimmingCharacters(in: .whitespacesAndNewlines),
            category: patch.category ?? current.category,
            notes: patch.notes ?? current.notes,
            tags: patch.tags.map(VaultE2EECrypto.normalizeTags) ?? current.tags,
            customFields: patch.customFields.map(VaultE2EECrypto.sanitizeCustomFields) ?? current.customFields,
            history: nextHistory,
            passwordChangedAt: nextChangedAt
        )
        let nextRevision = current.revision + 1
        let envelope = try VaultE2EECrypto.encryptItemPayload(
            dek: dek,
            itemId: id,
            itemType: .password,
            revision: nextRevision,
            payload: nextPayload
        )
        let wirePatch = UpdateEncryptedItemRequest(
            isPinned: patch.isPinned,
            isArchived: patch.isArchived,
            isTrashed: patch.isTrashed,
            expectedRevision: patch.expectedRevision ?? current.revision,
            revision: nextRevision,
            envelope: envelope
        )
        let body = try JSONEncoder().encode(wirePatch)
        let updated: GetResp = try await performJSON(
            path: "/api/v1/passwords/\(encoded)",
            method: "PATCH",
            bodyData: body
        )
        return try VaultE2EECrypto.hydrateDecryptedPassword(dek: dek, record: updated.item)
    }

    public func deletePasswordPermanently(id: String) async throws {
        struct Resp: Decodable { let ok: Bool }
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        _ = try await performJSON(path: "/api/v1/passwords/\(encoded)", method: "DELETE") as Resp
    }

    public func emptyPasswordTrash() async throws -> Int {
        struct Resp: Decodable { let ok: Bool; let purgedCount: Int }
        let res: Resp = try await performJSON(path: "/api/v1/passwords/trash", method: "DELETE")
        return res.purgedCount
    }

    // MARK: - 4. Zero-Knowledge Encrypted Images, Streaming Videos & Resumable PSENC001 Upload

    public func createAlbum(_ input: CreateAlbumRequest) async throws -> MediaAlbum {
        let dek = try requireUnlockedDek()
        let id = UUID().uuidString.lowercased()
        let payload = MediaAlbumDecryptedPayload(
            name: input.name.trimmingCharacters(in: .whitespacesAndNewlines),
            description: input.description ?? "",
            kind: input.kind ?? "mixed",
            coverMediaId: input.coverMediaId
        )
        let envelope = try VaultE2EECrypto.encryptItemPayload(
            dek: dek,
            itemId: id,
            itemType: .album,
            revision: 1,
            payload: payload
        )
        let wireReq = CreateEncryptedAlbumRequest(id: id, revision: 1, envelope: envelope)
        struct Resp: Decodable { let album: EncryptedAlbumRecordDto }
        let body = try JSONEncoder().encode(wireReq)
        let res: Resp = try await performJSON(
            path: "/api/v1/media/albums",
            method: "POST",
            bodyData: body
        )
        return try VaultE2EECrypto.hydrateDecryptedAlbum(dek: dek, record: res.album)
    }

    public func deleteAlbum(id: String) async throws {
        struct Resp: Decodable { let ok: Bool }
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        _ = try await performJSON(path: "/api/v1/media/albums/\(encoded)", method: "DELETE") as Resp
    }

    public func fetchEncryptedMediaRecord(id: String) async throws -> EncryptedVaultRecordDto {
        struct Resp: Decodable { let item: EncryptedVaultRecordDto }
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        let res: Resp = try await performJSON(path: "/api/v1/media/\(encoded)")
        return res.item
    }

    public func updateMedia(id: String, patch: UpdateMediaRequest) async throws -> MediaItem {
        let dek = try requireUnlockedDek()
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        let record = try await fetchEncryptedMediaRecord(id: id)
        let current = try VaultE2EECrypto.hydrateDecryptedMedia(dek: dek, record: record)

        let nextAlbumId: String?
        if let albumWrapped = patch.albumId {
            nextAlbumId = albumWrapped
        } else {
            nextAlbumId = current.albumId
        }

        let nextTitle = (patch.title ?? current.title).trimmingCharacters(in: .whitespacesAndNewlines)
        let nextPayload = MediaDecryptedPayload(
            title: nextTitle.isEmpty ? current.originalFilename : nextTitle,
            originalFilename: current.originalFilename,
            mimeType: current.mimeType,
            albumId: nextAlbumId,
            tags: patch.tags.map(VaultE2EECrypto.normalizeTags) ?? current.tags,
            description: patch.description ?? current.description,
            width: current.width,
            height: current.height,
            durationMs: current.durationMs,
            videoCodec: current.videoCodec,
            audioCodec: current.audioCodec,
            bitrate: current.bitrate,
            sha256: current.sha256,
            thumbnailMimeType: current.thumbnailMimeType,
            takenAt: current.takenAt
        )

        let nextRevision = current.revision + 1
        let cipherDomain: VaultCipherDomain = current.itemType == .video ? .video : .image
        let envelope = try VaultE2EECrypto.encryptItemPayload(
            dek: dek,
            itemId: id,
            itemType: cipherDomain,
            revision: nextRevision,
            payload: nextPayload
        )
        let wirePatch = UpdateEncryptedItemRequest(
            isPinned: patch.isPinned,
            isArchived: patch.isArchived,
            isTrashed: patch.isTrashed,
            expectedRevision: patch.expectedRevision ?? current.revision,
            revision: nextRevision,
            envelope: envelope
        )
        struct Resp: Decodable { let item: EncryptedVaultRecordDto }
        let body = try JSONEncoder().encode(wirePatch)
        let res: Resp = try await performJSON(
            path: "/api/v1/media/\(encoded)",
            method: "PATCH",
            bodyData: body
        )
        return try VaultE2EECrypto.hydrateDecryptedMedia(dek: dek, record: res.item)
    }

    public func deleteMediaPermanently(id: String) async throws {
        struct Resp: Decodable { let ok: Bool }
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        _ = try await performJSON(path: "/api/v1/media/\(encoded)", method: "DELETE") as Resp
    }

    public func emptyMediaTrash(kind: MediaKind) async throws -> Int {
        struct Resp: Decodable { let ok: Bool; let purgedCount: Int }
        let res: Resp = try await performJSON(
            path: "/api/v1/media/trash?kind=\(kind.rawValue)",
            method: "DELETE"
        )
        return res.purgedCount
    }

    /// Client-side PSENC001 resumable chunked upload (`64 KiB` AEAD sub-chunks + SHA-256 plaintext integrity).
    public func uploadMediaResumable(
        data: Data,
        filename: String,
        mimeType: String,
        kind: MediaKind? = nil,
        title: String? = nil,
        albumId: String? = nil,
        tags: [String] = [],
        description: String = "",
        existingUploadId: String? = nil,
        chunkBytes: Int = 512 * 1024,
        onProgress: (@Sendable (Int, Int) -> Void)? = nil
    ) async throws -> MediaItem {
        let dek = try requireUnlockedDek()
        let resolvedKind: MediaKind = kind ?? (mimeType.lowercased().hasPrefix("video/") ? .video : .image)
        let psencChunkSize = VaultE2EECrypto.defaultMediaChunkSize
        let alignedPartBytes = max(
            psencChunkSize,
            ((max(psencChunkSize, chunkBytes) + psencChunkSize - 1) / psencChunkSize) * psencChunkSize
        )

        let totalPlainBytes = data.count
        let (psencChunkCount, totalEncryptedBytes) = VaultE2EECrypto.computePsencEncryptedSize(
            plainSize: totalPlainBytes,
            chunkPlainSize: psencChunkSize
        )
        let sha256Hex = VaultE2EECrypto.sha256Hex(data)
        let takenAt = ISO8601DateFormatter().string(from: Date())
        let probed = VaultE2EECrypto.probeMediaMetadata(data: data, mimeType: mimeType)

        let mainBlobId = VaultE2EECrypto.generateBlobId()
        let fek = VaultE2EECrypto.randomBytes(32)
        let baseNonce = VaultE2EECrypto.randomBytes(12)
        let wrappedFek = try VaultE2EECrypto.wrapBlobFek(dek: dek, fek: fek, blobId: mainBlobId)

        var uploadId: String
        var resolvedPartPlainBytes = alignedPartBytes
        var totalParts = max(1, (totalPlainBytes + alignedPartBytes - 1) / alignedPartBytes)
        var receivedSet = Set<Int>()

        if let existingUploadId, !existingUploadId.isEmpty {
            let encoded = existingUploadId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? existingUploadId
            let status: EncryptedResumableUploadStatusResponse = try await performJSON(
                path: "/api/v1/media/uploads/\(encoded)"
            )
            uploadId = status.uploadId
            resolvedPartPlainBytes = status.chunkBytes
            totalParts = status.totalChunks
            receivedSet = Set(status.receivedChunks)
        } else {
            let clientSessionId = UUID().uuidString.lowercased()
            let sessionMeta = UploadSessionDecryptedMeta(
                filename: filename,
                mimeType: mimeType,
                title: title,
                albumId: albumId,
                tags: tags,
                description: description,
                sha256: sha256Hex,
                takenAt: takenAt
            )
            let metaEnvelope = try VaultE2EECrypto.encryptItemPayload(
                dek: dek,
                itemId: clientSessionId,
                itemType: .upload,
                revision: 1,
                payload: sessionMeta
            )
            let initPayload = EncryptedResumableUploadInitRequest(
                uploadId: clientSessionId,
                kind: resolvedKind,
                totalPlainBytes: totalPlainBytes,
                totalEncryptedBytes: totalEncryptedBytes,
                partPlainBytes: resolvedPartPlainBytes,
                totalParts: totalParts,
                metaEnvelope: metaEnvelope
            )
            let body = try JSONEncoder().encode(initPayload)
            let initResp: EncryptedResumableUploadInitResponse = try await performJSON(
                path: "/api/v1/media/uploads/init",
                method: "POST",
                bodyData: body
            )
            uploadId = initResp.uploadId
            resolvedPartPlainBytes = initResp.partPlainBytes
            totalParts = initResp.totalParts
        }

        let encodedUploadId = uploadId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? uploadId

        for index in 0..<totalParts {
            if receivedSet.contains(index) {
                continue
            }
            let start = index * resolvedPartPlainBytes
            let end = min(totalPlainBytes, start + resolvedPartPlainBytes)
            let plainPart = totalPlainBytes > 0 ? data.subdata(in: start..<end) : Data()
            let encryptedPart = try VaultE2EECrypto.encryptResumableMediaPart(
                fek: fek,
                blobId: mainBlobId,
                baseNonce: baseNonce,
                partPlainData: plainPart,
                partIndex: index,
                partStridePlainBytes: resolvedPartPlainBytes,
                totalPlainSize: totalPlainBytes,
                chunkPlainSize: psencChunkSize
            )

            var attempt = 0
            while true {
                do {
                    let req = try buildRequest(
                        path: "/api/v1/media/uploads/\(encodedUploadId)/chunks/\(index)",
                        method: "PUT",
                        bodyData: encryptedPart,
                        contentType: "application/octet-stream"
                    )
                    let (respData, resp) = try await session.data(for: req)
                    guard let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
                        let code = (resp as? HTTPURLResponse)?.statusCode ?? 500
                        throw decodeAPIError(status: code, data: respData)
                    }
                    break
                } catch {
                    attempt += 1
                    if attempt >= 3 { throw error }
                    try await Task.sleep(nanoseconds: UInt64(attempt) * 300_000_000)
                }
            }

            onProgress?(end, totalPlainBytes)
        }

        var thumbBlobMeta: EncryptedBlobKeyMetaDto?
        var encryptedThumbBase64: String?
        if resolvedKind == .image,
           let thumbJpeg = VaultE2EECrypto.generateThumbnailJpeg(from: data) {
            let encryptedThumb = try VaultE2EECrypto.encryptMediaBytesToPsenc(
                dek: dek,
                plainData: thumbJpeg
            )
            thumbBlobMeta = encryptedThumb.meta
            encryptedThumbBase64 = encryptedThumb.encryptedData.base64EncodedString()
        }

        let mediaId = UUID().uuidString.lowercased()
        let resolvedTitle = (title?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false)
            ? title!.trimmingCharacters(in: .whitespacesAndNewlines)
            : filename
        let mediaPayload = MediaDecryptedPayload(
            title: resolvedTitle,
            originalFilename: filename,
            mimeType: mimeType,
            albumId: albumId,
            tags: VaultE2EECrypto.normalizeTags(tags),
            description: description,
            width: probed.width,
            height: probed.height,
            durationMs: probed.durationMs,
            videoCodec: probed.videoCodec,
            audioCodec: probed.audioCodec,
            bitrate: probed.bitrate,
            sha256: sha256Hex,
            thumbnailMimeType: thumbBlobMeta != nil ? "image/jpeg" : nil,
            takenAt: takenAt
        )
        let cipherDomain: VaultCipherDomain = resolvedKind == .video ? .video : .image
        let mediaEnvelope = try VaultE2EECrypto.encryptItemPayload(
            dek: dek,
            itemId: mediaId,
            itemType: cipherDomain,
            revision: 1,
            payload: mediaPayload
        )
        let mainBlobMeta = EncryptedBlobKeyMetaDto(
            blobId: mainBlobId,
            fekSalt: wrappedFek.fekSalt,
            fekNonce: wrappedFek.fekNonce,
            fekTag: wrappedFek.fekTag,
            wrappedFek: wrappedFek.wrappedFek,
            baseNonce: baseNonce.base64EncodedString(),
            chunkSize: psencChunkSize,
            chunkCount: psencChunkCount,
            plainSize: totalPlainBytes,
            encryptedSize: totalEncryptedBytes,
            sha256: sha256Hex
        )

        let completeReq = EncryptedResumableUploadCompleteRequest(
            id: mediaId,
            kind: resolvedKind,
            isPinned: false,
            revision: 1,
            envelope: mediaEnvelope,
            mainBlob: mainBlobMeta,
            thumbBlob: thumbBlobMeta,
            encryptedThumbnailBase64: encryptedThumbBase64
        )
        struct CompleteResp: Decodable { let item: EncryptedVaultRecordDto }
        let completeBody = try JSONEncoder().encode(completeReq)
        let done: CompleteResp = try await performJSON(
            path: "/api/v1/media/uploads/\(encodedUploadId)/complete",
            method: "POST",
            bodyData: completeBody
        )
        return try VaultE2EECrypto.hydrateDecryptedMedia(dek: dek, record: done.item)
    }

    public func fetchThumbnailData(
        mediaId: String,
        revision: Int = 1,
        blobBundle: MediaBlobKeyBundleDto? = nil
    ) async throws -> Data {
        let cacheKey = "thumb:\(mediaId):\(revision)"
        if let cached = VolatileMediaMemoryCache.shared.data(forKey: cacheKey) {
            return cached
        }
        let dek = try requireUnlockedDek()
        let resolvedBundle: MediaBlobKeyBundleDto
        if let blobBundle {
            resolvedBundle = blobBundle
        } else {
            let record = try await fetchEncryptedMediaRecord(id: mediaId)
            guard let mediaBlobs = record.mediaBlobs else {
                throw PrivateSpaceClientError.e2eeDecryptionFailed("媒体缺少加密分块密钥元数据")
            }
            resolvedBundle = mediaBlobs
        }

        let targetMeta = resolvedBundle.thumbnail ?? resolvedBundle.main
        let encoded = mediaId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? mediaId
        let path = resolvedBundle.thumbnail != nil
            ? "/api/v1/media/\(encoded)/thumbnail-blob?rev=\(revision)"
            : "/api/v1/media/\(encoded)/blob?rev=\(revision)"
        let req = try buildRequest(path: path, accept: "application/octet-stream")
        let (encryptedData, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let status = (resp as? HTTPURLResponse)?.statusCode ?? 500
            throw decodeAPIError(status: status, data: encryptedData)
        }

        let plainData = try VaultE2EECrypto.decryptPsencFullBuffer(
            dek: dek,
            encryptedData: encryptedData,
            meta: targetMeta
        )
        VolatileMediaMemoryCache.shared.insert(plainData, forKey: cacheKey)
        return plainData
    }

    public func fetchFullMediaData(
        mediaId: String,
        revision: Int = 1,
        blobMeta: EncryptedBlobKeyMetaDto? = nil
    ) async throws -> Data {
        let cacheKey = "full:\(mediaId):\(revision)"
        if let cached = VolatileMediaMemoryCache.shared.data(forKey: cacheKey) {
            return cached
        }
        let dek = try requireUnlockedDek()
        let resolvedMeta: EncryptedBlobKeyMetaDto
        if let blobMeta {
            resolvedMeta = blobMeta
        } else {
            let record = try await fetchEncryptedMediaRecord(id: mediaId)
            guard let mainMeta = record.mediaBlobs?.main else {
                throw PrivateSpaceClientError.e2eeDecryptionFailed("媒体缺少主文件密钥元数据")
            }
            resolvedMeta = mainMeta
        }

        let encoded = mediaId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? mediaId
        let req = try buildRequest(
            path: "/api/v1/media/\(encoded)/blob?rev=\(revision)",
            accept: "application/octet-stream"
        )
        let (encryptedData, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let status = (resp as? HTTPURLResponse)?.statusCode ?? 500
            throw decodeAPIError(status: status, data: encryptedData)
        }

        let plainData = try VaultE2EECrypto.decryptPsencFullBuffer(
            dek: dek,
            encryptedData: encryptedData,
            meta: resolvedMeta
        )
        if plainData.count <= 16 * 1024 * 1024 {
            VolatileMediaMemoryCache.shared.insert(plainData, forKey: cacheKey)
        }
        return plainData
    }

    /// Fetches only the overlapping encrypted `.psenc` chunks via `HTTP 206 Partial Content` and decrypts
    /// the exact requested plaintext byte slice `[startPlainByte...endPlainByte]` in O(1) memory.
    public func fetchDecryptedMediaByteRange(
        mediaId: String,
        startPlainByte: Int,
        endPlainByte: Int? = nil,
        blobMeta: EncryptedBlobKeyMetaDto? = nil
    ) async throws -> Data {
        let dek = try requireUnlockedDek()
        let resolvedMeta: EncryptedBlobKeyMetaDto
        if let blobMeta {
            resolvedMeta = blobMeta
        } else {
            let record = try await fetchEncryptedMediaRecord(id: mediaId)
            guard let mainMeta = record.mediaBlobs?.main else {
                throw PrivateSpaceClientError.e2eeDecryptionFailed("媒体缺少主文件密钥元数据")
            }
            resolvedMeta = mainMeta
        }

        if resolvedMeta.plainSize == 0 {
            return Data()
        }

        let range = VaultE2EECrypto.computeEncryptedRangeForPlainRange(
            meta: resolvedMeta,
            startPlainByte: startPlainByte,
            endPlainByte: endPlainByte
        )
        let encoded = mediaId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? mediaId
        let req = try buildRequest(
            path: "/api/v1/media/\(encoded)/stream",
            accept: "application/octet-stream",
            extraHeaders: [
                "Range": "bytes=\(range.diskStart)-\(range.diskEnd)",
            ]
        )
        let (encryptedSlice, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, http.statusCode == 206 || http.statusCode == 200 else {
            let status = (resp as? HTTPURLResponse)?.statusCode ?? 500
            throw decodeAPIError(status: status, data: encryptedSlice)
        }

        let cipherPayload: Data
        if http.statusCode == 206 {
            cipherPayload = encryptedSlice
        } else {
            let endExclusive = min(encryptedSlice.count, range.diskEnd + 1)
            cipherPayload = encryptedSlice.subdata(in: range.diskStart..<endExclusive)
        }

        return try VaultE2EECrypto.decryptPsencRangeSlice(
            dek: dek,
            encryptedSlice: cipherPayload,
            meta: resolvedMeta,
            range: range
        )
    }

    /// Returns authenticated `.psenc` ciphertext stream URL and HTTP headers for direct ciphertext inspection.
    public func makeAuthenticatedStreamDescriptor(
        mediaId: String,
        revision: Int = 1
    ) throws -> (url: URL, headers: [String: String]) {
        let encoded = mediaId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? mediaId
        var query = "?rev=\(revision)"
        if let token = sessionToken,
           let encodedToken = token.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) {
            query += "&token=\(encodedToken)"
        }
        let url = try makeURL("/api/v1/media/\(encoded)/stream\(query)")
        var headers: [String: String] = [
            "User-Agent": "PrivateSpace-IOS/2.0 (\(deviceName))",
        ]
        if let token = sessionToken, !token.isEmpty {
            headers["Authorization"] = "Bearer \(token)"
        }
        return (url, headers)
    }

    // MARK: - 5. Incremental Sync (`since_seq`), Cipher Inspector & SSE Real-Time Stream

    public func pullSync(sinceSeq: Int) async throws -> SyncPullResponse {
        let dek = try requireUnlockedDek()
        let raw: EncryptedSyncPullResponse = try await performJSON(
            path: "/api/v1/sync?since_seq=\(max(0, sinceSeq))"
        )

        var notes: [NoteItem] = []
        var passwords: [PasswordItem] = []
        var media: [MediaItem] = []
        var albumItemCounts: [String: Int] = [:]

        for record in raw.items {
            switch record.itemType {
            case .note:
                notes.append(try VaultE2EECrypto.hydrateDecryptedNote(dek: dek, record: record))
            case .password:
                passwords.append(try VaultE2EECrypto.hydrateDecryptedPassword(dek: dek, record: record))
            case .image, .video:
                let item = try VaultE2EECrypto.hydrateDecryptedMedia(dek: dek, record: record)
                if !item.isTrashed, let albumId = item.albumId {
                    albumItemCounts[albumId, default: 0] += 1
                }
                media.append(item)
            }
        }

        let albums = try raw.albums.map { albumRecord in
            try VaultE2EECrypto.hydrateDecryptedAlbum(
                dek: dek,
                record: albumRecord,
                itemCount: albumItemCounts[albumRecord.id] ?? 0
            )
        }

        return SyncPullResponse(
            serverTime: raw.serverTime,
            latestSyncSeq: raw.latestSyncSeq,
            sinceSeq: raw.sinceSeq,
            notes: notes,
            passwords: passwords,
            media: media,
            albums: albums,
            deleted: raw.deleted
        )
    }

    public func inspectCipherEnvelope(itemId: String) async throws -> CipherEnvelopeInspection {
        struct Resp: Decodable { let envelope: CipherEnvelopeInspection }
        let encoded = itemId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? itemId
        let res: Resp = try await performJSON(path: "/api/v1/sync/cipher/\(encoded)")
        return res.envelope
    }

    /// Subscribes to `/api/v1/sync/stream` via W3C Server-Sent Events using raw UTF-8 byte framing.
    public func subscribeSyncEvents() throws -> AsyncThrowingStream<SyncStreamMessage, Error> {
        let req = try buildRequest(
            path: "/api/v1/sync/stream",
            method: "GET",
            accept: "text/event-stream"
        )
        let targetSession = self.streamSession

        return AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    let (bytes, response) = try await targetSession.bytes(for: req)
                    guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                        let status = (response as? HTTPURLResponse)?.statusCode ?? 500
                        throw PrivateSpaceClientError.serverError(
                            status: status,
                            code: "SSE_FAILED",
                            message: "实时同步流连接失败 (\(status))"
                        )
                    }

                    var lineBuffer: [UInt8] = []
                    var currentEvent = "message"
                    var currentDataLines: [String] = []

                    func dispatchBufferedEvent() {
                        guard !currentDataLines.isEmpty else {
                            currentEvent = "message"
                            return
                        }
                        let rawPayload = currentDataLines.joined(separator: "\n")
                        currentDataLines.removeAll(keepingCapacity: true)
                        let eventName = currentEvent
                        currentEvent = "message"

                        guard let payloadData = rawPayload.data(using: .utf8),
                              let decoded = try? JSONDecoder().decode(SyncCursorEvent.self, from: payloadData) else {
                            return
                        }
                        if eventName == "connected" {
                            continuation.yield(.connected(decoded))
                        } else if eventName == "sync_cursor" {
                            continuation.yield(.cursorChanged(decoded))
                        }
                    }

                    for try await byte in bytes {
                        if Task.isCancelled { break }
                        if byte == 0x0A { // '\n'
                            if lineBuffer.last == 0x0D {
                                lineBuffer.removeLast()
                            }
                            let line = String(decoding: lineBuffer, as: UTF8.self)
                            lineBuffer.removeAll(keepingCapacity: true)

                            if line.isEmpty {
                                dispatchBufferedEvent()
                            } else if line.hasPrefix(":") {
                                continue
                            } else if line.hasPrefix("event:") {
                                currentEvent = line.dropFirst(6).trimmingCharacters(in: .whitespaces)
                            } else if line.hasPrefix("data:") {
                                currentDataLines.append(
                                    line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                                )
                            }
                        } else {
                            lineBuffer.append(byte)
                        }
                    }

                    continuation.finish()
                } catch {
                    if !Task.isCancelled {
                        continuation.finish(throwing: error)
                    } else {
                        continuation.finish()
                    }
                }
            }

            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }
}
