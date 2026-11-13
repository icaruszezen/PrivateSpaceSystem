import CryptoKit
import Foundation

public enum SyncStreamMessage: Sendable, Equatable {
    case connected(SyncCursorEvent)
    case cursorChanged(SyncCursorEvent)
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

/// Complete PrivateSpace v1 Network, Resumable Chunked Upload, HTTP 206 Range & SSE Client for iOS.
/// Uses `URLSessionConfiguration.ephemeral` so decrypted JSON/media never leak into `URLCache` SQLite on disk.
public actor PrivateSpaceAPIClient {
    private var baseURLString: String
    private var sessionToken: String?
    private let deviceName: String
    private let session: URLSession
    private let streamSession: URLSession

    public init(
        baseURLString: String,
        sessionToken: String? = nil,
        deviceName: String = "iPhone · PrivateSpace iOS",
        urlSession: URLSession? = nil
    ) {
        self.baseURLString = Self.normalizeBaseURL(baseURLString)
        self.sessionToken = sessionToken
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
        accept: String = "application/json"
    ) throws -> URLRequest {
        let url = try makeURL(path)
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue(accept, forHTTPHeaderField: "Accept")
        req.setValue("PrivateSpace-IOS/1.0 (\(deviceName))", forHTTPHeaderField: "User-Agent")

        if let token = sessionToken, !token.isEmpty {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let bodyData {
            req.httpBody = bodyData
            req.setValue(contentType ?? "application/json", forHTTPHeaderField: "Content-Type")
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

    // MARK: - 1. Auth, Setup, Sessions & Security Summary

    public func getAuthStatus() async throws -> AuthStatusResponse {
        try await performJSON(path: "/api/v1/auth/status")
    }

    public func setupAdmin(password: String, vaultName: String?) async throws -> AuthSessionResponse {
        let payload = SetupRequest(
            password: password,
            vaultName: vaultName,
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
        return auth
    }

    public func login(password: String) async throws -> AuthSessionResponse {
        let payload = LoginRequest(
            password: password,
            deviceName: deviceName,
            platform: .ios
        )
        let body = try JSONEncoder().encode(payload)
        let auth: AuthSessionResponse = try await performJSON(
            path: "/api/v1/auth/login",
            method: "POST",
            bodyData: body
        )
        self.sessionToken = auth.token
        return auth
    }

    public func logout() async {
        struct OkResp: Decodable { let ok: Bool }
        _ = try? await performJSON(path: "/api/v1/auth/logout", method: "POST") as OkResp
        self.sessionToken = nil
    }

    public func changeMasterPassword(_ input: ChangePasswordRequest) async throws -> ChangePasswordResponse {
        let body = try JSONEncoder().encode(input)
        return try await performJSON(
            path: "/api/v1/auth/change-password",
            method: "POST",
            bodyData: body
        )
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

    // MARK: - 2. Encrypted Text Notes

    public func createNote(_ input: CreateNoteRequest) async throws -> NoteItem {
        struct Resp: Decodable { let note: NoteItem }
        let body = try JSONEncoder().encode(input)
        let res: Resp = try await performJSON(path: "/api/v1/notes", method: "POST", bodyData: body)
        return res.note
    }

    public func updateNote(id: String, patch: UpdateNoteRequest) async throws -> NoteItem {
        struct Resp: Decodable { let note: NoteItem }
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        let body = try JSONEncoder().encode(patch)
        let res: Resp = try await performJSON(
            path: "/api/v1/notes/\(encoded)",
            method: "PATCH",
            bodyData: body
        )
        return res.note
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

    // MARK: - 3. Encrypted Passwords & 2FA

    public func createPassword(_ input: CreatePasswordRequest) async throws -> PasswordItem {
        struct Resp: Decodable { let password: PasswordItem }
        let body = try JSONEncoder().encode(input)
        let res: Resp = try await performJSON(
            path: "/api/v1/passwords",
            method: "POST",
            bodyData: body
        )
        return res.password
    }

    public func importPasswords(_ entries: [ImportPasswordEntryInput]) async throws -> [PasswordItem] {
        struct Req: Encodable { let entries: [ImportPasswordEntryInput] }
        struct Resp: Decodable { let imported: [PasswordItem]; let count: Int }
        let body = try JSONEncoder().encode(Req(entries: entries))
        let res: Resp = try await performJSON(
            path: "/api/v1/passwords/import",
            method: "POST",
            bodyData: body
        )
        return res.imported
    }

    public func updatePassword(id: String, patch: UpdatePasswordRequest) async throws -> PasswordItem {
        struct Resp: Decodable { let password: PasswordItem }
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        let body = try JSONEncoder().encode(patch)
        let res: Resp = try await performJSON(
            path: "/api/v1/passwords/\(encoded)",
            method: "PATCH",
            bodyData: body
        )
        return res.password
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

    // MARK: - 4. Encrypted Images, Streaming Videos & Resumable Chunked Upload

    public func createAlbum(_ input: CreateAlbumRequest) async throws -> MediaAlbum {
        struct Resp: Decodable { let album: MediaAlbum }
        let body = try JSONEncoder().encode(input)
        let res: Resp = try await performJSON(
            path: "/api/v1/media/albums",
            method: "POST",
            bodyData: body
        )
        return res.album
    }

    public func deleteAlbum(id: String) async throws {
        struct Resp: Decodable { let ok: Bool }
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        _ = try await performJSON(path: "/api/v1/media/albums/\(encoded)", method: "DELETE") as Resp
    }

    public func updateMedia(id: String, patch: UpdateMediaRequest) async throws -> MediaItem {
        struct Resp: Decodable { let media: MediaItem }
        let encoded = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        let body = try JSONEncoder().encode(patch)
        let res: Resp = try await performJSON(
            path: "/api/v1/media/\(encoded)",
            method: "PATCH",
            bodyData: body
        )
        return res.media
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

    /// Resumable chunked media upload (`512 KiB` default chunks + `SHA-256` end-to-end integrity check).
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
        let sha256Hex = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        var uploadId: String
        var resolvedChunkBytes = max(64 * 1024, chunkBytes)
        var totalChunks: Int
        var receivedSet = Set<Int>()

        if let existingUploadId, !existingUploadId.isEmpty {
            let encoded = existingUploadId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? existingUploadId
            let status: ResumableUploadStatusResponse = try await performJSON(
                path: "/api/v1/media/uploads/\(encoded)"
            )
            uploadId = status.uploadId
            resolvedChunkBytes = status.chunkBytes
            totalChunks = status.totalChunks
            receivedSet = Set(status.receivedChunks)
        } else {
            let initPayload = ResumableUploadInitRequest(
                filename: filename,
                mimeType: mimeType,
                kind: kind,
                totalBytes: data.count,
                chunkBytes: resolvedChunkBytes,
                title: title,
                albumId: albumId,
                tags: tags,
                description: description,
                sha256: sha256Hex,
                takenAt: ISO8601DateFormatter().string(from: Date())
            )
            let body = try JSONEncoder().encode(initPayload)
            let initResp: ResumableUploadInitResponse = try await performJSON(
                path: "/api/v1/media/uploads/init",
                method: "POST",
                bodyData: body
            )
            uploadId = initResp.uploadId
            resolvedChunkBytes = initResp.chunkBytes
            totalChunks = initResp.totalChunks
        }

        let encodedUploadId = uploadId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? uploadId

        for index in 0..<totalChunks {
            if receivedSet.contains(index) {
                continue
            }
            let start = index * resolvedChunkBytes
            let end = min(data.count, start + resolvedChunkBytes)
            let chunkSlice = data.subdata(in: start..<end)

            var attempt = 0
            while true {
                do {
                    let req = try buildRequest(
                        path: "/api/v1/media/uploads/\(encodedUploadId)/chunks/\(index)",
                        method: "PUT",
                        bodyData: chunkSlice,
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

            onProgress?(end, data.count)
        }

        struct CompleteResp: Decodable { let media: MediaItem }
        let done: CompleteResp = try await performJSON(
            path: "/api/v1/media/uploads/\(encodedUploadId)/complete",
            method: "POST"
        )
        return done.media
    }

    public func fetchThumbnailData(mediaId: String, revision: Int = 1) async throws -> Data {
        let cacheKey = "thumb:\(mediaId):\(revision)"
        if let cached = VolatileMediaMemoryCache.shared.data(forKey: cacheKey) {
            return cached
        }
        let encoded = mediaId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? mediaId
        let req = try buildRequest(
            path: "/api/v1/media/\(encoded)/thumbnail?rev=\(revision)",
            accept: "image/*"
        )
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let status = (resp as? HTTPURLResponse)?.statusCode ?? 500
            throw decodeAPIError(status: status, data: data)
        }
        VolatileMediaMemoryCache.shared.insert(data, forKey: cacheKey)
        return data
    }

    public func fetchFullMediaData(mediaId: String, revision: Int = 1) async throws -> Data {
        let cacheKey = "full:\(mediaId):\(revision)"
        if let cached = VolatileMediaMemoryCache.shared.data(forKey: cacheKey) {
            return cached
        }
        let encoded = mediaId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? mediaId
        let req = try buildRequest(
            path: "/api/v1/media/\(encoded)/stream?rev=\(revision)",
            accept: "*/*"
        )
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let status = (resp as? HTTPURLResponse)?.statusCode ?? 500
            throw decodeAPIError(status: status, data: data)
        }
        if data.count <= 16 * 1024 * 1024 {
            VolatileMediaMemoryCache.shared.insert(data, forKey: cacheKey)
        }
        return data
    }

    /// Returns authenticated stream URL and HTTP headers for `AVURLAsset` HTTP 206 Partial Content playback.
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
            "User-Agent": "PrivateSpace-IOS/1.0 (\(deviceName))",
        ]
        if let token = sessionToken, !token.isEmpty {
            headers["Authorization"] = "Bearer \(token)"
        }
        return (url, headers)
    }

    // MARK: - 5. Incremental Sync (`since_seq`), Cipher Inspector & SSE Real-Time Stream

    public func pullSync(sinceSeq: Int) async throws -> SyncPullResponse {
        try await performJSON(path: "/api/v1/sync?since_seq=\(max(0, sinceSeq))")
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
                                // SSE keepalive comment
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
