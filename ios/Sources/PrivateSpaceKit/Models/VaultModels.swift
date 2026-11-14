import Foundation

// MARK: - Core Enumerations

public enum VaultItemType: String, Codable, Sendable, CaseIterable {
    case note
    case password
    case image
    case video
}

public enum VaultCipherDomain: String, Codable, Sendable, CaseIterable {
    case note
    case password
    case image
    case video
    case album
    case upload
}

public enum NoteFormat: String, Codable, Sendable, CaseIterable {
    case markdown
    case plain
}

public enum MediaKind: String, Codable, Sendable, CaseIterable {
    case image
    case video
}

public enum DevicePlatform: String, Codable, Sendable {
    case web
    case ios
    case android
    case api
}

public enum PasswordCategory: String, Codable, Sendable, CaseIterable, Identifiable {
    case login
    case finance
    case work
    case dev
    case social
    case server
    case other

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .login: return "网站登录"
        case .finance: return "金融支付"
        case .work: return "办公协作"
        case .dev: return "开发凭据"
        case .social: return "社交账号"
        case .server: return "服务器与运维"
        case .other: return "其他凭据"
        }
    }

    public var systemImage: String {
        switch self {
        case .login: return "globe"
        case .finance: return "creditcard.fill"
        case .work: return "briefcase.fill"
        case .dev: return "terminal.fill"
        case .social: return "person.2.fill"
        case .server: return "server.rack"
        case .other: return "key.fill"
        }
    }
}

// MARK: - Zero-Knowledge Auth, KDF & Envelope Contracts

public struct EncryptionSpecInfo: Codable, Sendable, Equatable {
    public let architecture: String?
    public let zeroKnowledge: Bool?
    public let cipher: String
    public let keyWrap: String
    public let itemKdf: String
    public let passwordKdf: String
    public let authProof: String?
    public let mediaStreamCipher: String?
    public let aadBound: Bool
}

public struct E2EEKdfParams: Codable, Sendable, Equatable, Hashable {
    public let algorithm: String
    public let iterations: Int
    public let hash: String
    public let dkLen: Int

    public init(
        algorithm: String = "PBKDF2-HMAC-SHA256",
        iterations: Int = 310_000,
        hash: String = "SHA-256",
        dkLen: Int = 64
    ) {
        self.algorithm = algorithm
        self.iterations = iterations
        self.hash = hash
        self.dkLen = dkLen
    }
}

public struct WrappedDekDto: Codable, Sendable, Equatable, Hashable {
    public let iv: String
    public let tag: String
    public let ciphertext: String

    public init(iv: String, tag: String, ciphertext: String) {
        self.iv = iv
        self.tag = tag
        self.ciphertext = ciphertext
    }
}

public struct SessionInfo: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: String
    public let deviceName: String
    public let platform: DevicePlatform
    public let ipAddress: String
    public let createdAt: String
    public let lastActiveAt: String
    public let expiresAt: String
    public let current: Bool
}

public struct AuthParamsResponse: Codable, Sendable, Equatable {
    public let initialized: Bool
    public let vaultName: String
    public let keyFingerprint: String?
    public let kdfSalt: String?
    public let kdfParams: E2EEKdfParams?
    public let encryption: EncryptionSpecInfo
}

public struct AuthEnvelopeResponse: Codable, Sendable, Equatable {
    public let vaultName: String
    public let keyFingerprint: String
    public let kdfSalt: String
    public let kdfParams: E2EEKdfParams
    public let wrappedDek: WrappedDekDto
}

public struct AuthStatusResponse: Codable, Sendable, Equatable {
    public let initialized: Bool
    public let authenticated: Bool
    public let vaultName: String
    public let keyFingerprint: String?
    public let kdfSalt: String?
    public let kdfParams: E2EEKdfParams?
    public let wrappedDek: WrappedDekDto?
    public let encryption: EncryptionSpecInfo
    public let session: SessionInfo?
}

/// Client-local setup input (master password is never sent over HTTP).
public struct SetupRequest: Codable, Sendable {
    public let password: String
    public let vaultName: String?
    public let deviceName: String?
    public let platform: DevicePlatform?

    public init(
        password: String,
        vaultName: String? = nil,
        deviceName: String? = nil,
        platform: DevicePlatform? = .ios
    ) {
        self.password = password
        self.vaultName = vaultName
        self.deviceName = deviceName
        self.platform = platform
    }
}

/// Client-local login input (master password is never sent over HTTP).
public struct LoginRequest: Codable, Sendable {
    public let password: String
    public let deviceName: String?
    public let platform: DevicePlatform?

    public init(
        password: String,
        deviceName: String? = nil,
        platform: DevicePlatform? = .ios
    ) {
        self.password = password
        self.deviceName = deviceName
        self.platform = platform
    }
}

/// Zero-Knowledge wire payload for `POST /api/v1/auth/setup`.
public struct ZeroKnowledgeSetupRequest: Codable, Sendable {
    public let vaultName: String?
    public let kdfSalt: String
    public let kdfParams: E2EEKdfParams
    public let authKey: String
    public let wrappedDek: WrappedDekDto
    public let keyFingerprint: String
    public let deviceName: String?
    public let platform: DevicePlatform?

    public init(
        vaultName: String?,
        kdfSalt: String,
        kdfParams: E2EEKdfParams,
        authKey: String,
        wrappedDek: WrappedDekDto,
        keyFingerprint: String,
        deviceName: String?,
        platform: DevicePlatform? = .ios
    ) {
        self.vaultName = vaultName
        self.kdfSalt = kdfSalt
        self.kdfParams = kdfParams
        self.authKey = authKey
        self.wrappedDek = wrappedDek
        self.keyFingerprint = keyFingerprint
        self.deviceName = deviceName
        self.platform = platform
    }
}

/// Zero-Knowledge wire payload for `POST /api/v1/auth/login`.
public struct ZeroKnowledgeLoginRequest: Codable, Sendable {
    public let authKey: String
    public let deviceName: String?
    public let platform: DevicePlatform?

    public init(authKey: String, deviceName: String?, platform: DevicePlatform? = .ios) {
        self.authKey = authKey
        self.deviceName = deviceName
        self.platform = platform
    }
}

public struct AuthSessionResponse: Codable, Sendable, Equatable {
    public let token: String
    public let expiresAt: String
    public let vaultName: String
    public let keyFingerprint: String
    public let kdfSalt: String
    public let kdfParams: E2EEKdfParams
    public let wrappedDek: WrappedDekDto
    public let session: SessionInfo
}

/// Client-local master password rotation input (passwords never sent over HTTP).
public struct ChangePasswordRequest: Codable, Sendable {
    public let currentPassword: String
    public let newPassword: String
    public let revokeOtherSessions: Bool

    public init(currentPassword: String, newPassword: String, revokeOtherSessions: Bool = true) {
        self.currentPassword = currentPassword
        self.newPassword = newPassword
        self.revokeOtherSessions = revokeOtherSessions
    }
}

/// Zero-Knowledge wire payload for `POST /api/v1/auth/change-password`.
public struct ZeroKnowledgeChangePasswordRequest: Codable, Sendable {
    public let currentAuthKey: String
    public let newAuthKey: String
    public let newKdfSalt: String
    public let newKdfParams: E2EEKdfParams
    public let newWrappedDek: WrappedDekDto
    public let keyFingerprint: String
    public let revokeOtherSessions: Bool

    public init(
        currentAuthKey: String,
        newAuthKey: String,
        newKdfSalt: String,
        newKdfParams: E2EEKdfParams,
        newWrappedDek: WrappedDekDto,
        keyFingerprint: String,
        revokeOtherSessions: Bool
    ) {
        self.currentAuthKey = currentAuthKey
        self.newAuthKey = newAuthKey
        self.newKdfSalt = newKdfSalt
        self.newKdfParams = newKdfParams
        self.newWrappedDek = newWrappedDek
        self.keyFingerprint = keyFingerprint
        self.revokeOtherSessions = revokeOtherSessions
    }
}

public struct ChangePasswordResponse: Codable, Sendable {
    public let ok: Bool
    public let keyFingerprint: String
    public let passwordUpdatedAt: String
}

public struct UpdateVaultSettingsRequest: Codable, Sendable {
    public let vaultName: String

    public init(vaultName: String) {
        self.vaultName = vaultName
    }
}

// MARK: - Zero-Knowledge Wire Ciphertext Envelopes

public struct CipherEnvelopeDto: Codable, Sendable, Equatable, Hashable {
    public let cipherVersion: Int
    public let itemSalt: String
    public let nonce: String
    public let authTag: String
    public let ciphertext: String

    public init(
        cipherVersion: Int = 2,
        itemSalt: String,
        nonce: String,
        authTag: String,
        ciphertext: String
    ) {
        self.cipherVersion = cipherVersion
        self.itemSalt = itemSalt
        self.nonce = nonce
        self.authTag = authTag
        self.ciphertext = ciphertext
    }
}

public struct EncryptedBlobKeyMetaDto: Codable, Sendable, Equatable, Hashable {
    public let blobId: String
    public let fekSalt: String
    public let fekNonce: String
    public let fekTag: String
    public let wrappedFek: String
    public let baseNonce: String
    public let chunkSize: Int
    public let chunkCount: Int
    public let plainSize: Int
    public let encryptedSize: Int
    public let sha256: String

    public init(
        blobId: String,
        fekSalt: String,
        fekNonce: String,
        fekTag: String,
        wrappedFek: String,
        baseNonce: String,
        chunkSize: Int,
        chunkCount: Int,
        plainSize: Int,
        encryptedSize: Int,
        sha256: String
    ) {
        self.blobId = blobId
        self.fekSalt = fekSalt
        self.fekNonce = fekNonce
        self.fekTag = fekTag
        self.wrappedFek = wrappedFek
        self.baseNonce = baseNonce
        self.chunkSize = chunkSize
        self.chunkCount = chunkCount
        self.plainSize = plainSize
        self.encryptedSize = encryptedSize
        self.sha256 = sha256
    }
}

public struct MediaBlobKeyBundleDto: Codable, Sendable, Equatable, Hashable {
    public let main: EncryptedBlobKeyMetaDto
    public let thumbnail: EncryptedBlobKeyMetaDto?

    public init(main: EncryptedBlobKeyMetaDto, thumbnail: EncryptedBlobKeyMetaDto? = nil) {
        self.main = main
        self.thumbnail = thumbnail
    }
}

public struct EncryptedVaultRecordDto: Codable, Sendable, Equatable {
    public let id: String
    public let itemType: VaultItemType
    public let isPinned: Bool
    public let isArchived: Bool
    public let isTrashed: Bool
    public let revision: Int
    public let syncSeq: Int
    public let byteSize: Int
    public let createdAt: String
    public let updatedAt: String
    public let trashedAt: String?
    public let envelope: CipherEnvelopeDto
    public let mediaBlobs: MediaBlobKeyBundleDto?
}

public struct EncryptedAlbumRecordDto: Codable, Sendable, Equatable {
    public let id: String
    public let revision: Int
    public let syncSeq: Int
    public let createdAt: String
    public let updatedAt: String
    public let envelope: CipherEnvelopeDto
}

public struct CreateEncryptedItemRequest: Codable, Sendable {
    public let id: String
    public let isPinned: Bool?
    public let revision: Int
    public let envelope: CipherEnvelopeDto

    public init(id: String, isPinned: Bool? = nil, revision: Int = 1, envelope: CipherEnvelopeDto) {
        self.id = id
        self.isPinned = isPinned
        self.revision = revision
        self.envelope = envelope
    }
}

public struct BatchCreateEncryptedItemsRequest: Codable, Sendable {
    public let items: [CreateEncryptedItemRequest]

    public init(items: [CreateEncryptedItemRequest]) {
        self.items = items
    }
}

public struct UpdateEncryptedItemRequest: Codable, Sendable {
    public let isPinned: Bool?
    public let isArchived: Bool?
    public let isTrashed: Bool?
    public let expectedRevision: Int?
    public let revision: Int
    public let envelope: CipherEnvelopeDto

    public init(
        isPinned: Bool? = nil,
        isArchived: Bool? = nil,
        isTrashed: Bool? = nil,
        expectedRevision: Int? = nil,
        revision: Int,
        envelope: CipherEnvelopeDto
    ) {
        self.isPinned = isPinned
        self.isArchived = isArchived
        self.isTrashed = isTrashed
        self.expectedRevision = expectedRevision
        self.revision = revision
        self.envelope = envelope
    }
}

public struct CreateEncryptedAlbumRequest: Codable, Sendable {
    public let id: String
    public let revision: Int
    public let envelope: CipherEnvelopeDto

    public init(id: String, revision: Int = 1, envelope: CipherEnvelopeDto) {
        self.id = id
        self.revision = revision
        self.envelope = envelope
    }
}

public struct EncryptedResumableUploadInitRequest: Codable, Sendable {
    public let uploadId: String?
    public let kind: MediaKind
    public let totalPlainBytes: Int
    public let totalEncryptedBytes: Int
    public let partPlainBytes: Int
    public let totalParts: Int
    public let metaEnvelope: CipherEnvelopeDto

    public init(
        uploadId: String? = nil,
        kind: MediaKind,
        totalPlainBytes: Int,
        totalEncryptedBytes: Int,
        partPlainBytes: Int,
        totalParts: Int,
        metaEnvelope: CipherEnvelopeDto
    ) {
        self.uploadId = uploadId
        self.kind = kind
        self.totalPlainBytes = totalPlainBytes
        self.totalEncryptedBytes = totalEncryptedBytes
        self.partPlainBytes = partPlainBytes
        self.totalParts = totalParts
        self.metaEnvelope = metaEnvelope
    }
}

public struct EncryptedResumableUploadInitResponse: Codable, Sendable {
    public let uploadId: String
    public let partPlainBytes: Int
    public let totalParts: Int
    public let totalPlainBytes: Int
    public let totalEncryptedBytes: Int
    public let expiresAt: String
}

public struct EncryptedResumableUploadStatusResponse: Codable, Sendable {
    public let uploadId: String
    public let kind: MediaKind
    public let receivedChunks: [Int]
    public let totalChunks: Int
    public let totalBytes: Int
    public let totalEncryptedBytes: Int
    public let chunkBytes: Int
    public let metaEnvelope: CipherEnvelopeDto
}

public struct EncryptedResumableUploadCompleteRequest: Codable, Sendable {
    public let id: String
    public let kind: MediaKind
    public let isPinned: Bool?
    public let revision: Int
    public let envelope: CipherEnvelopeDto
    public let mainBlob: EncryptedBlobKeyMetaDto
    public let thumbBlob: EncryptedBlobKeyMetaDto?
    public let encryptedThumbnailBase64: String?

    public init(
        id: String,
        kind: MediaKind,
        isPinned: Bool? = nil,
        revision: Int = 1,
        envelope: CipherEnvelopeDto,
        mainBlob: EncryptedBlobKeyMetaDto,
        thumbBlob: EncryptedBlobKeyMetaDto? = nil,
        encryptedThumbnailBase64: String? = nil
    ) {
        self.id = id
        self.kind = kind
        self.isPinned = isPinned
        self.revision = revision
        self.envelope = envelope
        self.mainBlob = mainBlob
        self.thumbBlob = thumbBlob
        self.encryptedThumbnailBase64 = encryptedThumbnailBase64
    }
}

public struct EncryptedSyncPullResponse: Codable, Sendable {
    public let serverTime: String
    public let latestSyncSeq: Int
    public let sinceSeq: Int
    public let items: [EncryptedVaultRecordDto]
    public let albums: [EncryptedAlbumRecordDto]
    public let deleted: [SyncTombstone]
}

// MARK: - Decrypted Client Payloads

public struct NoteDecryptedPayload: Codable, Sendable, Equatable {
    public var title: String
    public var content: String
    public var excerpt: String
    public var tags: [String]
    public var format: NoteFormat
    public var wordCount: Int

    public init(
        title: String,
        content: String,
        excerpt: String,
        tags: [String],
        format: NoteFormat,
        wordCount: Int
    ) {
        self.title = title
        self.content = content
        self.excerpt = excerpt
        self.tags = tags
        self.format = format
        self.wordCount = wordCount
    }
}

public struct PasswordDecryptedPayload: Codable, Sendable, Equatable {
    public var title: String
    public var username: String
    public var password: String
    public var url: String
    public var totpSecret: String
    public var category: PasswordCategory
    public var notes: String
    public var tags: [String]
    public var customFields: [PasswordCustomField]
    public var history: [PasswordHistoryEntry]
    public var passwordChangedAt: String

    public init(
        title: String,
        username: String,
        password: String,
        url: String,
        totpSecret: String,
        category: PasswordCategory,
        notes: String,
        tags: [String],
        customFields: [PasswordCustomField],
        history: [PasswordHistoryEntry],
        passwordChangedAt: String
    ) {
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.totpSecret = totpSecret
        self.category = category
        self.notes = notes
        self.tags = tags
        self.customFields = customFields
        self.history = history
        self.passwordChangedAt = passwordChangedAt
    }
}

public struct MediaDecryptedPayload: Codable, Sendable, Equatable {
    public var title: String
    public var originalFilename: String
    public var mimeType: String
    public var albumId: String?
    public var tags: [String]
    public var description: String
    public var width: Int
    public var height: Int
    public var durationMs: Double?
    public var videoCodec: String?
    public var audioCodec: String?
    public var bitrate: Int?
    public var sha256: String
    public var thumbnailMimeType: String?
    public var takenAt: String

    public init(
        title: String,
        originalFilename: String,
        mimeType: String,
        albumId: String?,
        tags: [String],
        description: String,
        width: Int,
        height: Int,
        durationMs: Double?,
        videoCodec: String?,
        audioCodec: String?,
        bitrate: Int?,
        sha256: String,
        thumbnailMimeType: String?,
        takenAt: String
    ) {
        self.title = title
        self.originalFilename = originalFilename
        self.mimeType = mimeType
        self.albumId = albumId
        self.tags = tags
        self.description = description
        self.width = width
        self.height = height
        self.durationMs = durationMs
        self.videoCodec = videoCodec
        self.audioCodec = audioCodec
        self.bitrate = bitrate
        self.sha256 = sha256
        self.thumbnailMimeType = thumbnailMimeType
        self.takenAt = takenAt
    }
}

public struct MediaAlbumDecryptedPayload: Codable, Sendable, Equatable {
    public var name: String
    public var description: String
    public var kind: String
    public var coverMediaId: String?

    public init(name: String, description: String, kind: String, coverMediaId: String?) {
        self.name = name
        self.description = description
        self.kind = kind
        self.coverMediaId = coverMediaId
    }
}

// MARK: - 1. Encrypted Text Notes

public struct NoteItem: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: String
    public let itemType: VaultItemType
    public var title: String
    public var content: String
    public var excerpt: String
    public var tags: [String]
    public var format: NoteFormat
    public var wordCount: Int
    public var isPinned: Bool
    public var isArchived: Bool
    public var isTrashed: Bool
    public var revision: Int
    public var syncSeq: Int
    public var byteSize: Int
    public var createdAt: String
    public var updatedAt: String
    public var trashedAt: String?

    public init(
        id: String,
        itemType: VaultItemType = .note,
        title: String,
        content: String,
        excerpt: String,
        tags: [String],
        format: NoteFormat = .markdown,
        wordCount: Int,
        isPinned: Bool = false,
        isArchived: Bool = false,
        isTrashed: Bool = false,
        revision: Int = 1,
        syncSeq: Int = 0,
        byteSize: Int = 0,
        createdAt: String,
        updatedAt: String,
        trashedAt: String? = nil
    ) {
        self.id = id
        self.itemType = itemType
        self.title = title
        self.content = content
        self.excerpt = excerpt
        self.tags = tags
        self.format = format
        self.wordCount = wordCount
        self.isPinned = isPinned
        self.isArchived = isArchived
        self.isTrashed = isTrashed
        self.revision = revision
        self.syncSeq = syncSeq
        self.byteSize = byteSize
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.trashedAt = trashedAt
    }
}

public struct CreateNoteRequest: Codable, Sendable {
    public var id: String?
    public var title: String?
    public var content: String?
    public var tags: [String]?
    public var format: NoteFormat?
    public var isPinned: Bool?

    public init(
        id: String? = nil,
        title: String? = nil,
        content: String? = nil,
        tags: [String]? = nil,
        format: NoteFormat? = .markdown,
        isPinned: Bool? = nil
    ) {
        self.id = id
        self.title = title
        self.content = content
        self.tags = tags
        self.format = format
        self.isPinned = isPinned
    }
}

public struct UpdateNoteRequest: Codable, Sendable {
    public var title: String?
    public var content: String?
    public var tags: [String]?
    public var format: NoteFormat?
    public var isPinned: Bool?
    public var isArchived: Bool?
    public var isTrashed: Bool?
    public var expectedRevision: Int?

    public init(
        title: String? = nil,
        content: String? = nil,
        tags: [String]? = nil,
        format: NoteFormat? = nil,
        isPinned: Bool? = nil,
        isArchived: Bool? = nil,
        isTrashed: Bool? = nil,
        expectedRevision: Int? = nil
    ) {
        self.title = title
        self.content = content
        self.tags = tags
        self.format = format
        self.isPinned = isPinned
        self.isArchived = isArchived
        self.isTrashed = isTrashed
        self.expectedRevision = expectedRevision
    }
}

// MARK: - 2. Encrypted Passwords & 2FA TOTP

public struct PasswordCustomField: Codable, Sendable, Identifiable, Equatable, Hashable {
    public var id: String
    public var label: String
    public var value: String
    public var hidden: Bool

    public init(id: String = UUID().uuidString, label: String, value: String, hidden: Bool = true) {
        self.id = id
        self.label = label
        self.value = value
        self.hidden = hidden
    }
}

public struct PasswordHistoryEntry: Codable, Sendable, Equatable, Hashable {
    public let password: String
    public let changedAt: String

    public init(password: String, changedAt: String) {
        self.password = password
        self.changedAt = changedAt
    }
}

public struct PasswordItem: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: String
    public let itemType: VaultItemType
    public var title: String
    public var username: String
    public var password: String
    public var url: String
    public var totpSecret: String
    public var category: PasswordCategory
    public var notes: String
    public var tags: [String]
    public var customFields: [PasswordCustomField]
    public var history: [PasswordHistoryEntry]
    public var passwordChangedAt: String
    public var isPinned: Bool
    public var isArchived: Bool
    public var isTrashed: Bool
    public var revision: Int
    public var syncSeq: Int
    public var byteSize: Int
    public var createdAt: String
    public var updatedAt: String
    public var trashedAt: String?

    public init(
        id: String,
        itemType: VaultItemType = .password,
        title: String,
        username: String = "",
        password: String,
        url: String = "",
        totpSecret: String = "",
        category: PasswordCategory = .login,
        notes: String = "",
        tags: [String] = [],
        customFields: [PasswordCustomField] = [],
        history: [PasswordHistoryEntry] = [],
        passwordChangedAt: String,
        isPinned: Bool = false,
        isArchived: Bool = false,
        isTrashed: Bool = false,
        revision: Int = 1,
        syncSeq: Int = 1,
        byteSize: Int = 0,
        createdAt: String,
        updatedAt: String,
        trashedAt: String? = nil
    ) {
        self.id = id
        self.itemType = itemType
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.totpSecret = totpSecret
        self.category = category
        self.notes = notes
        self.tags = tags
        self.customFields = customFields
        self.history = history
        self.passwordChangedAt = passwordChangedAt
        self.isPinned = isPinned
        self.isArchived = isArchived
        self.isTrashed = isTrashed
        self.revision = revision
        self.syncSeq = syncSeq
        self.byteSize = byteSize
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.trashedAt = trashedAt
    }
}

public struct CreatePasswordRequest: Codable, Sendable {
    public var id: String?
    public var title: String
    public var username: String?
    public var password: String
    public var url: String?
    public var totpSecret: String?
    public var category: PasswordCategory?
    public var notes: String?
    public var tags: [String]?
    public var customFields: [PasswordCustomField]?
    public var isPinned: Bool?

    public init(
        id: String? = nil,
        title: String,
        username: String? = nil,
        password: String,
        url: String? = nil,
        totpSecret: String? = nil,
        category: PasswordCategory? = .login,
        notes: String? = nil,
        tags: [String]? = nil,
        customFields: [PasswordCustomField]? = nil,
        isPinned: Bool? = nil
    ) {
        self.id = id
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.totpSecret = totpSecret
        self.category = category
        self.notes = notes
        self.tags = tags
        self.customFields = customFields
        self.isPinned = isPinned
    }
}

public struct UpdatePasswordRequest: Codable, Sendable {
    public var title: String?
    public var username: String?
    public var password: String?
    public var url: String?
    public var totpSecret: String?
    public var category: PasswordCategory?
    public var notes: String?
    public var tags: [String]?
    public var customFields: [PasswordCustomField]?
    public var isPinned: Bool?
    public var isArchived: Bool?
    public var isTrashed: Bool?
    public var expectedRevision: Int?

    public init(
        title: String? = nil,
        username: String? = nil,
        password: String? = nil,
        url: String? = nil,
        totpSecret: String? = nil,
        category: PasswordCategory? = nil,
        notes: String? = nil,
        tags: [String]? = nil,
        customFields: [PasswordCustomField]? = nil,
        isPinned: Bool? = nil,
        isArchived: Bool? = nil,
        isTrashed: Bool? = nil,
        expectedRevision: Int? = nil
    ) {
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.totpSecret = totpSecret
        self.category = category
        self.notes = notes
        self.tags = tags
        self.customFields = customFields
        self.isPinned = isPinned
        self.isArchived = isArchived
        self.isTrashed = isTrashed
        self.expectedRevision = expectedRevision
    }
}

public struct ImportPasswordEntryInput: Codable, Sendable, Equatable {
    public var title: String
    public var username: String?
    public var password: String
    public var url: String?
    public var totpSecret: String?
    public var category: PasswordCategory?
    public var notes: String?
    public var tags: [String]?

    public init(
        title: String,
        username: String? = nil,
        password: String,
        url: String? = nil,
        totpSecret: String? = nil,
        category: PasswordCategory? = .login,
        notes: String? = nil,
        tags: [String]? = nil
    ) {
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.totpSecret = totpSecret
        self.category = category
        self.notes = notes
        self.tags = tags
    }
}

// MARK: - 3. Encrypted Images, Streaming Videos & Albums

public struct MediaItem: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: String
    public let itemType: VaultItemType
    public var title: String
    public var originalFilename: String
    public var mimeType: String
    public var albumId: String?
    public var tags: [String]
    public var description: String
    public var width: Int
    public var height: Int
    public var durationMs: Double?
    public var videoCodec: String?
    public var audioCodec: String?
    public var bitrate: Int?
    public var sha256: String
    public var thumbnailMimeType: String?
    public var takenAt: String
    public var isPinned: Bool
    public var isArchived: Bool
    public var isTrashed: Bool
    public var revision: Int
    public var syncSeq: Int
    public var byteSize: Int
    public var encryptedSize: Int
    public var chunkSize: Int
    public var chunkCount: Int
    public var hasThumbnail: Bool
    public var blobKeyBundle: MediaBlobKeyBundleDto?
    public var createdAt: String
    public var updatedAt: String
    public var trashedAt: String?

    public var isVideo: Bool {
        itemType == .video
    }

    public init(
        id: String,
        itemType: VaultItemType,
        title: String,
        originalFilename: String,
        mimeType: String,
        albumId: String? = nil,
        tags: [String] = [],
        description: String = "",
        width: Int = 0,
        height: Int = 0,
        durationMs: Double? = nil,
        videoCodec: String? = nil,
        audioCodec: String? = nil,
        bitrate: Int? = nil,
        sha256: String,
        thumbnailMimeType: String? = nil,
        takenAt: String,
        isPinned: Bool = false,
        isArchived: Bool = false,
        isTrashed: Bool = false,
        revision: Int = 1,
        syncSeq: Int = 0,
        byteSize: Int,
        encryptedSize: Int,
        chunkSize: Int = 65_536,
        chunkCount: Int = 1,
        hasThumbnail: Bool = false,
        blobKeyBundle: MediaBlobKeyBundleDto? = nil,
        createdAt: String,
        updatedAt: String,
        trashedAt: String? = nil
    ) {
        self.id = id
        self.itemType = itemType
        self.title = title
        self.originalFilename = originalFilename
        self.mimeType = mimeType
        self.albumId = albumId
        self.tags = tags
        self.description = description
        self.width = width
        self.height = height
        self.durationMs = durationMs
        self.videoCodec = videoCodec
        self.audioCodec = audioCodec
        self.bitrate = bitrate
        self.sha256 = sha256
        self.thumbnailMimeType = thumbnailMimeType
        self.takenAt = takenAt
        self.isPinned = isPinned
        self.isArchived = isArchived
        self.isTrashed = isTrashed
        self.revision = revision
        self.syncSeq = syncSeq
        self.byteSize = byteSize
        self.encryptedSize = encryptedSize
        self.chunkSize = chunkSize
        self.chunkCount = chunkCount
        self.hasThumbnail = hasThumbnail
        self.blobKeyBundle = blobKeyBundle
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.trashedAt = trashedAt
    }
}

public struct MediaAlbum: Codable, Sendable, Identifiable, Equatable, Hashable {
    public let id: String
    public var revision: Int?
    public var name: String
    public var description: String
    public var kind: String
    public var coverMediaId: String?
    public var itemCount: Int
    public var syncSeq: Int
    public var createdAt: String
    public var updatedAt: String

    public init(
        id: String,
        revision: Int? = 1,
        name: String,
        description: String = "",
        kind: String = "mixed",
        coverMediaId: String? = nil,
        itemCount: Int = 0,
        syncSeq: Int = 0,
        createdAt: String,
        updatedAt: String
    ) {
        self.id = id
        self.revision = revision
        self.name = name
        self.description = description
        self.kind = kind
        self.coverMediaId = coverMediaId
        self.itemCount = itemCount
        self.syncSeq = syncSeq
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

public struct CreateAlbumRequest: Codable, Sendable {
    public var name: String
    public var description: String?
    public var kind: String?
    public var coverMediaId: String?

    public init(
        name: String,
        description: String? = nil,
        kind: String? = "mixed",
        coverMediaId: String? = nil
    ) {
        self.name = name
        self.description = description
        self.kind = kind
        self.coverMediaId = coverMediaId
    }
}

public struct UpdateMediaRequest: Encodable, Sendable {
    public var title: String?
    public var albumId: String??
    public var tags: [String]?
    public var description: String?
    public var isPinned: Bool?
    public var isArchived: Bool?
    public var isTrashed: Bool?
    public var expectedRevision: Int?

    public init(
        title: String? = nil,
        albumId: String?? = nil,
        tags: [String]? = nil,
        description: String? = nil,
        isPinned: Bool? = nil,
        isArchived: Bool? = nil,
        isTrashed: Bool? = nil,
        expectedRevision: Int? = nil
    ) {
        self.title = title
        self.albumId = albumId
        self.tags = tags
        self.description = description
        self.isPinned = isPinned
        self.isArchived = isArchived
        self.isTrashed = isTrashed
        self.expectedRevision = expectedRevision
    }

    private enum CodingKeys: String, CodingKey {
        case title, albumId, tags, description, isPinned, isArchived, isTrashed, expectedRevision
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(title, forKey: .title)
        if let albumIdWrapped = albumId {
            if let value = albumIdWrapped {
                try container.encode(value, forKey: .albumId)
            } else {
                try container.encodeNil(forKey: .albumId)
            }
        }
        try container.encodeIfPresent(tags, forKey: .tags)
        try container.encodeIfPresent(description, forKey: .description)
        try container.encodeIfPresent(isPinned, forKey: .isPinned)
        try container.encodeIfPresent(isArchived, forKey: .isArchived)
        try container.encodeIfPresent(isTrashed, forKey: .isTrashed)
        try container.encodeIfPresent(expectedRevision, forKey: .expectedRevision)
    }
}

// MARK: - 4. Cipher Envelope Inspection & Security Summary

public struct ChunkStoreInspection: Codable, Sendable, Equatable {
    public let formatMagic: String
    public let blobId: String
    public let chunkPlainBytes: Int
    public let chunkCount: Int
    public let plainBytes: Int
    public let encryptedDiskBytes: Int
    public let fekWrapInfo: String
    public let baseNonceHex: String
    public let hasEncryptedThumbnail: Bool
    public let sha256Hex: String
}

public struct CipherEnvelopeInspection: Codable, Sendable, Equatable {
    public let itemId: String
    public let itemType: VaultItemType
    public let revision: Int
    public let syncSeq: Int
    public let cipherVersion: Int
    public let algorithm: String
    public let kdfSpec: String
    public let hkdfContext: String
    public let aadJson: String
    public let saltHex: String
    public let nonceHex: String
    public let authTagHex: String
    public let ciphertextPreviewHex: String
    public let ciphertextTotalBytes: Int
    public let keyFingerprint: String
    public let sqliteColumnsCleartext: [String]
    public let sqliteColumnsEncrypted: [String]
    public let chunkStore: ChunkStoreInspection?
    public let updatedAt: String
}

public struct VaultSecuritySummary: Codable, Sendable, Equatable {
    public let vaultName: String
    public let encryption: EncryptionSpecInfo
    public let keyFingerprint: String
    public let totalNotes: Int
    public let activeNotes: Int
    public let pinnedNotes: Int
    public let archivedNotes: Int
    public let trashedNotes: Int
    public let totalPasswords: Int
    public let activePasswords: Int
    public let totalImages: Int
    public let activeImages: Int
    public let totalVideos: Int
    public let activeVideos: Int
    public let totalEncryptedBytes: Int
    public let notesEncryptedBytes: Int
    public let passwordsEncryptedBytes: Int
    public let imagesEncryptedBytes: Int
    public let videosEncryptedBytes: Int
    public let latestSyncSeq: Int
    public let createdAt: String
    public let passwordUpdatedAt: String
}

// MARK: - 5. Multi-Device Incremental Sync & Offline Snapshot

public struct SyncTombstone: Codable, Sendable, Equatable {
    public let id: String
    public let itemType: String
    public let syncSeq: Int
    public let deletedAt: String
}

public struct SyncPullResponse: Codable, Sendable {
    public let serverTime: String
    public let latestSyncSeq: Int
    public let sinceSeq: Int
    public let notes: [NoteItem]
    public let passwords: [PasswordItem]
    public let media: [MediaItem]
    public let albums: [MediaAlbum]
    public let deleted: [SyncTombstone]
}

public struct SyncCursorEvent: Codable, Sendable, Equatable {
    public let latestSyncSeq: Int
    public let itemType: String?
    public let timestamp: String?
    public let serverTime: String?
}

public enum OutboxActionKind: String, Codable, Sendable {
    case createNote
    case updateNote
    case createPassword
    case updatePassword
}

public struct OutboxOperation: Codable, Sendable, Identifiable, Equatable {
    public let id: String
    public let kind: OutboxActionKind
    public let targetItemId: String?
    public let payloadJson: Data
    public let queuedAt: String

    public init(
        id: String = UUID().uuidString,
        kind: OutboxActionKind,
        targetItemId: String? = nil,
        payloadJson: Data,
        queuedAt: String = ISO8601DateFormatter().string(from: Date())
    ) {
        self.id = id
        self.kind = kind
        self.targetItemId = targetItemId
        self.payloadJson = payloadJson
        self.queuedAt = queuedAt
    }
}

public struct MobileVaultSnapshot: Codable, Sendable, Equatable {
    public var vaultName: String
    public var keyFingerprint: String?
    public var lastSyncSeq: Int
    public var syncedAt: String?
    public var notes: [String: NoteItem]
    public var passwords: [String: PasswordItem]
    public var media: [String: MediaItem]
    public var albums: [String: MediaAlbum]
    public var pendingOutbox: [OutboxOperation]

    public init(
        vaultName: String = "PrivateSpace",
        keyFingerprint: String? = nil,
        lastSyncSeq: Int = 0,
        syncedAt: String? = nil,
        notes: [String: NoteItem] = [:],
        passwords: [String: PasswordItem] = [:],
        media: [String: MediaItem] = [:],
        albums: [String: MediaAlbum] = [:],
        pendingOutbox: [OutboxOperation] = []
    ) {
        self.vaultName = vaultName
        self.keyFingerprint = keyFingerprint
        self.lastSyncSeq = lastSyncSeq
        self.syncedAt = syncedAt
        self.notes = notes
        self.passwords = passwords
        self.media = media
        self.albums = albums
        self.pendingOutbox = pendingOutbox
    }
}

// MARK: - 6. iOS AutoFill Credential Record (App Group Encrypted Share)

public struct AutoFillCredentialRecord: Codable, Sendable, Identifiable, Equatable {
    public let id: String
    public let title: String
    public let username: String
    public let password: String
    public let url: String
    public let domain: String
    public let totpSecret: String
    public let updatedAt: String

    public init(from item: PasswordItem) {
        self.id = item.id
        self.title = item.title
        self.username = item.username
        self.password = item.password
        self.url = item.url
        self.domain = Self.extractNormalizedDomain(from: item.url)
        self.totpSecret = item.totpSecret
        self.updatedAt = item.updatedAt
    }

    public static func extractNormalizedDomain(from rawUrl: String) -> String {
        let trimmed = rawUrl.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !trimmed.isEmpty else { return "" }
        let candidate = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
        guard let host = URLComponents(string: candidate)?.host?.lowercased() else {
            return trimmed
        }
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }

    public func matches(serviceIdentifier: String) -> Bool {
        let queryDomain = Self.extractNormalizedDomain(from: serviceIdentifier)
        guard !queryDomain.isEmpty, !domain.isEmpty else { return false }
        return domain == queryDomain
            || domain.hasSuffix(".\(queryDomain)")
            || queryDomain.hasSuffix(".\(domain)")
    }
}

// MARK: - API Error Envelope

public struct ApiErrorBody: Codable, Sendable {
    public struct Detail: Codable, Sendable {
        public let code: String?
        public let message: String?
    }
    public let error: Detail?
}

public enum PrivateSpaceClientError: LocalizedError, Sendable, Equatable {
    case invalidServerURL(String)
    case unauthorized(String)
    case vaultNotInitialized(String)
    case vaultLocked
    case e2eeDecryptionFailed(String)
    case conflict(String)
    case rateLimited(String)
    case serverError(status: Int, code: String, message: String)
    case networkUnavailable(String)
    case corruptedLocalCiphertext

    public var errorDescription: String? {
        switch self {
        case .invalidServerURL(let raw):
            return "无效的服务器地址：\(raw)"
        case .unauthorized(let msg):
            return msg
        case .vaultNotInitialized(let msg):
            return msg
        case .vaultLocked:
            return "私密空间主密钥尚未在本地解锁，请输入管理员主密码"
        case .e2eeDecryptionFailed(let msg):
            return "端到端零知识加解密校验失败：\(msg)"
        case .conflict(let msg):
            return msg
        case .rateLimited(let msg):
            return msg
        case .serverError(_, _, let msg):
            return msg
        case .networkUnavailable(let msg):
            return "网络连接不可用：\(msg)"
        case .corruptedLocalCiphertext:
            return "本地加密缓存认证失败（AES-256-GCM Tag 不匹配）"
        }
    }
}
