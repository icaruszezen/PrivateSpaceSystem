import CommonCrypto
import CryptoKit
import Foundation
import Security

#if canImport(ImageIO) && canImport(CoreGraphics) && canImport(UniformTypeIdentifiers)
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers
#endif

public struct MasterKeyDerivationResult: Sendable, Equatable {
    public let kek: Data
    public let authKey: Data
    public let authKeyBase64: String
}

public struct ZeroKnowledgeMasterBundle: Sendable, Equatable {
    public let dek: Data
    public let kdfSalt: String
    public let kdfParams: E2EEKdfParams
    public let authKey: String
    public let wrappedDek: WrappedDekDto
    public let keyFingerprint: String
}

public struct UnlockedMasterBundle: Sendable, Equatable {
    public let dek: Data
    public let authKey: String
    public let keyFingerprint: String
}

public struct PsencEncryptedRange: Sendable, Equatable {
    public let clampedStart: Int
    public let clampedEnd: Int
    public let firstChunkIdx: Int
    public let lastChunkIdx: Int
    public let diskStart: Int
    public let diskEnd: Int
}

public struct ProbedMediaInfo: Sendable, Equatable {
    public let width: Int
    public let height: Int
    public let durationMs: Double?
    public let videoCodec: String?
    public let audioCodec: String?
    public let bitrate: Int?
}

/// Cross-platform Zero-Knowledge E2EE v2 cryptographic engine for iOS & macOS.
/// Byte-for-byte wire-compatible with `src/shared/e2ee.ts` (Web & Android clients).
public enum VaultE2EECrypto {
    public static let cipherVersion = 2
    public static let defaultPbkdf2Iterations = 310_000
    public static let minPbkdf2Iterations = 10_000
    public static let maxPbkdf2Iterations = 2_000_000

    public static let psencMagic = Data("PSENC001".utf8)
    public static let psencHeaderSize = 20
    public static let psencTagSize = 16
    public static let defaultMediaChunkSize = 64 * 1024 // 64 KiB

    private static let dekWrapAad = Data("privatespace:e2ee:dek:v2".utf8)
    private static let authKeyHkdfInfo = Data("privatespace:e2ee:auth-key:v2".utf8)
    private static let keyFingerprintContext = Data("privatespace:key-fingerprint:v1".utf8)

    // MARK: - Randomness & Hex Helpers

    public static func randomBytes(_ count: Int) -> Data {
        guard count > 0 else { return Data() }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buf -> Int32 in
            guard let base = buf.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        if status != errSecSuccess {
            let fallback = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
            var out = Data()
            while out.count < count {
                out.append(fallback)
            }
            return out.subdata(in: 0..<count)
        }
        return data
    }

    public static func generateBlobId() -> String {
        bytesToHex(randomBytes(16))
    }

    public static func bytesToHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - 1. Master Key Derivation & Zero-Knowledge Envelope

    public static func pbkdf2HmacSha256(
        passwordUtf8: Data,
        salt: Data,
        iterations: Int,
        keyByteCount: Int = 64
    ) throws -> Data {
        guard !passwordUtf8.isEmpty, salt.count >= 16, keyByteCount > 0 else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("无效的 PBKDF2 口令或盐值长度")
        }

        var derived = Data(count: keyByteCount)
        let status: CCCryptorStatus = derived.withUnsafeMutableBytes { derivedBuf in
            salt.withUnsafeBytes { saltBuf in
                passwordUtf8.withUnsafeBytes { passBuf in
                    guard let outPtr = derivedBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                          let saltPtr = saltBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                          let passPtr = passBuf.baseAddress?.assumingMemoryBound(to: Int8.self) else {
                        return CCCryptorStatus(kCCParamError)
                    }
                    return CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passPtr,
                        passwordUtf8.count,
                        saltPtr,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        outPtr,
                        keyByteCount
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("PBKDF2-HMAC-SHA256 派生失败 (\(status))")
        }
        return derived
    }

    public static func deriveMasterKeysFromPassword(
        password: String,
        kdfSalt: Data,
        kdfParams: E2EEKdfParams = E2EEKdfParams()
    ) throws -> MasterKeyDerivationResult {
        guard !password.isEmpty else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("管理员主密码不能为空")
        }
        guard kdfSalt.count >= 16 else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("KDF 盐值长度不足 16 字节")
        }

        let clampedIterations = max(
            minPbkdf2Iterations,
            min(maxPbkdf2Iterations, kdfParams.iterations > 0 ? kdfParams.iterations : defaultPbkdf2Iterations)
        )
        let normalizedUtf8 = Data(password.precomposedStringWithCompatibilityMapping.utf8)
        let masterSeed = try pbkdf2HmacSha256(
            passwordUtf8: normalizedUtf8,
            salt: kdfSalt,
            iterations: clampedIterations,
            keyByteCount: 64
        )

        let kek = masterSeed.subdata(in: 0..<32)
        let authSeed = masterSeed.subdata(in: 32..<64)
        let authSymKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: authSeed),
            salt: kdfSalt,
            info: authKeyHkdfInfo,
            outputByteCount: 32
        )
        let authKey = authSymKey.withUnsafeBytes { Data($0) }

        return MasterKeyDerivationResult(
            kek: kek,
            authKey: authKey,
            authKeyBase64: authKey.base64EncodedString()
        )
    }

    public static func deriveMasterKeysFromPassword(
        password: String,
        kdfSaltBase64: String,
        kdfParams: E2EEKdfParams = E2EEKdfParams()
    ) throws -> MasterKeyDerivationResult {
        guard let saltData = Data(base64Encoded: kdfSaltBase64) else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("KDF Salt Base64 解码失败")
        }
        return try deriveMasterKeysFromPassword(password: password, kdfSalt: saltData, kdfParams: kdfParams)
    }

    public static func computeKeyFingerprint(dek: Data) throws -> String {
        guard dek.count == 32 else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("DEK 长度必须为 32 字节")
        }
        let mac = HMAC<SHA256>.authenticationCode(
            for: keyFingerprintContext,
            using: SymmetricKey(data: dek)
        )
        let hex = Data(mac).map { String(format: "%02X", $0) }.joined()
        let g1 = hex.prefix(4)
        let g2 = hex.dropFirst(4).prefix(4)
        let g3 = hex.dropFirst(8).prefix(4)
        return "\(g1)-\(g2)-\(g3)"
    }

    public static func wrapMasterDek(
        dek: Data,
        kek: Data,
        customIv: Data? = nil
    ) throws -> WrappedDekDto {
        guard dek.count == 32, kek.count == 32 else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("DEK 与 KEK 长度必须均为 32 字节")
        }
        let iv = customIv ?? randomBytes(12)
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealed = try AES.GCM.seal(
            dek,
            using: SymmetricKey(data: kek),
            nonce: nonce,
            authenticating: dekWrapAad
        )
        return WrappedDekDto(
            iv: iv.base64EncodedString(),
            tag: sealed.tag.base64EncodedString(),
            ciphertext: sealed.ciphertext.base64EncodedString()
        )
    }

    public static func unwrapMasterDek(wrappedDek: WrappedDekDto, kek: Data) throws -> Data {
        guard kek.count == 32 else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("KEK 长度必须为 32 字节")
        }
        guard let iv = Data(base64Encoded: wrappedDek.iv),
              let tag = Data(base64Encoded: wrappedDek.tag),
              let ciphertext = Data(base64Encoded: wrappedDek.ciphertext) else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("WrappedDek Base64 解码失败")
        }

        do {
            let nonce = try AES.GCM.Nonce(data: iv)
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            let dek = try AES.GCM.open(box, using: SymmetricKey(data: kek), authenticating: dekWrapAad)
            guard dek.count == 32 else {
                throw PrivateSpaceClientError.e2eeDecryptionFailed("解封后的 DEK 长度异常")
            }
            return dek
        } catch {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("主密码错误或 DEK 密文信封认证失败")
        }
    }

    public static func createZeroKnowledgeMasterBundle(
        password: String,
        existingDek: Data? = nil,
        iterations: Int = defaultPbkdf2Iterations
    ) throws -> ZeroKnowledgeMasterBundle {
        let dek = existingDek ?? randomBytes(32)
        guard dek.count == 32 else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("DEK 长度必须为 32 字节")
        }
        let kdfSalt = randomBytes(32)
        let kdfParams = E2EEKdfParams(
            algorithm: "PBKDF2-HMAC-SHA256",
            iterations: iterations,
            hash: "SHA-256",
            dkLen: 64
        )
        let derived = try deriveMasterKeysFromPassword(
            password: password,
            kdfSalt: kdfSalt,
            kdfParams: kdfParams
        )
        let wrappedDek = try wrapMasterDek(dek: dek, kek: derived.kek)
        let fingerprint = try computeKeyFingerprint(dek: dek)

        return ZeroKnowledgeMasterBundle(
            dek: dek,
            kdfSalt: kdfSalt.base64EncodedString(),
            kdfParams: kdfParams,
            authKey: derived.authKeyBase64,
            wrappedDek: wrappedDek,
            keyFingerprint: fingerprint
        )
    }

    public static func unlockZeroKnowledgeMasterBundle(
        password: String,
        kdfSaltBase64: String,
        kdfParams: E2EEKdfParams,
        wrappedDek: WrappedDekDto
    ) throws -> UnlockedMasterBundle {
        let derived = try deriveMasterKeysFromPassword(
            password: password,
            kdfSaltBase64: kdfSaltBase64,
            kdfParams: kdfParams
        )
        let dek = try unwrapMasterDek(wrappedDek: wrappedDek, kek: derived.kek)
        let fingerprint = try computeKeyFingerprint(dek: dek)
        return UnlockedMasterBundle(
            dek: dek,
            authKey: derived.authKeyBase64,
            keyFingerprint: fingerprint
        )
    }

    // MARK: - 2. Per-Item HKDF-SHA256 + AES-256-GCM AEAD Record Encryption

    public static func buildItemHkdfInfo(
        itemId: String,
        itemType: VaultCipherDomain,
        version: Int = cipherVersion
    ) -> String {
        "privatespace:item:v\(version):\(itemType.rawValue):\(itemId)"
    }

    private static func encodeCanonicalJsonString(_ value: String) -> String {
        if let encoded = try? JSONEncoder().encode(value),
           let str = String(data: encoded, encoding: .utf8) {
            return str
        }
        return "\"\(value)\""
    }

    /// Exact canonical key order matching `JSON.stringify({ v, id, type, rev })` in `src/shared/e2ee.ts`.
    public static func buildItemAad(
        itemId: String,
        itemType: VaultCipherDomain,
        revision: Int,
        version: Int = cipherVersion
    ) -> String {
        "{\"v\":\(version),\"id\":\(encodeCanonicalJsonString(itemId)),\"type\":\(encodeCanonicalJsonString(itemType.rawValue)),\"rev\":\(revision)}"
    }

    private static func deriveItemKey(
        dek: Data,
        itemSalt: Data,
        itemId: String,
        itemType: VaultCipherDomain,
        version: Int
    ) throws -> SymmetricKey {
        guard dek.count == 32 else {
            throw PrivateSpaceClientError.vaultLocked
        }
        let info = Data(buildItemHkdfInfo(itemId: itemId, itemType: itemType, version: version).utf8)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: dek),
            salt: itemSalt,
            info: info,
            outputByteCount: 32
        )
    }

    public static func encryptItemPayload<T: Encodable>(
        dek: Data,
        itemId: String,
        itemType: VaultCipherDomain,
        revision: Int,
        payload: T
    ) throws -> CipherEnvelopeDto {
        let itemSalt = randomBytes(16)
        let nonceBytes = randomBytes(12)
        let itemKey = try deriveItemKey(
            dek: dek,
            itemSalt: itemSalt,
            itemId: itemId,
            itemType: itemType,
            version: cipherVersion
        )
        let aad = Data(buildItemAad(itemId: itemId, itemType: itemType, revision: revision, version: cipherVersion).utf8)
        let plaintext = try JSONEncoder().encode(payload)
        let nonce = try AES.GCM.Nonce(data: nonceBytes)
        let sealed = try AES.GCM.seal(plaintext, using: itemKey, nonce: nonce, authenticating: aad)

        return CipherEnvelopeDto(
            cipherVersion: cipherVersion,
            itemSalt: itemSalt.base64EncodedString(),
            nonce: nonceBytes.base64EncodedString(),
            authTag: sealed.tag.base64EncodedString(),
            ciphertext: sealed.ciphertext.base64EncodedString()
        )
    }

    public static func decryptItemPayload<T: Decodable>(
        _ type: T.Type,
        dek: Data,
        itemId: String,
        itemType: VaultCipherDomain,
        revision: Int,
        envelope: CipherEnvelopeDto
    ) throws -> T {
        let version = envelope.cipherVersion > 0 ? envelope.cipherVersion : cipherVersion
        guard let itemSalt = Data(base64Encoded: envelope.itemSalt),
              let nonceBytes = Data(base64Encoded: envelope.nonce),
              let tagBytes = Data(base64Encoded: envelope.authTag),
              let ciphertext = Data(base64Encoded: envelope.ciphertext) else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("条目密文信封 Base64 解码失败")
        }

        let itemKey = try deriveItemKey(
            dek: dek,
            itemSalt: itemSalt,
            itemId: itemId,
            itemType: itemType,
            version: version
        )
        let aad = Data(buildItemAad(itemId: itemId, itemType: itemType, revision: revision, version: version).utf8)

        do {
            let nonce = try AES.GCM.Nonce(data: nonceBytes)
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tagBytes)
            let plaintext = try AES.GCM.open(box, using: itemKey, authenticating: aad)
            return try JSONDecoder().decode(T.self, from: plaintext)
        } catch {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("条目 \(itemId) AEAD 认证解密失败")
        }
    }

    // MARK: - 3. Client Hydrators & Normalizers

    public static func summarizeNoteText(title: String, content: String) -> (cleanTitle: String, excerpt: String, wordCount: Int) {
        let trimmedTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
        let collapsed = content
            .replacingOccurrences(of: "[#>*_`~\\-\\[\\]()!]", with: " ", options: .regularExpression)
            .replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        var cleanTitle = trimmedTitle
        if cleanTitle.isEmpty {
            let firstLine = content
                .split(separator: "\n")
                .map { $0.replacingOccurrences(of: "^#{1,6}\\s+", with: "", options: .regularExpression).trimmingCharacters(in: .whitespaces) }
                .first { !$0.isEmpty }
            cleanTitle = firstLine.map { String($0.prefix(60)) } ?? "无标题记录"
        }

        let excerpt = String(collapsed.prefix(160))
        let compactChars = content.replacingOccurrences(of: "\\s+", with: "", options: .regularExpression).count
        return (String(cleanTitle.prefix(120)), excerpt, compactChars)
    }

    public static func normalizeTags(_ raw: [String]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for entry in raw {
            let cleaned = entry
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "^#+", with: "", options: .regularExpression)
            let clipped = String(cleaned.prefix(24))
            guard !clipped.isEmpty else { continue }
            let lower = clipped.lowercased()
            if !seen.contains(lower) {
                seen.insert(lower)
                out.append(clipped)
            }
            if out.count >= 12 { break }
        }
        return out
    }

    public static func sanitizeCustomFields(_ raw: [PasswordCustomField]) -> [PasswordCustomField] {
        var out: [PasswordCustomField] = []
        for field in raw.prefix(20) {
            let label = String(field.label.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64))
            let value = String(field.value.prefix(1000))
            guard !label.isEmpty || !value.isEmpty else { continue }
            let id = field.id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? UUID().uuidString.lowercased() : String(field.id.prefix(48))
            out.append(PasswordCustomField(id: id, label: label.isEmpty ? "自定义字段" : label, value: value, hidden: field.hidden))
        }
        return out
    }

    public static func hydrateDecryptedNote(dek: Data, record: EncryptedVaultRecordDto) throws -> NoteItem {
        let payload = try decryptItemPayload(
            NoteDecryptedPayload.self,
            dek: dek,
            itemId: record.id,
            itemType: .note,
            revision: record.revision,
            envelope: record.envelope
        )
        return NoteItem(
            id: record.id,
            itemType: .note,
            title: payload.title,
            content: payload.content,
            excerpt: payload.excerpt,
            tags: payload.tags,
            format: payload.format,
            wordCount: payload.wordCount,
            isPinned: record.isPinned,
            isArchived: record.isArchived,
            isTrashed: record.isTrashed,
            revision: record.revision,
            syncSeq: record.syncSeq,
            byteSize: record.byteSize,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
            trashedAt: record.trashedAt
        )
    }

    public static func hydrateDecryptedPassword(dek: Data, record: EncryptedVaultRecordDto) throws -> PasswordItem {
        let payload = try decryptItemPayload(
            PasswordDecryptedPayload.self,
            dek: dek,
            itemId: record.id,
            itemType: .password,
            revision: record.revision,
            envelope: record.envelope
        )
        return PasswordItem(
            id: record.id,
            itemType: .password,
            title: payload.title.isEmpty ? "未命名账号" : payload.title,
            username: payload.username,
            password: payload.password,
            url: payload.url,
            totpSecret: payload.totpSecret,
            category: payload.category,
            notes: payload.notes,
            tags: payload.tags,
            customFields: payload.customFields,
            history: payload.history,
            passwordChangedAt: payload.passwordChangedAt.isEmpty ? record.updatedAt : payload.passwordChangedAt,
            isPinned: record.isPinned,
            isArchived: record.isArchived,
            isTrashed: record.isTrashed,
            revision: record.revision,
            syncSeq: record.syncSeq,
            byteSize: record.byteSize,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
            trashedAt: record.trashedAt
        )
    }

    public static func hydrateDecryptedMedia(dek: Data, record: EncryptedVaultRecordDto) throws -> MediaItem {
        let cipherDomain: VaultCipherDomain = record.itemType == .video ? .video : .image
        let itemType: VaultItemType = record.itemType == .video ? .video : .image
        let payload = try decryptItemPayload(
            MediaDecryptedPayload.self,
            dek: dek,
            itemId: record.id,
            itemType: cipherDomain,
            revision: record.revision,
            envelope: record.envelope
        )
        let mainMeta = record.mediaBlobs?.main
        let thumbMeta = record.mediaBlobs?.thumbnail

        return MediaItem(
            id: record.id,
            itemType: itemType,
            title: payload.title.isEmpty ? (payload.originalFilename.isEmpty ? "未命名媒体" : payload.originalFilename) : payload.title,
            originalFilename: payload.originalFilename,
            mimeType: payload.mimeType.isEmpty ? (itemType == .video ? "video/mp4" : "image/jpeg") : payload.mimeType,
            albumId: payload.albumId,
            tags: payload.tags,
            description: payload.description,
            width: payload.width,
            height: payload.height,
            durationMs: payload.durationMs,
            videoCodec: payload.videoCodec,
            audioCodec: payload.audioCodec,
            bitrate: payload.bitrate,
            sha256: payload.sha256.isEmpty ? (mainMeta?.sha256 ?? "") : payload.sha256,
            thumbnailMimeType: payload.thumbnailMimeType,
            takenAt: payload.takenAt.isEmpty ? record.createdAt : payload.takenAt,
            isPinned: record.isPinned,
            isArchived: record.isArchived,
            isTrashed: record.isTrashed,
            revision: record.revision,
            syncSeq: record.syncSeq,
            byteSize: mainMeta?.plainSize ?? record.byteSize,
            encryptedSize: mainMeta?.encryptedSize ?? record.byteSize,
            chunkSize: mainMeta?.chunkSize ?? defaultMediaChunkSize,
            chunkCount: mainMeta?.chunkCount ?? 1,
            hasThumbnail: thumbMeta != nil,
            blobKeyBundle: record.mediaBlobs,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt,
            trashedAt: record.trashedAt
        )
    }

    public static func hydrateDecryptedAlbum(
        dek: Data,
        record: EncryptedAlbumRecordDto,
        itemCount: Int = 0
    ) throws -> MediaAlbum {
        let payload = try decryptItemPayload(
            MediaAlbumDecryptedPayload.self,
            dek: dek,
            itemId: record.id,
            itemType: .album,
            revision: record.revision,
            envelope: record.envelope
        )
        return MediaAlbum(
            id: record.id,
            revision: record.revision,
            name: payload.name,
            description: payload.description,
            kind: payload.kind.isEmpty ? "mixed" : payload.kind,
            coverMediaId: payload.coverMediaId,
            itemCount: itemCount,
            syncSeq: record.syncSeq,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt
        )
    }

    // MARK: - 4. PSENC001 Chunked Media E2EE & HTTP 206 Range Decryption

    public static func buildBlobKekInfo(blobId: String) -> String {
        "privatespace:blob-kek:v1:\(blobId)"
    }

    public static func derivePsencChunkNonce(baseNonce: Data, chunkIndex: Int) throws -> Data {
        guard baseNonce.count == 12 else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("PSENC001 baseNonce 长度必须为 12 字节")
        }
        var bytes = [UInt8](baseNonce)
        let idxBigEndian = UInt64(max(0, chunkIndex)).bigEndian
        withUnsafeBytes(of: idxBigEndian) { idxBuf in
            for i in 0..<8 {
                bytes[4 + i] ^= idxBuf[i]
            }
        }
        return Data(bytes)
    }

    public static func buildPsencChunkAad(blobId: String, chunkIndex: Int, isFinalChunk: Bool) -> Data {
        Data("psenc:v1:\(blobId):\(chunkIndex):\(isFinalChunk ? 1 : 0)".utf8)
    }

    public static func computePsencEncryptedSize(
        plainSize: Int,
        chunkPlainSize: Int = defaultMediaChunkSize
    ) -> (chunkCount: Int, encryptedSize: Int) {
        let chunkCount = plainSize == 0 ? 1 : ((plainSize + chunkPlainSize - 1) / chunkPlainSize)
        let encryptedSize = psencHeaderSize + plainSize + chunkCount * psencTagSize
        return (chunkCount, encryptedSize)
    }

    public static func encodePsencHeader(
        plainSize: Int,
        chunkPlainSize: Int = defaultMediaChunkSize
    ) -> Data {
        var out = Data(capacity: psencHeaderSize)
        out.append(psencMagic)
        var chunkBE = UInt32(chunkPlainSize).bigEndian
        var plainBE = UInt64(max(0, plainSize)).bigEndian
        withUnsafeBytes(of: &chunkBE) { out.append(contentsOf: $0) }
        withUnsafeBytes(of: &plainBE) { out.append(contentsOf: $0) }
        return out
    }

    public static func parsePsencHeader(_ data: Data) throws -> (chunkPlainSize: Int, totalPlainSize: Int) {
        guard data.count >= psencHeaderSize else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("PSENC001 文件头长度不足 20 字节")
        }
        let headerBytes = [UInt8](data.subdata(in: 0..<psencHeaderSize))
        let magicBytes = [UInt8](psencMagic)
        for i in 0..<8 where headerBytes[i] != magicBytes[i] {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("PSENC001 魔数头校验失败")
        }

        let chunkPlainSize =
            (Int(headerBytes[8]) << 24)
            | (Int(headerBytes[9]) << 16)
            | (Int(headerBytes[10]) << 8)
            | Int(headerBytes[11])

        var plainU64: UInt64 = 0
        for i in 12..<20 {
            plainU64 = (plainU64 << 8) | UInt64(headerBytes[i])
        }
        return (chunkPlainSize, Int(plainU64))
    }

    public static func wrapBlobFek(
        dek: Data,
        fek: Data,
        blobId: String
    ) throws -> (fekSalt: String, fekNonce: String, fekTag: String, wrappedFek: String) {
        guard dek.count == 32, fek.count == 32 else {
            throw PrivateSpaceClientError.vaultLocked
        }
        let fekSalt = randomBytes(16)
        let fekNonceBytes = randomBytes(12)
        let blobKek = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: dek),
            salt: fekSalt,
            info: Data(buildBlobKekInfo(blobId: blobId).utf8),
            outputByteCount: 32
        )
        let nonce = try AES.GCM.Nonce(data: fekNonceBytes)
        let sealed = try AES.GCM.seal(
            fek,
            using: blobKek,
            nonce: nonce,
            authenticating: Data("fek:\(blobId)".utf8)
        )
        return (
            fekSalt: fekSalt.base64EncodedString(),
            fekNonce: fekNonceBytes.base64EncodedString(),
            fekTag: sealed.tag.base64EncodedString(),
            wrappedFek: sealed.ciphertext.base64EncodedString()
        )
    }

    public static func unwrapBlobFek(dek: Data, meta: EncryptedBlobKeyMetaDto) throws -> Data {
        guard dek.count == 32 else {
            throw PrivateSpaceClientError.vaultLocked
        }
        guard let fekSalt = Data(base64Encoded: meta.fekSalt),
              let fekNonceBytes = Data(base64Encoded: meta.fekNonce),
              let fekTag = Data(base64Encoded: meta.fekTag),
              let wrappedFek = Data(base64Encoded: meta.wrappedFek) else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("FEK 元数据 Base64 解码失败")
        }
        let blobKek = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: dek),
            salt: fekSalt,
            info: Data(buildBlobKekInfo(blobId: meta.blobId).utf8),
            outputByteCount: 32
        )
        do {
            let nonce = try AES.GCM.Nonce(data: fekNonceBytes)
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: wrappedFek, tag: fekTag)
            return try AES.GCM.open(box, using: blobKek, authenticating: Data("fek:\(meta.blobId)".utf8))
        } catch {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("媒体文件密钥 FEK 解封认证失败")
        }
    }

    public static func encryptMediaBytesToPsenc(
        dek: Data,
        plainData: Data,
        blobId: String? = nil,
        chunkPlainSize: Int = defaultMediaChunkSize
    ) throws -> (encryptedData: Data, meta: EncryptedBlobKeyMetaDto) {
        let resolvedBlobId = blobId ?? generateBlobId()
        let plainSize = plainData.count
        let (chunkCount, encryptedSize) = computePsencEncryptedSize(plainSize: plainSize, chunkPlainSize: chunkPlainSize)

        let fek = randomBytes(32)
        let baseNonce = randomBytes(12)
        let wrapped = try wrapBlobFek(dek: dek, fek: fek, blobId: resolvedBlobId)
        let digestHex = sha256Hex(plainData)
        let fekSym = SymmetricKey(data: fek)

        var out = Data()
        out.reserveCapacity(encryptedSize)
        out.append(encodePsencHeader(plainSize: plainSize, chunkPlainSize: chunkPlainSize))

        if plainSize == 0 {
            let nonceData = try derivePsencChunkNonce(baseNonce: baseNonce, chunkIndex: 0)
            let aad = buildPsencChunkAad(blobId: resolvedBlobId, chunkIndex: 0, isFinalChunk: true)
            let sealed = try AES.GCM.seal(Data(), using: fekSym, nonce: try AES.GCM.Nonce(data: nonceData), authenticating: aad)
            out.append(sealed.ciphertext)
            out.append(sealed.tag)
        } else {
            for chunkIdx in 0..<chunkCount {
                let start = chunkIdx * chunkPlainSize
                let end = min(plainSize, start + chunkPlainSize)
                let slice = plainData.subdata(in: start..<end)
                let isFinal = chunkIdx == chunkCount - 1
                let nonceData = try derivePsencChunkNonce(baseNonce: baseNonce, chunkIndex: chunkIdx)
                let aad = buildPsencChunkAad(blobId: resolvedBlobId, chunkIndex: chunkIdx, isFinalChunk: isFinal)
                let sealed = try AES.GCM.seal(slice, using: fekSym, nonce: try AES.GCM.Nonce(data: nonceData), authenticating: aad)
                out.append(sealed.ciphertext)
                out.append(sealed.tag)
            }
        }

        let meta = EncryptedBlobKeyMetaDto(
            blobId: resolvedBlobId,
            fekSalt: wrapped.fekSalt,
            fekNonce: wrapped.fekNonce,
            fekTag: wrapped.fekTag,
            wrappedFek: wrapped.wrappedFek,
            baseNonce: baseNonce.base64EncodedString(),
            chunkSize: chunkPlainSize,
            chunkCount: chunkCount,
            plainSize: plainSize,
            encryptedSize: out.count,
            sha256: digestHex
        )
        return (out, meta)
    }

    public static func encryptResumableMediaPart(
        fek: Data,
        blobId: String,
        baseNonce: Data,
        partPlainData: Data,
        partIndex: Int,
        partStridePlainBytes: Int,
        totalPlainSize: Int,
        chunkPlainSize: Int = defaultMediaChunkSize
    ) throws -> Data {
        guard partStridePlainBytes % chunkPlainSize == 0 else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("断点续传分片步长必须为 64KiB 的整数倍")
        }
        let (totalPsencChunks, _) = computePsencEncryptedSize(plainSize: totalPlainSize, chunkPlainSize: chunkPlainSize)
        let startChunkIdx = (partIndex * partStridePlainBytes) / chunkPlainSize
        let partLen = partPlainData.count
        let subChunks = partLen == 0 ? 1 : ((partLen + chunkPlainSize - 1) / chunkPlainSize)
        let includeHeader = (partIndex == 0)
        let outLen = (includeHeader ? psencHeaderSize : 0) + partLen + subChunks * psencTagSize

        var out = Data()
        out.reserveCapacity(outLen)
        if includeHeader {
            out.append(encodePsencHeader(plainSize: totalPlainSize, chunkPlainSize: chunkPlainSize))
        }

        let fekSym = SymmetricKey(data: fek)
        if partLen == 0 {
            let nonceData = try derivePsencChunkNonce(baseNonce: baseNonce, chunkIndex: 0)
            let aad = buildPsencChunkAad(blobId: blobId, chunkIndex: 0, isFinalChunk: true)
            let sealed = try AES.GCM.seal(Data(), using: fekSym, nonce: try AES.GCM.Nonce(data: nonceData), authenticating: aad)
            out.append(sealed.ciphertext)
            out.append(sealed.tag)
            return out
        }

        for localIdx in 0..<subChunks {
            let globalChunkIdx = startChunkIdx + localIdx
            let isFinal = globalChunkIdx == totalPsencChunks - 1
            let start = localIdx * chunkPlainSize
            let end = min(partLen, start + chunkPlainSize)
            let slice = partPlainData.subdata(in: start..<end)
            let nonceData = try derivePsencChunkNonce(baseNonce: baseNonce, chunkIndex: globalChunkIdx)
            let aad = buildPsencChunkAad(blobId: blobId, chunkIndex: globalChunkIdx, isFinalChunk: isFinal)
            let sealed = try AES.GCM.seal(slice, using: fekSym, nonce: try AES.GCM.Nonce(data: nonceData), authenticating: aad)
            out.append(sealed.ciphertext)
            out.append(sealed.tag)
        }
        return out
    }

    public static func computeEncryptedRangeForPlainRange(
        meta: EncryptedBlobKeyMetaDto,
        startPlainByte: Int,
        endPlainByte: Int? = nil
    ) -> PsencEncryptedRange {
        let totalPlain = meta.plainSize
        if totalPlain <= 0 {
            return PsencEncryptedRange(
                clampedStart: 0,
                clampedEnd: 0,
                firstChunkIdx: 0,
                lastChunkIdx: 0,
                diskStart: psencHeaderSize,
                diskEnd: psencHeaderSize + psencTagSize - 1
            )
        }

        let clampedStart = max(0, min(totalPlain - 1, startPlainByte))
        let requestedEnd = endPlainByte ?? (totalPlain - 1)
        let clampedEnd = max(clampedStart, min(totalPlain - 1, requestedEnd))

        let chunkPlainSize = meta.chunkSize
        let chunkCipherStride = chunkPlainSize + psencTagSize
        let firstChunkIdx = clampedStart / chunkPlainSize
        let lastChunkIdx = clampedEnd / chunkPlainSize

        let diskStart = psencHeaderSize + firstChunkIdx * chunkCipherStride
        let isLastFinal = lastChunkIdx == meta.chunkCount - 1
        let lastPlainLen = isLastFinal ? (totalPlain - lastChunkIdx * chunkPlainSize) : chunkPlainSize
        let diskEnd = psencHeaderSize + lastChunkIdx * chunkCipherStride + lastPlainLen + psencTagSize - 1

        return PsencEncryptedRange(
            clampedStart: clampedStart,
            clampedEnd: clampedEnd,
            firstChunkIdx: firstChunkIdx,
            lastChunkIdx: lastChunkIdx,
            diskStart: diskStart,
            diskEnd: diskEnd
        )
    }

    public static func decryptPsencRangeSlice(
        dek: Data? = nil,
        fek: Data? = nil,
        encryptedSlice: Data,
        meta: EncryptedBlobKeyMetaDto,
        range: PsencEncryptedRange
    ) throws -> Data {
        if meta.plainSize == 0 {
            return Data()
        }

        let resolvedFek: Data
        if let fek {
            resolvedFek = fek
        } else if let dek {
            resolvedFek = try unwrapBlobFek(dek: dek, meta: meta)
        } else {
            throw PrivateSpaceClientError.vaultLocked
        }

        guard let baseNonce = Data(base64Encoded: meta.baseNonce) else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("PSENC001 baseNonce Base64 解码失败")
        }

        let chunkPlainSize = meta.chunkSize
        let totalPlain = meta.plainSize
        let totalChunkCount = meta.chunkCount
        let fekSym = SymmetricKey(data: resolvedFek)

        var out = Data()
        out.reserveCapacity(range.clampedEnd - range.clampedStart + 1)
        var readOffset = 0

        for chunkIdx in range.firstChunkIdx...range.lastChunkIdx {
            let isFinal = chunkIdx == totalChunkCount - 1
            let expectedPlainLen = isFinal ? (totalPlain - chunkIdx * chunkPlainSize) : chunkPlainSize
            let expectedDiskLen = expectedPlainLen + psencTagSize
            guard readOffset + expectedDiskLen <= encryptedSlice.count else {
                throw PrivateSpaceClientError.e2eeDecryptionFailed("PSENC001 分块密文切片不完整")
            }

            let cipherPart = encryptedSlice.subdata(in: readOffset..<(readOffset + expectedPlainLen))
            let tagPart = encryptedSlice.subdata(in: (readOffset + expectedPlainLen)..<(readOffset + expectedDiskLen))
            readOffset += expectedDiskLen

            let nonceData = try derivePsencChunkNonce(baseNonce: baseNonce, chunkIndex: chunkIdx)
            let aad = buildPsencChunkAad(blobId: meta.blobId, chunkIndex: chunkIdx, isFinalChunk: isFinal)

            let plainChunk: Data
            do {
                let nonce = try AES.GCM.Nonce(data: nonceData)
                let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: cipherPart, tag: tagPart)
                plainChunk = try AES.GCM.open(box, using: fekSym, authenticating: aad)
            } catch {
                throw PrivateSpaceClientError.e2eeDecryptionFailed("PSENC001 第 \(chunkIdx) 块 AEAD 认证失败")
            }

            let chunkGlobalStart = chunkIdx * chunkPlainSize
            let sliceStart = chunkIdx == range.firstChunkIdx ? (range.clampedStart - chunkGlobalStart) : 0
            let sliceEnd = chunkIdx == range.lastChunkIdx ? (range.clampedEnd - chunkGlobalStart + 1) : plainChunk.count
            out.append(plainChunk.subdata(in: sliceStart..<sliceEnd))
        }

        return out
    }

    public static func decryptPsencFullBuffer(
        dek: Data,
        encryptedData: Data,
        meta: EncryptedBlobKeyMetaDto
    ) throws -> Data {
        let header = try parsePsencHeader(encryptedData)
        guard header.totalPlainSize == meta.plainSize, header.chunkPlainSize == meta.chunkSize else {
            throw PrivateSpaceClientError.e2eeDecryptionFailed("PSENC001 头部大小与认证元数据不一致")
        }
        if meta.plainSize == 0 {
            let fek = try unwrapBlobFek(dek: dek, meta: meta)
            guard let baseNonce = Data(base64Encoded: meta.baseNonce),
                  encryptedData.count >= psencHeaderSize + psencTagSize else {
                throw PrivateSpaceClientError.e2eeDecryptionFailed("PSENC001 空文件密文格式无效")
            }
            let nonceData = try derivePsencChunkNonce(baseNonce: baseNonce, chunkIndex: 0)
            let aad = buildPsencChunkAad(blobId: meta.blobId, chunkIndex: 0, isFinalChunk: true)
            let tag = encryptedData.subdata(in: psencHeaderSize..<(psencHeaderSize + psencTagSize))
            let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonceData), ciphertext: Data(), tag: tag)
            return try AES.GCM.open(box, using: SymmetricKey(data: fek), authenticating: aad)
        }

        let range = computeEncryptedRangeForPlainRange(meta: meta, startPlainByte: 0, endPlainByte: meta.plainSize - 1)
        let cipherBody = encryptedData.subdata(in: psencHeaderSize..<encryptedData.count)
        return try decryptPsencRangeSlice(dek: dek, encryptedSlice: cipherBody, meta: meta, range: range)
    }

    // MARK: - 5. Client-Side Media Metadata Probe & Encrypted Thumbnail Generator

    public static func probeMediaMetadata(data: Data, mimeType: String) -> ProbedMediaInfo {
        let lowerMime = mimeType.lowercased()

        #if canImport(ImageIO) && canImport(CoreGraphics)
        if lowerMime.hasPrefix("image/"),
           let source = CGImageSourceCreateWithData(data as CFData, nil),
           let props = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any] {
            let w = (props[kCGImagePropertyPixelWidth] as? Int) ?? 0
            let h = (props[kCGImagePropertyPixelHeight] as? Int) ?? 0
            if w > 0 && h > 0 {
                return ProbedMediaInfo(width: w, height: h, durationMs: nil, videoCodec: nil, audioCodec: nil, bitrate: nil)
            }
        }
        #endif

        let bytes = [UInt8](data.prefix(min(data.count, 256 * 1024)))
        // PNG header
        if bytes.count >= 24,
           bytes[0] == 0x89, bytes[1] == 0x50, bytes[2] == 0x4E, bytes[3] == 0x47 {
            let w = (Int(bytes[16]) << 24) | (Int(bytes[17]) << 16) | (Int(bytes[18]) << 8) | Int(bytes[19])
            let h = (Int(bytes[20]) << 24) | (Int(bytes[21]) << 16) | (Int(bytes[22]) << 8) | Int(bytes[23])
            return ProbedMediaInfo(width: max(0, w), height: max(0, h), durationMs: nil, videoCodec: nil, audioCodec: nil, bitrate: nil)
        }

        // GIF header
        if bytes.count >= 10,
           bytes[0] == 0x47, bytes[1] == 0x49, bytes[2] == 0x46 {
            let w = Int(bytes[6]) | (Int(bytes[7]) << 8)
            let h = Int(bytes[8]) | (Int(bytes[9]) << 8)
            return ProbedMediaInfo(width: w, height: h, durationMs: nil, videoCodec: nil, audioCodec: nil, bitrate: nil)
        }

        if lowerMime.hasPrefix("video/") {
            return ProbedMediaInfo(
                width: 0,
                height: 0,
                durationMs: nil,
                videoCodec: lowerMime.contains("mp4") ? "h264" : nil,
                audioCodec: nil,
                bitrate: nil
            )
        }

        return ProbedMediaInfo(width: 0, height: 0, durationMs: nil, videoCodec: nil, audioCodec: nil, bitrate: nil)
    }

    public static func generateThumbnailJpeg(from imageData: Data, maxDimension: Int = 480) -> Data? {
        #if canImport(ImageIO) && canImport(CoreGraphics) && canImport(UniformTypeIdentifiers)
        guard let source = CGImageSourceCreateWithData(imageData as CFData, nil) else {
            return nil
        }
        let thumbOptions: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceThumbnailMaxPixelSize: maxDimension,
        ]
        guard let cgImage = CGImageSourceCreateThumbnailAtIndex(source, 0, thumbOptions as CFDictionary) else {
            return nil
        }
        let mutableData = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(
            mutableData,
            UTType.jpeg.identifier as CFString,
            1,
            nil
        ) else {
            return nil
        }
        let destProps: [CFString: Any] = [
            kCGImageDestinationLossyCompressionQuality: 0.78,
        ]
        CGImageDestinationAddImage(destination, cgImage, destProps as CFDictionary)
        guard CGImageDestinationFinalize(destination) else {
            return nil
        }
        return mutableData as Data
        #else
        return nil
        #endif
    }
}
