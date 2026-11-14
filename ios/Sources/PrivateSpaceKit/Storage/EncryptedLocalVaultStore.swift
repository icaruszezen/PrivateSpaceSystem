import CryptoKit
import Foundation

/// On-device Zero-Plaintext-at-Rest encrypted vault cache & App Group AutoFill store.
/// Uses `HKDF-SHA256` per-write random salt + `AES-256-GCM` with `PSCACHE1` magic header & AAD binding.
public final class EncryptedLocalVaultStore: @unchecked Sendable {
    public static let magicHeader = Data("PSCACHE1".utf8) // 8 bytes
    private static let saltLength = 16
    private static let nonceLength = 12
    private static let tagLength = 16

    public let snapshotFileURL: URL
    public let autoFillFileURL: URL
    private let secretStore: SecretStoreProtocol
    private let lock = NSLock()

    public init(
        directoryURL: URL? = nil,
        appGroupIdentifier: String? = "group.io.privatespace.ios",
        secretStore: SecretStoreProtocol = AppleKeychainStore()
    ) {
        self.secretStore = secretStore

        let resolvedBaseDir: URL
        if let directoryURL {
            resolvedBaseDir = directoryURL
        } else if let appGroupIdentifier,
                  let sharedURL = FileManager.default.containerURL(
                      forSecurityApplicationGroupIdentifier: appGroupIdentifier
                  ) {
            resolvedBaseDir = sharedURL.appendingPathComponent("PrivateSpaceEncryptedCache", isDirectory: true)
        } else {
            let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? FileManager.default.temporaryDirectory
            resolvedBaseDir = appSupport.appendingPathComponent("PrivateSpaceEncryptedCache", isDirectory: true)
        }

        try? FileManager.default.createDirectory(at: resolvedBaseDir, withIntermediateDirectories: true)
        self.snapshotFileURL = resolvedBaseDir.appendingPathComponent("vault_snapshot.pscache")
        self.autoFillFileURL = resolvedBaseDir.appendingPathComponent("autofill_credentials.psautofill")
    }

    // MARK: - Snapshot Persistence

    public func saveSnapshot(_ snapshot: MobileVaultSnapshot) throws {
        lock.lock()
        defer { lock.unlock() }

        let masterKey = try secretStore.loadOrCreateLocalCacheKey()
        let encoder = JSONEncoder()
        let plaintext = try encoder.encode(snapshot)
        let sealedBlob = try sealContainer(
            plaintext: plaintext,
            masterKey: masterKey,
            hkdfInfo: "privatespace:ios-local-cache:v1",
            aad: "privatespace:ios-cache:snapshot:v1"
        )
        try writeProtectedFile(sealedBlob, to: snapshotFileURL)

        // Synchronize active non-trashed credentials into encrypted App Group AutoFill container
        let credentials = snapshot.passwords.values
            .filter { !$0.isTrashed }
            .sorted { $0.title.localizedCompare($1.title) == .orderedAscending }
            .map(AutoFillCredentialRecord.init(from:))
        let credPlaintext = try encoder.encode(credentials)
        let sealedAutoFill = try sealContainer(
            plaintext: credPlaintext,
            masterKey: masterKey,
            hkdfInfo: "privatespace:ios-autofill:v1",
            aad: "privatespace:ios-cache:autofill:v1"
        )
        try writeProtectedFile(sealedAutoFill, to: autoFillFileURL)
    }

    public func loadSnapshot() throws -> MobileVaultSnapshot? {
        lock.lock()
        defer { lock.unlock() }

        guard FileManager.default.fileExists(atPath: snapshotFileURL.path) else {
            return nil
        }
        let raw = try Data(contentsOf: snapshotFileURL)
        let masterKey = try secretStore.loadOrCreateLocalCacheKey()
        let plaintext = try openContainer(
            container: raw,
            masterKey: masterKey,
            hkdfInfo: "privatespace:ios-local-cache:v1",
            aad: "privatespace:ios-cache:snapshot:v1"
        )
        return try JSONDecoder().decode(MobileVaultSnapshot.self, from: plaintext)
    }

    // MARK: - iOS AutoFill Credential Extension Reader

    public func loadAutoFillCredentials(matching serviceIdentifiers: [String] = []) throws -> [AutoFillCredentialRecord] {
        lock.lock()
        defer { lock.unlock() }

        guard FileManager.default.fileExists(atPath: autoFillFileURL.path) else {
            return []
        }
        let raw = try Data(contentsOf: autoFillFileURL)
        let masterKey = try secretStore.loadOrCreateLocalCacheKey()
        let plaintext = try openContainer(
            container: raw,
            masterKey: masterKey,
            hkdfInfo: "privatespace:ios-autofill:v1",
            aad: "privatespace:ios-cache:autofill:v1"
        )
        let all = try JSONDecoder().decode([AutoFillCredentialRecord].self, from: plaintext)
        guard !serviceIdentifiers.isEmpty else { return all }

        let matched = all.filter { record in
            serviceIdentifiers.contains { record.matches(serviceIdentifier: $0) }
        }
        return matched.isEmpty ? all : matched
    }

    public func encryptedDiskFootprintBytes() -> Int {
        lock.lock()
        defer { lock.unlock() }

        var total = 0
        for url in [snapshotFileURL, autoFillFileURL] {
            if let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
               let size = attrs[.size] as? Int {
                total += size
            }
        }
        return total
    }

    /// Overwrites local `.pscache` & `.psautofill` files with zeros before unlinking (file shredding).
    public func shredLocalCache() {
        lock.lock()
        defer { lock.unlock() }

        for url in [snapshotFileURL, autoFillFileURL] {
            if let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
               let size = attrs[.size] as? Int,
               size > 0 {
                let zeros = Data(repeating: 0, count: size)
                try? zeros.write(to: url, options: .atomic)
            }
            try? FileManager.default.removeItem(at: url)
        }
    }

    // MARK: - Binary AEAD Container (`PSCACHE1` + 16B Salt + 12B Nonce + 16B Tag + Ciphertext)

    private func sealContainer(
        plaintext: Data,
        masterKey: SymmetricKey,
        hkdfInfo: String,
        aad: String
    ) throws -> Data {
        var salt = Data(count: Self.saltLength)
        _ = salt.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, Self.saltLength, buf.baseAddress!)
        }

        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: masterKey,
            salt: salt,
            info: Data(hkdfInfo.utf8),
            outputByteCount: 32
        )

        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(
            plaintext,
            using: derivedKey,
            nonce: nonce,
            authenticating: Data(aad.utf8)
        )

        var out = Data()
        out.reserveCapacity(
            Self.magicHeader.count + Self.saltLength + Self.nonceLength + Self.tagLength + sealed.ciphertext.count
        )
        out.append(Self.magicHeader)
        out.append(salt)
        out.append(Data(nonce))
        out.append(sealed.tag)
        out.append(sealed.ciphertext)
        return out
    }

    private func openContainer(
        container: Data,
        masterKey: SymmetricKey,
        hkdfInfo: String,
        aad: String
    ) throws -> Data {
        let headerSize = Self.magicHeader.count + Self.saltLength + Self.nonceLength + Self.tagLength
        guard container.count >= headerSize else {
            throw PrivateSpaceClientError.corruptedLocalCiphertext
        }

        let magic = container.subdata(in: 0..<Self.magicHeader.count)
        guard magic == Self.magicHeader else {
            throw PrivateSpaceClientError.corruptedLocalCiphertext
        }

        let saltStart = Self.magicHeader.count
        let nonceStart = saltStart + Self.saltLength
        let tagStart = nonceStart + Self.nonceLength
        let cipherStart = tagStart + Self.tagLength

        let salt = container.subdata(in: saltStart..<nonceStart)
        let nonceData = container.subdata(in: nonceStart..<tagStart)
        let tagData = container.subdata(in: tagStart..<cipherStart)
        let ciphertext = container.subdata(in: cipherStart..<container.count)

        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: masterKey,
            salt: salt,
            info: Data(hkdfInfo.utf8),
            outputByteCount: 32
        )

        do {
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tagData)
            return try AES.GCM.open(box, using: derivedKey, authenticating: Data(aad.utf8))
        } catch {
            throw PrivateSpaceClientError.corruptedLocalCiphertext
        }
    }

    private func writeProtectedFile(_ data: Data, to url: URL) throws {
        #if os(iOS)
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try data.write(to: url, options: [.atomic])
        #endif
    }
}
