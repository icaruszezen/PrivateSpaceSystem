import CryptoKit
import Foundation
import Security

/// Abstraction over hardware-backed Apple Keychain Services for testability and App Group sharing.
public protocol SecretStoreProtocol: Sendable {
    func readData(forKey key: String) throws -> Data?
    func writeData(_ data: Data, forKey key: String) throws
    func deleteData(forKey key: String) throws
}

extension SecretStoreProtocol {
    public func readString(forKey key: String) throws -> String? {
        guard let data = try readData(forKey: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public func writeString(_ value: String?, forKey key: String) throws {
        if let value {
            try writeData(Data(value.utf8), forKey: key)
        } else {
            try deleteData(forKey: key)
        }
    }

    /// Loads or creates a persistent 256-bit local cache master key stored inside Keychain.
    public func loadOrCreateLocalCacheKey(keyIdentifier: String = "local_vault_aes256_key") throws -> SymmetricKey {
        if let existing = try readData(forKey: keyIdentifier), existing.count == 32 {
            return SymmetricKey(data: existing)
        }
        let generated = SymmetricKey(size: .bits256)
        let rawBytes = generated.withUnsafeBytes { Data($0) }
        try writeData(rawBytes, forKey: keyIdentifier)
        return generated
    }
}

/// Hardware-backed Apple Keychain Services (`SecItem`) store using `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
public final class AppleKeychainStore: SecretStoreProtocol, @unchecked Sendable {
    private let service: String
    private let accessGroup: String?
    private let lock = NSLock()

    public init(service: String = "io.privatespace.ios.keychain", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    private func baseQuery(forKey key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        if let accessGroup, !accessGroup.isEmpty {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }

    public func readData(forKey key: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }

        var query = baseQuery(forKey: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        return item as? Data
    }

    public func writeData(_ data: Data, forKey key: String) throws {
        lock.lock()
        defer { lock.unlock() }

        let query = baseQuery(forKey: key)
        SecItemDelete(query as CFDictionary)

        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    public func deleteData(forKey key: String) throws {
        lock.lock()
        defer { lock.unlock() }

        let query = baseQuery(forKey: key)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }
}

/// Thread-safe in-memory secret store for XCTest and SwiftUI Previews.
public final class InMemorySecretStore: SecretStoreProtocol, @unchecked Sendable {
    private var storage: [String: Data] = [:]
    private let lock = NSLock()

    public init() {}

    public func readData(forKey key: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return storage[key]
    }

    public func writeData(_ data: Data, forKey key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        storage[key] = data
    }

    public func deleteData(forKey key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        storage.removeValue(forKey: key)
    }
}
