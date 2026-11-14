import CryptoKit
import Foundation
import XCTest
@testable import PrivateSpaceKit

final class PrivateSpaceKitTests: XCTestCase {

    // MARK: - 1. RFC 6238 TOTP Vectors & otpauth:// Parser

    func testRFC6238TotpVectorsAndOtpAuthURI() throws {
        // RFC 6238 ASCII seed "12345678901234567890" -> Base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        // At t = 59s, 8-digit SHA-1 RFC 6238 vector = "94287082"
        let rfcURI = "otpauth://totp/RFC6238:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1"
        let snap = try TotpGenerator.generateTotp(rfcURI, timestampMs: 59_000)
        XCTAssertEqual(snap.code, "94287082")
        XCTAssertEqual(snap.formattedCode, "9428 7082")
        XCTAssertEqual(snap.remainingSeconds, 1)

        // Parse SHA256 otpauth URI with percent-encoded account label
        let sha256URI = "otpauth://totp/GitHub:icarus%40privatespace.dev?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=6&period=30"
        let cfg = try TotpGenerator.parseTotpInput(sha256URI)
        XCTAssertEqual(cfg.issuer, "GitHub")
        XCTAssertEqual(cfg.accountName, "icarus@privatespace.dev")
        XCTAssertEqual(cfg.algorithm, .sha256)
        XCTAssertEqual(cfg.digits, 6)

        let code256 = try TotpGenerator.generateTotp(sha256URI, timestampMs: 1_700_000_000_000)
        XCTAssertEqual(code256.code.count, 6)
    }

    // MARK: - 2. CSPRNG Password Generator, Vault Health Audit & CSV Parser

    func testPasswordGeneratorAuditAndCsvImport() {
        let generated = PasswordSecurityEngine.generateSecurePassword(
            PasswordGeneratorOptions(
                length: 28,
                uppercase: true,
                lowercase: true,
                digits: true,
                symbols: true,
                excludeAmbiguous: true
            )
        )
        XCTAssertEqual(generated.count, 28)
        XCTAssertFalse(generated.contains(where: { ["0", "O", "o", "1", "l", "I", "|"].contains($0) }))

        let entropy = PasswordSecurityEngine.evaluatePasswordEntropy(generated)
        XCTAssertEqual(entropy.score, 4)
        XCTAssertGreaterThan(entropy.entropyBits, 110)

        let passphrase = PasswordSecurityEngine.generateMemorablePassphrase(
            PassphraseGeneratorOptions(wordCount: 5, separator: "-", capitalize: true, includeNumber: true)
        )
        XCTAssertEqual(passphrase.split(separator: "-").count, 5)
        XCTAssertEqual(PasswordSecurityEngine.evaluatePasswordEntropy("123456").score, 0)

        let nowIso = "2026-11-13T00:00:00Z"
        let items: [PasswordItem] = [
            PasswordItem(
                id: "weak-1",
                title: "Legacy Forum",
                username: "user1",
                password: "password123",
                totpSecret: "",
                passwordChangedAt: "2024-01-01T00:00:00Z",
                createdAt: nowIso,
                updatedAt: nowIso
            ),
            PasswordItem(
                id: "dup-a",
                title: "Service A",
                username: "ops@corp.io",
                password: "ReusedStrong#Password!2026",
                totpSecret: "JBSWY3DPEHPK3PXP",
                passwordChangedAt: nowIso,
                createdAt: nowIso,
                updatedAt: nowIso
            ),
            PasswordItem(
                id: "dup-b",
                title: "Service B",
                username: "ops@corp.io",
                password: "ReusedStrong#Password!2026",
                totpSecret: "",
                passwordChangedAt: nowIso,
                createdAt: nowIso,
                updatedAt: nowIso
            ),
        ]

        let audit = PasswordSecurityEngine.auditPasswordVault(items)
        XCTAssertTrue(audit.weakIds.contains("weak-1"))
        XCTAssertTrue(audit.reusedIds.contains("dup-a"))
        XCTAssertTrue(audit.reusedIds.contains("dup-b"))
        XCTAssertTrue(audit.missingTotpIds.contains("weak-1"))
        XCTAssertLessThan(audit.healthScore, 85)

        let csv = """
        name,url,username,password,totp
        "GitHub Enterprise",https://github.com,dev@privatespace.io,"Ultra#Strong$Pass99",JBSWY3DPEHPK3PXP
        Cloudflare,https://dash.cloudflare.com,dns@privatespace.io,Cf#Vault$Pass88,
        """
        let imported = PasswordSecurityEngine.parsePasswordCsv(csv)
        XCTAssertEqual(imported.count, 2)
        XCTAssertEqual(imported[0].title, "GitHub Enterprise")
        XCTAssertEqual(imported[0].totpSecret, "JBSWY3DPEHPK3PXP")
    }

    // MARK: - 3. On-Device CryptoKit AES-256-GCM Zero-Plaintext Cache & AutoFill Domain Matching

    func testEncryptedLocalVaultStoreZeroPlaintextAndTamperDetection() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pss-ios-cache-test-\(UUID().uuidString)", isDirectory: true)
        defer {
            try? FileManager.default.removeItem(at: tempDir)
        }

        let memKeychain = InMemorySecretStore()
        let store = EncryptedLocalVaultStore(
            directoryURL: tempDir,
            appGroupIdentifier: nil,
            secretStore: memKeychain
        )

        let secretNoteBody = "IOS_LOCAL_CACHE_TOP_SECRET_NOTE_PAYLOAD_887766"
        let secretPasswordVal = "IOS_AUTOFILL_SUPER_SECRET_PASSWORD_991122!"
        let now = "2026-11-13T10:00:00Z"

        var snap = MobileVaultSnapshot(vaultName: "iPhone Vault", keyFingerprint: "fp-test", lastSyncSeq: 7)
        snap.notes["n1"] = NoteItem(
            id: "n1",
            title: "iOS 密钥备忘",
            content: secretNoteBody,
            excerpt: "备忘",
            tags: ["iOS"],
            wordCount: secretNoteBody.count,
            createdAt: now,
            updatedAt: now
        )
        snap.passwords["p1"] = PasswordItem(
            id: "p1",
            title: "GitHub",
            username: "ios@privatespace.dev",
            password: secretPasswordVal,
            url: "https://github.com/login",
            totpSecret: "JBSWY3DPEHPK3PXP",
            passwordChangedAt: now,
            createdAt: now,
            updatedAt: now
        )

        try store.saveSnapshot(snap)

        // Verify zero cleartext on disk inside both .pscache and .psautofill
        let rawCacheBytes = try Data(contentsOf: store.snapshotFileURL)
        let rawAutoFillBytes = try Data(contentsOf: store.autoFillFileURL)
        XCTAssertEqual(rawCacheBytes.subdata(in: 0..<8), Data("PSCACHE1".utf8))
        XCTAssertEqual(rawAutoFillBytes.subdata(in: 0..<8), Data("PSCACHE1".utf8))
        XCTAssertNil(rawCacheBytes.range(of: Data(secretNoteBody.utf8)))
        XCTAssertNil(rawCacheBytes.range(of: Data(secretPasswordVal.utf8)))
        XCTAssertNil(rawAutoFillBytes.range(of: Data(secretPasswordVal.utf8)))

        // Round-trip decryption
        let restored = try store.loadSnapshot()
        XCTAssertEqual(restored?.notes["n1"]?.content, secretNoteBody)
        XCTAssertEqual(restored?.passwords["p1"]?.password, secretPasswordVal)

        // Domain-matched AutoFill lookup
        let matched = try store.loadAutoFillCredentials(matching: ["https://gist.github.com"])
        XCTAssertEqual(matched.count, 1)
        XCTAssertEqual(matched.first?.password, secretPasswordVal)

        // Flip 1 bit in ciphertext -> AES-GCM authentication MUST reject
        var tampered = rawCacheBytes
        tampered[tampered.count - 4] ^= 0x80
        try tampered.write(to: store.snapshotFileURL)
        XCTAssertThrowsError(try store.loadSnapshot())

        // File shredding removes files cleanly
        store.shredLocalCache()
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.snapshotFileURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.autoFillFileURL.path))
    }

    // MARK: - 4. Live PrivateSpace Server End-to-End Integration Test (CI Automated)

    func testLiveServerEndToEndSyncAndStreamingWhenConfigured() async throws {
        guard let serverURL = ProcessInfo.processInfo.environment["PRIVATESPACE_TEST_SERVER_URL"],
              !serverURL.isEmpty else {
            return
        }
        let adminPassword = ProcessInfo.processInfo.environment["PRIVATESPACE_TEST_PASSWORD"]
            ?? "IosIntegrationMaster!2026"

        let client = PrivateSpaceAPIClient(
            baseURLString: serverURL,
            deviceName: "iPhone 16 Pro · XCTest"
        )

        let status = try await client.getAuthStatus()
        if !status.initialized {
            _ = try await client.setupAdmin(password: adminPassword, vaultName: "iOS CI Vault")
        } else {
            _ = try await client.login(password: adminPassword)
        }

        // 1. Create encrypted note & password
        let note = try await client.createNote(
            CreateNoteRequest(
                title: "SwiftUI E2E Note",
                content: "- [ ] Verify CryptoKit & Server Sync",
                tags: ["ios", "ci"]
            )
        )
        XCTAssertEqual(note.revision, 1)

        let pw = try await client.createPassword(
            CreatePasswordRequest(
                title: "Apple Developer Portal",
                username: "ios-ci@privatespace.io",
                password: PasswordSecurityEngine.generateSecurePassword(),
                url: "https://developer.apple.com",
                totpSecret: "JBSWY3DPEHPK3PXP",
                category: .dev
            )
        )
        XCTAssertEqual(pw.category, .dev)

        // 2. Upload multi-chunk synthetic MP4 via 64 KiB resumable protocol with SHA-256 integrity
        var syntheticVideo = Data(count: 150 * 1024)
        for i in 0..<syntheticVideo.count {
            syntheticVideo[i] = UInt8(i & 0xff)
        }
        let media = try await client.uploadMediaResumable(
            data: syntheticVideo,
            filename: "ios-cinema-test.mp4",
            mimeType: "video/mp4",
            kind: .video,
            title: "iOS AVPlayer Range Stream Test",
            chunkBytes: 64 * 1024
        )
        XCTAssertEqual(media.byteSize, syntheticVideo.count)
        XCTAssertEqual(media.chunkCount, 3)

        // 3. Verify HTTP 206 Partial Content Range request matching iOS AVPlayer behavior
        let (streamURL, headers) = try await client.makeAuthenticatedStreamDescriptor(
            mediaId: media.id,
            revision: media.revision
        )
        var rangeReq = URLRequest(url: streamURL)
        for (k, v) in headers { rangeReq.setValue(v, forHTTPHeaderField: k) }
        rangeReq.setValue("bytes=40000-110000", forHTTPHeaderField: "Range")

        let (sliceData, resp) = try await URLSession.shared.data(for: rangeReq)
        let http = try XCTUnwrap(resp as? HTTPURLResponse)
        XCTAssertEqual(http.statusCode, 206)
        XCTAssertEqual(sliceData, syntheticVideo.subdata(in: 40000..<110001))

        // 4. Verify incremental `since_seq` sync, cipher inspection & active sessions
        let syncDelta = try await client.pullSync(sinceSeq: 0)
        XCTAssertTrue(syncDelta.notes.contains(where: { $0.id == note.id }))
        XCTAssertTrue(syncDelta.passwords.contains(where: { $0.id == pw.id }))
        XCTAssertTrue(syncDelta.media.contains(where: { $0.id == media.id }))

        let cipher = try await client.inspectCipherEnvelope(itemId: media.id)
        XCTAssertEqual(cipher.chunkStore?.formatMagic, "PSENC001")

        let sessions = try await client.listSessions()
        XCTAssertTrue(sessions.contains(where: { $0.platform == .ios }))
    }
}
