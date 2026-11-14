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

        let rawCacheBytes = try Data(contentsOf: store.snapshotFileURL)
        let rawAutoFillBytes = try Data(contentsOf: store.autoFillFileURL)
        XCTAssertEqual(rawCacheBytes.subdata(in: 0..<8), Data("PSCACHE1".utf8))
        XCTAssertEqual(rawAutoFillBytes.subdata(in: 0..<8), Data("PSCACHE1".utf8))
        XCTAssertNil(rawCacheBytes.range(of: Data(secretNoteBody.utf8)))
        XCTAssertNil(rawCacheBytes.range(of: Data(secretPasswordVal.utf8)))
        XCTAssertNil(rawAutoFillBytes.range(of: Data(secretPasswordVal.utf8)))

        let restored = try store.loadSnapshot()
        XCTAssertEqual(restored?.notes["n1"]?.content, secretNoteBody)
        XCTAssertEqual(restored?.passwords["p1"]?.password, secretPasswordVal)

        let matched = try store.loadAutoFillCredentials(matching: ["https://gist.github.com"])
        XCTAssertEqual(matched.count, 1)
        XCTAssertEqual(matched.first?.password, secretPasswordVal)

        var tampered = rawCacheBytes
        tampered[tampered.count - 4] ^= 0x80
        try tampered.write(to: store.snapshotFileURL)
        XCTAssertThrowsError(try store.loadSnapshot())

        store.shredLocalCache()
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.snapshotFileURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.autoFillFileURL.path))
    }

    // MARK: - 4. Cross-Language Zero-Knowledge E2EE v2 & PSENC001 Parity Vectors

    func testZeroKnowledgeCrossLanguageVectorsAndPsencChunking() throws {
        // Exact deterministic vectors generated from `src/shared/e2ee.ts`
        let saltB64 = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw="
        let expectedKekHex = "7b3c95e650de1d796b9ce386aa821846fe0b829d2d6169580390d1bb9c6db41e"
        let expectedAuthKeyB64 = "BUdAo3rUoqtEVmxB0AGl5xE9+EXLlNYUccqAZBoM5l4="
        let expectedDekB64 = "CRYjMD1KV2RxfouYpbK/zNnm8wANGic0QU5baHWCj5w="

        let derived = try VaultE2EECrypto.deriveMasterKeysFromPassword(
            password: "SwiftCrossVector!2026",
            kdfSaltBase64: saltB64,
            kdfParams: E2EEKdfParams(iterations: 12_000)
        )
        XCTAssertEqual(VaultE2EECrypto.bytesToHex(derived.kek), expectedKekHex)
        XCTAssertEqual(derived.authKeyBase64, expectedAuthKeyB64)

        let wrappedFromTs = WrappedDekDto(
            iv: "AQIDBAUGBwgJCgsM",
            tag: "GisJGMLfw8gAUufU7AoFVg==",
            ciphertext: "ZkJJvIlf/1OVK4thy9HUT/RJOEMSRp8HdoaLGCm9pNc="
        )
        let unwrappedDek = try VaultE2EECrypto.unwrapMasterDek(wrappedDek: wrappedFromTs, kek: derived.kek)
        XCTAssertEqual(unwrappedDek.base64EncodedString(), expectedDekB64)
        XCTAssertEqual(try VaultE2EECrypto.computeKeyFingerprint(dek: unwrappedDek), "B9EE-F980-A7AB")

        // Decrypt Note envelope encrypted by TypeScript `src/shared/e2ee.ts`
        let tsNoteEnvelope = CipherEnvelopeDto(
            cipherVersion: 2,
            itemSalt: "AgcMERYbICUqLzQ5PkNITQ==",
            nonce: "Cw4RFBcaHSAjJiks",
            authTag: "yePmpgUvOllEyGItFeW+Cw==",
            ciphertext: "lpTTl5SaUD82vjTUchuM7JF2SsiL3EseDUZ35K5X52Ps2I3CEMTkCoaDXSlN1YppPlrDF/YeF+OG9hEzbSyANzEm991OVg7w/wsxWsA4eqpO85G1FLjAtzQXc2vbSAFuraLxYH3G8J42rl8ogOc4i6UVeQEWr5wccbzoK0qA"
        )
        let decryptedTsNote = try VaultE2EECrypto.decryptItemPayload(
            NoteDecryptedPayload.self,
            dek: unwrappedDek,
            itemId: "vec-note-001",
            itemType: .note,
            revision: 1,
            envelope: tsNoteEnvelope
        )
        XCTAssertEqual(decryptedTsNote.title, "Vector")
        XCTAssertEqual(decryptedTsNote.content, "Hello Swift E2EE")
        XCTAssertEqual(decryptedTsNote.tags, ["e2ee"])

        // Verify PSENC001 20B header & chunk nonce derivation match TypeScript byte-for-byte
        let headerHex = VaultE2EECrypto.bytesToHex(
            VaultE2EECrypto.encodePsencHeader(plainSize: 150_000, chunkPlainSize: 65_536)
        )
        XCTAssertEqual(headerHex, "5053454e433030310001000000000000000249f0")

        let baseIv = try XCTUnwrap(Data(base64Encoded: "AQIDBAUGBwgJCgsM"))
        let nonce2Hex = VaultE2EECrypto.bytesToHex(
            try VaultE2EECrypto.derivePsencChunkNonce(baseNonce: baseIv, chunkIndex: 2)
        )
        XCTAssertEqual(nonce2Hex, "0102030405060708090a0b0e")

        // Multi-chunk PSENC001 full + arbitrary cross-chunk HTTP 206 range decryption + tamper rejection
        var plainMedia = Data(count: 145_000)
        for i in 0..<plainMedia.count {
            plainMedia[i] = UInt8((i * 31 + 17) & 0xff)
        }
        let (psencData, meta) = try VaultE2EECrypto.encryptMediaBytesToPsenc(dek: unwrappedDek, plainData: plainMedia)
        XCTAssertEqual(meta.chunkCount, 3)
        XCTAssertEqual(psencData.subdata(in: 0..<8), Data("PSENC001".utf8))
        XCTAssertEqual(try VaultE2EECrypto.decryptPsencFullBuffer(dek: unwrappedDek, encryptedData: psencData, meta: meta), plainMedia)

        let range = VaultE2EECrypto.computeEncryptedRangeForPlainRange(
            meta: meta,
            startPlainByte: 50_000,
            endPlainByte: 132_000
        )
        let cipherRangeSlice = psencData.subdata(in: range.diskStart..<(range.diskEnd + 1))
        let decryptedRange = try VaultE2EECrypto.decryptPsencRangeSlice(
            dek: unwrappedDek,
            encryptedSlice: cipherRangeSlice,
            meta: meta,
            range: range
        )
        XCTAssertEqual(decryptedRange, plainMedia.subdata(in: 50_000..<132_001))

        var tamperedPsenc = psencData
        tamperedPsenc[tamperedPsenc.count - 5] ^= 0x01
        XCTAssertThrowsError(
            try VaultE2EECrypto.decryptPsencFullBuffer(dek: unwrappedDek, encryptedData: tamperedPsenc, meta: meta)
        )
    }

    // MARK: - 5. Live PrivateSpace Zero-Knowledge Server End-to-End Integration Test (CI Automated)

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
            _ = try await client.setupAdmin(
                password: adminPassword,
                vaultName: "iOS Zero-Knowledge CI Vault",
                iterations: 20_000
            )
        } else {
            _ = try await client.login(password: adminPassword)
        }

        // Verify unauthenticated `/api/v1/auth/params` NEVER leaks `wrappedDek` and legacy plaintext login is rejected
        var paramsReq = URLRequest(url: try XCTUnwrap(URL(string: "\(serverURL)/api/v1/auth/params")))
        paramsReq.httpMethod = "GET"
        let (paramsRaw, _) = try await URLSession.shared.data(for: paramsReq)
        let paramsJsonStr = String(decoding: paramsRaw, as: UTF8.self)
        XCTAssertFalse(paramsJsonStr.contains("wrappedDek"))

        var legacyLoginReq = URLRequest(url: try XCTUnwrap(URL(string: "\(serverURL)/api/v1/auth/login")))
        legacyLoginReq.httpMethod = "POST"
        legacyLoginReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
        legacyLoginReq.httpBody = Data("{\"password\":\"\(adminPassword)\"}".utf8)
        let (_, legacyResp) = try await URLSession.shared.data(for: legacyLoginReq)
        XCTAssertEqual((legacyResp as? HTTPURLResponse)?.statusCode, 400)

        // 1. Create client-encrypted note, password & album
        let note = try await client.createNote(
            CreateNoteRequest(
                title: "SwiftUI Zero-Knowledge Note",
                content: "- [x] Verify Client-Side E2EE v2 & Server Blindness",
                tags: ["ios", "e2ee"]
            )
        )
        XCTAssertEqual(note.revision, 1)
        XCTAssertEqual(note.title, "SwiftUI Zero-Knowledge Note")

        let secretCredential = PasswordSecurityEngine.generateSecurePassword()
        let pw = try await client.createPassword(
            CreatePasswordRequest(
                title: "Apple Developer Portal",
                username: "ios-ci@privatespace.io",
                password: secretCredential,
                url: "https://developer.apple.com",
                totpSecret: "JBSWY3DPEHPK3PXP",
                category: .dev
            )
        )
        XCTAssertEqual(pw.category, .dev)
        XCTAssertEqual(pw.password, secretCredential)

        let album = try await client.createAlbum(CreateAlbumRequest(name: "iOS 零知识相册", kind: "video"))
        XCTAssertEqual(album.name, "iOS 零知识相册")

        // 2. Upload multi-chunk synthetic MP4 via client-side PSENC001 64 KiB resumable protocol
        var syntheticVideo = Data(count: 150 * 1024)
        for i in 0..<syntheticVideo.count {
            syntheticVideo[i] = UInt8((i * 7 + 13) & 0xff)
        }
        let media = try await client.uploadMediaResumable(
            data: syntheticVideo,
            filename: "ios-e2ee-cinema.mp4",
            mimeType: "video/mp4",
            kind: .video,
            title: "iOS AVPlayer E2EE Range Stream Test",
            albumId: album.id,
            chunkBytes: 64 * 1024
        )
        XCTAssertEqual(media.byteSize, syntheticVideo.count)
        XCTAssertEqual(media.chunkCount, 3)

        // 3. Prove raw server stream serves PSENC001 ciphertext (NOT plaintext) AND client range decryption recovers exact bytes
        let (streamURL, headers) = try await client.makeAuthenticatedStreamDescriptor(
            mediaId: media.id,
            revision: media.revision
        )
        var rawHeadReq = URLRequest(url: streamURL)
        for (k, v) in headers { rawHeadReq.setValue(v, forHTTPHeaderField: k) }
        rawHeadReq.setValue("bytes=0-31", forHTTPHeaderField: "Range")
        let (rawCipherHead, rawResp) = try await URLSession.shared.data(for: rawHeadReq)
        XCTAssertEqual((rawResp as? HTTPURLResponse)?.statusCode, 206)
        XCTAssertEqual(rawCipherHead.subdata(in: 0..<8), Data("PSENC001".utf8))

        let decryptedRangeSlice = try await client.fetchDecryptedMediaByteRange(
            mediaId: media.id,
            startPlainByte: 40_000,
            endPlainByte: 110_000,
            blobMeta: media.blobKeyBundle?.main
        )
        XCTAssertEqual(decryptedRangeSlice, syntheticVideo.subdata(in: 40_000..<110_001))

        // 4. Verify incremental `since_seq` sync, cipher v2 inspection & Zero-Knowledge KEK password rotation
        let syncDelta = try await client.pullSync(sinceSeq: 0)
        XCTAssertTrue(syncDelta.notes.contains(where: { $0.id == note.id && $0.title == "SwiftUI Zero-Knowledge Note" }))
        XCTAssertTrue(syncDelta.passwords.contains(where: { $0.id == pw.id && $0.password == secretCredential }))
        XCTAssertTrue(syncDelta.media.contains(where: { $0.id == media.id }))
        XCTAssertTrue(syncDelta.albums.contains(where: { $0.id == album.id && $0.name == "iOS 零知识相册" }))

        let cipher = try await client.inspectCipherEnvelope(itemId: media.id)
        XCTAssertEqual(cipher.cipherVersion, 2)
        XCTAssertEqual(cipher.chunkStore?.formatMagic, "PSENC001")

        let sessions = try await client.listSessions()
        XCTAssertTrue(sessions.contains(where: { $0.platform == .ios }))

        // Rotate master password without re-encrypting media, then verify a second iOS client can unlock and decrypt
        let rotatedPassword = "\(adminPassword)#Rotated99"
        let rotResp = try await client.changeMasterPassword(
            ChangePasswordRequest(
                currentPassword: adminPassword,
                newPassword: rotatedPassword,
                revokeOtherSessions: false
            )
        )
        XCTAssertTrue(rotResp.ok)

        let secondClient = PrivateSpaceAPIClient(
            baseURLString: serverURL,
            deviceName: "iPad Pro · XCTest Verify"
        )
        _ = try await secondClient.login(password: rotatedPassword)
        let fullDecryptedFromSecondDevice = try await secondClient.fetchFullMediaData(mediaId: media.id)
        XCTAssertEqual(fullDecryptedFromSecondDevice, syntheticVideo)
    }
}
