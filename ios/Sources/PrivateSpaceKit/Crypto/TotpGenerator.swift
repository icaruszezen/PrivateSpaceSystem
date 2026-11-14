import CryptoKit
import Foundation

public enum TotpAlgorithm: String, Codable, Sendable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
}

public struct ParsedTotpConfig: Sendable, Equatable {
    public let secret: String
    public let digits: Int
    public let period: Int
    public let algorithm: TotpAlgorithm
    public let issuer: String?
    public let accountName: String?
}

public struct TotpTokenSnapshot: Sendable, Equatable {
    public let code: String
    public let formattedCode: String
    public let period: Int
    public let remainingSeconds: Int
    /// Fraction elapsed within current window `[0, 1]`
    public let progress: Double
}

public enum TotpError: LocalizedError, Sendable, Equatable {
    case emptySecret
    case missingSecretParam
    case invalidBase32Character(Character)

    public var errorDescription: String? {
        switch self {
        case .emptySecret:
            return "TOTP 密钥为空"
        case .missingSecretParam:
            return "otpauth 链接缺少 secret 参数"
        case .invalidBase32Character(let ch):
            return "非法的 Base32 字符: \(ch)"
        }
    }
}

/// Native Apple CryptoKit RFC 6238 TOTP generator supporting Base32 secrets & `otpauth://` URIs.
public enum TotpGenerator {
    private static let base32Alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    private static let base32Lookup: [Character: UInt32] = {
        var map: [Character: UInt32] = [:]
        for (idx, ch) in base32Alphabet.enumerated() {
            map[ch] = UInt32(idx)
        }
        return map
    }()

    public static func decodeBase32(_ input: String) throws -> Data {
        let cleaned = input
            .uppercased()
            .filter { !$0.isWhitespace && $0 != "-" && $0 != "=" }

        guard !cleaned.isEmpty else {
            throw TotpError.emptySecret
        }

        var bits = 0
        var value: UInt32 = 0
        var output = Data()
        output.reserveCapacity((cleaned.count * 5) / 8)

        for ch in cleaned {
            guard let idx = base32Lookup[ch] else {
                throw TotpError.invalidBase32Character(ch)
            }
            value = (value << 5) | idx
            bits += 5
            if bits >= 8 {
                let byte = UInt8((value >> (bits - 8)) & 0xff)
                output.append(byte)
                bits -= 8
            }
        }

        return output
    }

    public static func parseTotpInput(_ rawInput: String) throws -> ParsedTotpConfig {
        let trimmed = rawInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw TotpError.emptySecret
        }

        if trimmed.lowercased().hasPrefix("otpauth://"),
           let components = URLComponents(string: trimmed) {
            let queryItems = components.queryItems ?? []
            let params = Dictionary(
                uniqueKeysWithValues: queryItems.compactMap { item in
                    item.value.map { (item.name.lowercased(), $0) }
                }
            )

            guard let rawSecret = params["secret"], !rawSecret.isEmpty else {
                throw TotpError.missingSecretParam
            }
            _ = try decodeBase32(rawSecret)
            let cleanedSecret = rawSecret
                .uppercased()
                .filter { !$0.isWhitespace && $0 != "-" && $0 != "=" }

            let digitsRaw = Int(params["digits"] ?? "6") ?? 6
            let digits = digitsRaw == 8 ? 8 : 6

            let periodRaw = Int(params["period"] ?? "30") ?? 30
            let period = periodRaw >= 10 ? periodRaw : 30

            let algParam = (params["algorithm"] ?? "SHA1").uppercased()
            let algorithm: TotpAlgorithm = algParam == "SHA256" ? .sha256 : .sha1

            let rawPath = components.percentEncodedPath
                .removingPercentEncoding ?? components.path
            let strippedLabel = rawPath.replacingOccurrences(
                of: "^/+",
                with: "",
                options: .regularExpression
            )
            let parts = strippedLabel.split(separator: ":", maxSplits: 1).map(String.init)
            let labelIssuer: String? = parts.count == 2 ? parts[0] : nil
            let accountName: String? = parts.count == 2 ? parts[1] : (parts.first?.isEmpty == false ? parts.first : nil)

            return ParsedTotpConfig(
                secret: cleanedSecret,
                digits: digits,
                period: period,
                algorithm: algorithm,
                issuer: params["issuer"] ?? labelIssuer,
                accountName: accountName
            )
        }

        _ = try decodeBase32(trimmed)
        let cleaned = trimmed
            .uppercased()
            .filter { !$0.isWhitespace && $0 != "-" && $0 != "=" }

        return ParsedTotpConfig(
            secret: cleaned,
            digits: 6,
            period: 30,
            algorithm: .sha1,
            issuer: nil,
            accountName: nil
        )
    }

    public static func generateTotp(
        _ rawInput: String,
        date: Date = Date()
    ) throws -> TotpTokenSnapshot {
        return try generateTotp(
            rawInput,
            timestampMs: Int64((date.timeIntervalSince1970 * 1000.0).rounded(.down))
        )
    }

    public static func generateTotp(
        _ rawInput: String,
        timestampMs: Int64
    ) throws -> TotpTokenSnapshot {
        let cfg = try parseTotpInput(rawInput)
        let keyData = try decodeBase32(cfg.secret)
        let symmetricKey = SymmetricKey(data: keyData)

        let epochSeconds = max(0, timestampMs / 1000)
        let counter = UInt64(epochSeconds) / UInt64(cfg.period)
        var bigEndianCounter = counter.bigEndian
        let counterData = Data(bytes: &bigEndianCounter, count: MemoryLayout<UInt64>.size)

        let digestBytes: [UInt8]
        switch cfg.algorithm {
        case .sha1:
            let mac = HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: symmetricKey)
            digestBytes = Array(mac)
        case .sha256:
            let mac = HMAC<SHA256>.authenticationCode(for: counterData, using: symmetricKey)
            digestBytes = Array(mac)
        }

        let offset = Int(digestBytes[digestBytes.count - 1] & 0x0f)
        let binary: UInt32 =
            (UInt32(digestBytes[offset] & 0x7f) << 24) |
            (UInt32(digestBytes[offset + 1]) << 16) |
            (UInt32(digestBytes[offset + 2]) << 8) |
            UInt32(digestBytes[offset + 3])

        let mod: UInt32 = cfg.digits == 8 ? 100_000_000 : 1_000_000
        let rawCode = String(binary % mod)
        let padded = String(repeating: "0", count: max(0, cfg.digits - rawCode.count)) + rawCode
        let half = padded.count / 2
        let splitIdx = padded.index(padded.startIndex, offsetBy: half)
        let formatted = "\(padded[..<splitIdx]) \(padded[splitIdx...])"

        let elapsed = (Double(timestampMs) / 1000.0)
            .truncatingRemainder(dividingBy: Double(cfg.period))
        let remaining = max(1, Int(ceil(Double(cfg.period) - elapsed)))
        let progress = min(1.0, max(0.0, elapsed / Double(cfg.period)))

        return TotpTokenSnapshot(
            code: padded,
            formattedCode: formatted,
            period: cfg.period,
            remainingSeconds: remaining,
            progress: progress
        )
    }
}
