import Foundation
import Security

public struct PasswordGeneratorOptions: Sendable, Equatable {
    public var length: Int
    public var uppercase: Bool
    public var lowercase: Bool
    public var digits: Bool
    public var symbols: Bool
    public var excludeAmbiguous: Bool

    public init(
        length: Int = 20,
        uppercase: Bool = true,
        lowercase: Bool = true,
        digits: Bool = true,
        symbols: Bool = true,
        excludeAmbiguous: Bool = true
    ) {
        self.length = length
        self.uppercase = uppercase
        self.lowercase = lowercase
        self.digits = digits
        self.symbols = symbols
        self.excludeAmbiguous = excludeAmbiguous
    }
}

public struct PassphraseGeneratorOptions: Sendable, Equatable {
    public var wordCount: Int
    public var separator: String
    public var capitalize: Bool
    public var includeNumber: Bool

    public init(
        wordCount: Int = 4,
        separator: String = "-",
        capitalize: Bool = true,
        includeNumber: Bool = true
    ) {
        self.wordCount = wordCount
        self.separator = separator
        self.capitalize = capitalize
        self.includeNumber = includeNumber
    }
}

public struct PasswordEntropyReport: Sendable, Equatable {
    public let entropyBits: Int
    public let score: Int
    public let label: String
    public let warnings: [String]
}

public struct VaultPasswordAuditReport: Sendable, Equatable {
    public let healthScore: Int
    public let totalCount: Int
    public let weakIds: [String]
    public let reusedIds: [String]
    public let missingTotpIds: [String]
    public let staleIds: [String]
}

/// Unbiased CSPRNG Password & Passphrase Generator + Vault Health Auditor + CSV Importer.
public enum PasswordSecurityEngine {
    private static let upperChars = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    private static let lowerChars = Array("abcdefghijklmnopqrstuvwxyz")
    private static let digitChars = Array("0123456789")
    private static let symbolChars = Array("!@#$%^&*()-_=+[]{}<>?")
    private static let ambiguousSet: Set<Character> = ["0", "O", "o", "1", "l", "I", "|"]

    private static let passphraseWords: [String] = [
        "amber", "anchor", "apollo", "arctic", "aspire", "atlas", "aurora", "autumn",
        "bamboo", "beacon", "bison", "breeze", "bridge", "bronze", "canyon", "carbon",
        "cedar", "cipher", "cobalt", "comet", "coral", "cosmos", "crater", "crystal",
        "cypress", "dawn", "delta", "desert", "dolphin", "dune", "eclipse", "ember",
        "emerald", "enigma", "falcon", "fjord", "flint", "forest", "fossil", "galaxy",
        "garnet", "glacier", "granite", "harbor", "harvest", "hazel", "horizon", "indigo",
        "island", "ivory", "jasper", "jungle", "jupiter", "kernel", "lagoon", "lantern",
        "laurel", "legend", "linen", "lotus", "lunar", "magnet", "maple", "marble",
        "meadow", "mercury", "meteor", "mineral", "mirage", "monolith", "moss", "nebula",
        "nectar", "nimbus", "nomad", "nordic", "oak", "oasis", "obsidian", "ocean",
        "olive", "onyx", "orbit", "orchid", "osprey", "oxygen", "pacific", "pebble",
        "phoenix", "pioneer", "planet", "polar", "poppy", "prism", "pulsar", "quartz",
        "quiver", "raven", "redwood", "reef", "ripple", "river", "saffron", "summit",
        "sierra", "silver", "solstice", "sonnet", "spark", "spruce", "starlight", "stone",
        "stream", "sunrise", "tempest", "terra", "thistle", "thunder", "timber", "topaz",
        "trident", "tundra", "velvet", "verde", "vertex", "voyage", "walnut", "zephyr",
    ]

    private static let commonWeakPatterns = [
        "123456", "password", "qwerty", "admin123", "111111", "abc123", "iloveyou", "888888",
    ]

    /// Unbiased rejection-sampling CSPRNG integer in `0..<maxExclusive` using Apple `SecRandomCopyBytes`.
    public static func secureRandomInt(_ maxExclusive: Int) -> Int {
        guard maxExclusive > 1 else { return 0 }
        let bound = UInt32(maxExclusive)
        let maxValid = (UInt64(0x1_0000_0000) / UInt64(bound)) * UInt64(bound)

        while true {
            var randomValue: UInt32 = 0
            let status = withUnsafeMutableBytes(of: &randomValue) { rawBuf in
                guard let base = rawBuf.baseAddress else { return errSecParam }
                return SecRandomCopyBytes(kSecRandomDefault, 4, base)
            }
            if status != errSecSuccess {
                var rng = SystemRandomNumberGenerator()
                return Int.random(in: 0..<maxExclusive, using: &rng)
            }
            if UInt64(randomValue) < maxValid {
                return Int(randomValue % bound)
            }
        }
    }

    private static func filterAmbiguous(_ chars: [Character], exclude: Bool) -> [Character] {
        guard exclude else { return chars }
        return chars.filter { !ambiguousSet.contains($0) }
    }

    public static func generateSecurePassword(
        _ opts: PasswordGeneratorOptions = PasswordGeneratorOptions()
    ) -> String {
        let length = min(128, max(6, opts.length))
        var pools: [[Character]] = []
        if opts.uppercase { pools.append(filterAmbiguous(upperChars, exclude: opts.excludeAmbiguous)) }
        if opts.lowercase { pools.append(filterAmbiguous(lowerChars, exclude: opts.excludeAmbiguous)) }
        if opts.digits { pools.append(filterAmbiguous(digitChars, exclude: opts.excludeAmbiguous)) }
        if opts.symbols { pools.append(filterAmbiguous(symbolChars, exclude: opts.excludeAmbiguous)) }

        var validPools = pools.filter { !$0.isEmpty }
        if validPools.isEmpty {
            validPools.append(filterAmbiguous(lowerChars + digitChars, exclude: opts.excludeAmbiguous))
        }

        let combined = validPools.flatMap { $0 }
        var chars: [Character] = []
        chars.reserveCapacity(length)

        for pool in validPools where chars.count < length {
            chars.append(pool[secureRandomInt(pool.count)])
        }
        while chars.count < length {
            chars.append(combined[secureRandomInt(combined.count)])
        }

        for i in stride(from: chars.count - 1, through: 1, by: -1) {
            let j = secureRandomInt(i + 1)
            chars.swapAt(i, j)
        }

        return String(chars)
    }

    public static func generateMemorablePassphrase(
        _ opts: PassphraseGeneratorOptions = PassphraseGeneratorOptions()
    ) -> String {
        let count = min(10, max(3, opts.wordCount))
        var words: [String] = []
        words.reserveCapacity(count)

        for _ in 0..<count {
            var word = passphraseWords[secureRandomInt(passphraseWords.count)]
            if opts.capitalize, let first = word.first {
                word = String(first).uppercased() + word.dropFirst()
            }
            words.append(word)
        }

        if opts.includeNumber, !words.isEmpty {
            let idx = secureRandomInt(words.count)
            words[idx] = "\(words[idx])\(secureRandomInt(90) + 10)"
        }

        return words.joined(separator: opts.separator)
    }

    public static func evaluatePasswordEntropy(_ password: String) -> PasswordEntropyReport {
        guard !password.isEmpty else {
            return PasswordEntropyReport(
                entropyBits: 0,
                score: 0,
                label: "极弱",
                warnings: ["密码为空"]
            )
        }

        var warnings: [String] = []
        var charsetSize = 0
        if password.contains(where: { $0.isASCII && $0.isLowercase }) { charsetSize += 26 }
        if password.contains(where: { $0.isASCII && $0.isUppercase }) { charsetSize += 26 }
        if password.contains(where: { $0.isASCII && $0.isNumber }) { charsetSize += 10 }
        if password.contains(where: { !($0.isASCII && ($0.isLetter || $0.isNumber)) }) { charsetSize += 32 }

        let chars = Array(password)
        let uniqueRatio = Double(Set(chars).count) / Double(chars.count)
        var entropyBits = Int(
            (Double(chars.count) * log2(Double(max(2, charsetSize))) * (0.55 + 0.45 * uniqueRatio)).rounded()
        )

        let lower = password.lowercased()
        if commonWeakPatterns.contains(where: { lower.contains($0) }) {
            entropyBits = min(entropyBits, 24)
            warnings.append("包含常见弱口令片段")
        }
        if chars.count < 10 {
            warnings.append("长度不足 10 位，建议至少 14 位")
        }
        if hasRepeatedRun(chars, minRun: 3) {
            entropyBits = max(0, entropyBits - 12)
            warnings.append("包含连续重复字符")
        }

        let score: Int
        let label: String
        if entropyBits < 32 || chars.count < 8 {
            score = 0
            label = "极弱"
        } else if entropyBits < 48 {
            score = 1
            label = "较弱"
        } else if entropyBits < 68 {
            score = 2
            label = "一般"
        } else if entropyBits < 92 {
            score = 3
            label = "强"
        } else {
            score = 4
            label = "极强"
        }

        return PasswordEntropyReport(
            entropyBits: entropyBits,
            score: score,
            label: label,
            warnings: warnings
        )
    }

    private static func hasRepeatedRun(_ chars: [Character], minRun: Int) -> Bool {
        guard chars.count >= minRun else { return false }
        var currentRun = 1
        for i in 1..<chars.count {
            if chars[i] == chars[i - 1] {
                currentRun += 1
                if currentRun >= minRun { return true }
            } else {
                currentRun = 1
            }
        }
        return false
    }

    public static func auditPasswordVault(
        _ items: [PasswordItem],
        now: Date = Date()
    ) -> VaultPasswordAuditReport {
        let active = items.filter { !$0.isTrashed }
        guard !active.isEmpty else {
            return VaultPasswordAuditReport(
                healthScore: 100,
                totalCount: 0,
                weakIds: [],
                reusedIds: [],
                missingTotpIds: [],
                staleIds: []
            )
        }

        var weakIds: [String] = []
        var missingTotpIds: [String] = []
        var staleIds: [String] = []
        var byPassword: [String: [String]] = [:]
        let staleThresholdSeconds: TimeInterval = 180 * 24 * 3600
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let fallbackIso = ISO8601DateFormatter()

        for item in active {
            let strength = evaluatePasswordEntropy(item.password)
            if strength.score <= 1 {
                weakIds.append(item.id)
            }
            if !item.password.isEmpty {
                byPassword[item.password, default: []].append(item.id)
            }
            if item.totpSecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                missingTotpIds.append(item.id)
            }
            let tsString = item.passwordChangedAt.isEmpty ? item.updatedAt : item.passwordChangedAt
            if let parsedDate = iso.date(from: tsString) ?? fallbackIso.date(from: tsString),
               now.timeIntervalSince(parsedDate) > staleThresholdSeconds {
                staleIds.append(item.id)
            }
        }

        var reusedSet = Set<String>()
        for ids in byPassword.values where ids.count > 1 {
            for id in ids { reusedSet.insert(id) }
        }
        let reusedIds = active.map(\.id).filter { reusedSet.contains($0) }

        let total = Double(active.count)
        let weakPenalty = (Double(weakIds.count) / total) * 45.0
        let reusedPenalty = (Double(reusedIds.count) / total) * 35.0
        let totpPenalty = (Double(missingTotpIds.count) / total) * 15.0
        let stalePenalty = (Double(staleIds.count) / total) * 5.0
        let rawScore = Int((100.0 - weakPenalty - reusedPenalty - totpPenalty - stalePenalty).rounded())

        return VaultPasswordAuditReport(
            healthScore: max(0, min(100, rawScore)),
            totalCount: active.count,
            weakIds: weakIds,
            reusedIds: reusedIds,
            missingTotpIds: missingTotpIds,
            staleIds: staleIds
        )
    }

    /// Parses Chrome / Apple Passwords / 1Password / Bitwarden CSV exports into `ImportPasswordEntryInput`.
    public static func parsePasswordCsv(_ csvText: String) -> [ImportPasswordEntryInput] {
        let lines = csvText
            .replacingOccurrences(of: "\r\n", with: "\n")
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map(String.init)
        guard lines.count >= 2 else { return [] }

        let headers = parseCsvRow(lines[0]).map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }

        func colIndex(_ candidates: [String]) -> Int? {
            headers.firstIndex(where: { h in candidates.contains(h) })
        }

        let titleIdx = colIndex(["name", "title", "service", "标题", "名称"])
        let urlIdx = colIndex(["url", "login_uri", "website", "网址"])
        let userIdx = colIndex(["username", "login_username", "user", "account", "用户名", "账号"])
        let passIdx = colIndex(["password", "login_password", "密码"])
        let totpIdx = colIndex(["totp", "login_totp", "otpauth", "otp"])
        let notesIdx = colIndex(["note", "notes", "extra", "备注"])

        var entries: [ImportPasswordEntryInput] = []
        for rowLine in lines.dropFirst() {
            let cols = parseCsvRow(rowLine)
            func val(_ idx: Int?) -> String {
                guard let idx, idx < cols.count else { return "" }
                return cols[idx].trimmingCharacters(in: .whitespacesAndNewlines)
            }
            let pw = val(passIdx)
            let url = val(urlIdx)
            let title = val(titleIdx).isEmpty ? AutoFillCredentialRecord.extractNormalizedDomain(from: url) : val(titleIdx)
            guard !pw.isEmpty, (!title.isEmpty || !url.isEmpty) else { continue }

            entries.append(
                ImportPasswordEntryInput(
                    title: title.isEmpty ? "导入凭据" : title,
                    username: val(userIdx),
                    password: pw,
                    url: url,
                    totpSecret: val(totpIdx),
                    category: .login,
                    notes: val(notesIdx)
                )
            )
        }
        return entries
    }

    private static func parseCsvRow(_ line: String) -> [String] {
        var result: [String] = []
        var current = ""
        var inQuotes = false
        let chars = Array(line)
        var i = 0
        while i < chars.count {
            let ch = chars[i]
            if inQuotes {
                if ch == "\"" {
                    if i + 1 < chars.count && chars[i + 1] == "\"" {
                        current.append("\"")
                        i += 2
                        continue
                    } else {
                        inQuotes = false
                    }
                } else {
                    current.append(ch)
                }
            } else {
                if ch == "\"" {
                    inQuotes = true
                } else if ch == "," {
                    result.append(current)
                    current = ""
                } else {
                    current.append(ch)
                }
            }
            i += 1
        }
        result.append(current)
        return result
    }
}
