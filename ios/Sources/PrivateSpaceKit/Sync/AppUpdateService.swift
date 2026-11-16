import Foundation

/// SemVer 2.0 parser & comparator matching `src/shared/appUpdate.ts` across Web, Android, and iOS.
public struct SemverVersion: Comparable, Equatable, Sendable, CustomStringConvertible {
    public let major: Int
    public let minor: Int
    public let patch: Int
    public let prerelease: [String]
    public let normalized: String

    public var description: String { normalized }

    public init?(parsing raw: String) {
        var trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("v") || trimmed.hasPrefix("V") {
            trimmed.removeFirst()
        }
        guard !trimmed.isEmpty else { return nil }

        let withoutBuild = String(trimmed.split(separator: "+", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
        let dashParts = withoutBuild.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
        let corePart = String(dashParts[0])
        let prePart = dashParts.count > 1 ? String(dashParts[1]) : ""

        let nums = corePart.split(separator: ".", omittingEmptySubsequences: false)
        guard nums.count == 2 || nums.count == 3 else { return nil }
        guard let maj = Int(nums[0]), maj >= 0, nums[0].allSatisfy(\.isNumber),
              let min = Int(nums[1]), min >= 0, nums[1].allSatisfy(\.isNumber) else {
            return nil
        }
        let pat: Int
        if nums.count == 3 {
            guard let p = Int(nums[2]), p >= 0, nums[2].allSatisfy(\.isNumber) else { return nil }
            pat = p
        } else {
            pat = 0
        }

        let preTokens = prePart.isEmpty
            ? []
            : prePart.split(separator: ".").map { String($0).trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }

        self.major = maj
        self.minor = min
        self.patch = pat
        self.prerelease = preTokens
        let base = "\(maj).\(min).\(pat)"
        self.normalized = preTokens.isEmpty ? base : "\(base)-\(preTokens.joined(separator: "."))"
    }

    public var computedBuildNumber: Int {
        max(1, major * 10_000 + minor * 100 + patch)
    }

    public static func < (lhs: SemverVersion, rhs: SemverVersion) -> Bool {
        if lhs.major != rhs.major { return lhs.major < rhs.major }
        if lhs.minor != rhs.minor { return lhs.minor < rhs.minor }
        if lhs.patch != rhs.patch { return lhs.patch < rhs.patch }

        if lhs.prerelease.isEmpty && rhs.prerelease.isEmpty { return false }
        // A normal release has higher precedence than a prerelease of the same major.minor.patch
        if lhs.prerelease.isEmpty { return false }
        if rhs.prerelease.isEmpty { return true }

        let maxCount = max(lhs.prerelease.count, rhs.prerelease.count)
        for idx in 0..<maxCount {
            if idx >= lhs.prerelease.count { return true }
            if idx >= rhs.prerelease.count { return false }
            let a = lhs.prerelease[idx]
            let b = rhs.prerelease[idx]
            if a == b { continue }

            let numA = a.allSatisfy(\.isNumber) ? Int(a) : nil
            let numB = b.allSatisfy(\.isNumber) ? Int(b) : nil
            if let na = numA, let nb = numB {
                return na < nb
            }
            if numA != nil { return true }
            if numB != nil { return false }
            return a < b
        }
        return false
    }
}

public struct ResolvedIosInstallAction: Sendable, Equatable {
    public let title: String
    public let subtitle: String
    public let systemImage: String
    public let url: URL
}

public enum AppUpdateService {
    public static let defaultGithubRepo = "icaruszezen/PrivateSpaceSystem"
    public static let defaultGithubApiBase = "https://api.github.com"
    public static let fallbackMarketingVersion = "0.6.1"
    public static let fallbackBuildNumber = 601

    private struct GithubAssetPayload: Decodable, Sendable {
        let name: String
        let size: Int?
        let browser_download_url: String
        let digest: String?
    }

    private struct GithubReleasePayload: Decodable, Sendable {
        let tag_name: String
        let name: String?
        let body: String?
        let draft: Bool?
        let prerelease: Bool?
        let published_at: String?
        let html_url: String?
        let assets: [GithubAssetPayload]?
    }

    public static func currentAppVersionAndBuild(bundle: Bundle = .main) -> (version: String, build: Int) {
        let rawVer = (bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? ""
        let rawBuild = (bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String) ?? ""
        let bundleId = bundle.bundleIdentifier ?? ""

        // When running under `swift test` / `xctest`, Bundle.main is the XCTest runner rather than PrivateSpaceIOS.
        if bundleId.contains("xctest") || rawVer.isEmpty || rawVer.contains("$(") {
            return (fallbackMarketingVersion, fallbackBuildNumber)
        }

        let cleanVersion = SemverVersion(parsing: rawVer)?.normalized ?? fallbackMarketingVersion
        let buildNum = Int(rawBuild) ?? SemverVersion(parsing: cleanVersion)?.computedBuildNumber ?? fallbackBuildNumber
        return (cleanVersion, buildNum)
    }

    public static func normalizeGithubRepo(_ raw: String?) -> String? {
        guard let raw else { return nil }
        var cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty else { return nil }

        if let range = cleaned.range(of: "https://github.com/", options: [.caseInsensitive, .anchored]) {
            cleaned.removeSubrange(range)
        } else if let range = cleaned.range(of: "http://github.com/", options: [.caseInsensitive, .anchored]) {
            cleaned.removeSubrange(range)
        }
        cleaned = cleaned.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if cleaned.lowercased().hasSuffix(".git") {
            cleaned = String(cleaned.dropLast(4))
        }
        cleaned = cleaned.trimmingCharacters(in: CharacterSet(charactersIn: "/"))

        let parts = cleaned.split(separator: "/").map(String.init)
        guard parts.count >= 2 else { return nil }
        let owner = parts[0]
        var repo = parts[1]
        if repo.lowercased().hasSuffix(".git") {
            repo = String(repo.dropLast(4))
        }
        guard owner != ".", owner != "..", repo != ".", repo != ".." else { return nil }

        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_.-"))
        guard owner.unicodeScalars.allSatisfy({ allowed.contains($0) }),
              repo.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            return nil
        }
        return "\(owner)/\(repo)"
    }

    public static func buildItmsServicesURL(manifestURL: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&+=?")
        let encoded = manifestURL.addingPercentEncoding(withAllowedCharacters: allowed) ?? manifestURL
        return "itms-services://?action=download-manifest&url=\(encoded)"
    }

    public static func buildAltStoreURL(ipaURL: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&+=?")
        let encoded = ipaURL.addingPercentEncoding(withAllowedCharacters: allowed) ?? ipaURL
        return "altstore://install?url=\(encoded)"
    }

    public static func buildAppStoreURL(appStoreId: String) -> String {
        let digits = appStoreId.replacingOccurrences(of: "id", with: "", options: [.caseInsensitive, .anchored])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return "itms-apps://itunes.apple.com/app/id\(digits)"
    }

    public static func parseSha256Sums(_ text: String) -> [String: String] {
        var map: [String: String] = [:]
        let hexChars = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let cols = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard cols.count >= 2 else { continue }
            let hash = cols[0].lowercased()
            guard hash.count == 64, hash.unicodeScalars.allSatisfy({ hexChars.contains($0) }) else { continue }
            var file = cols[1]
            if file.hasPrefix("*") { file.removeFirst() }
            let baseName = (file as NSString).lastPathComponent
            map[baseName] = hash
            map[file] = hash
        }
        return map
    }

    public static func resolveFromGithubReleasesData(
        _ data: Data,
        repository: String,
        channel: UpdateChannel,
        currentVersion: String,
        currentBuild: Int,
        sha256Map: [String: String] = [:]
    ) throws -> AppUpdateCheckResponseDTO {
        let releases = try JSONDecoder().decode([GithubReleasePayload].self, from: data)
        let nowIso = ISO8601DateFormatter().string(from: Date())
        let normalizedRepo = normalizeGithubRepo(repository) ?? defaultGithubRepo
        let curSemver = SemverVersion(parsing: currentVersion)
        let cleanCurVer = curSemver?.normalized ?? currentVersion

        let eligible = releases.filter { rel in
            if rel.draft == true { return false }
            if channel == .stable && rel.prerelease == true { return false }
            return SemverVersion(parsing: rel.tag_name) != nil
        }
        .sorted { a, b in
            guard let va = SemverVersion(parsing: a.tag_name),
                  let vb = SemverVersion(parsing: b.tag_name) else { return false }
            return va > vb
        }

        guard let latest = eligible.first,
              let latestSemver = SemverVersion(parsing: latest.tag_name) else {
            return AppUpdateCheckResponseDTO(
                checkedAt: nowIso,
                source: "github-direct",
                repository: normalizedRepo,
                channel: channel,
                currentVersion: cleanCurVer,
                currentBuild: currentBuild,
                latestVersion: cleanCurVer,
                latestBuild: currentBuild,
                hasUpdate: false,
                releaseName: "PrivateSpace v\(cleanCurVer)",
                releaseNotes: "",
                htmlUrl: "https://github.com/\(normalizedRepo)/releases"
            )
        }

        let latestBuild = latestSemver.computedBuildNumber
        let hasUpdate: Bool
        if let curSemver {
            hasUpdate = latestSemver > curSemver
        } else {
            hasUpdate = latestSemver.normalized != cleanCurVer
        }

        let assets = latest.assets ?? []
        let ipaAsset = assets.first { $0.name.lowercased().hasSuffix(".ipa") }
        let plistAsset = assets.first {
            let lower = $0.name.lowercased()
            return lower.hasSuffix(".plist") && (lower.contains("manifest") || lower.contains("ios") || lower.contains("ota"))
        }

        var resolvedAsset: PlatformReleaseAssetDTO? = nil
        if let ipaAsset {
            var sha: String? = sha256Map[ipaAsset.name]
            if sha == nil, let digest = ipaAsset.digest, digest.lowercased().hasPrefix("sha256:") {
                let candidate = String(digest.dropFirst(7)).lowercased()
                if candidate.count == 64 { sha = candidate }
            }
            let otaUrl = plistAsset?.browser_download_url
            let itmsUrl = otaUrl.map(buildItmsServicesURL(manifestURL:))
            let altUrl = buildAltStoreURL(ipaURL: ipaAsset.browser_download_url)
            let isUnsigned = ipaAsset.name.lowercased().contains("unsigned")
            resolvedAsset = PlatformReleaseAssetDTO(
                platform: "ios",
                version: latestSemver.normalized,
                buildNumber: latestBuild,
                fileName: ipaAsset.name,
                downloadUrl: ipaAsset.browser_download_url,
                sha256: sha,
                fileSize: ipaAsset.size,
                signingMode: isUnsigned ? "unsigned-sideload" : "adhoc-ota",
                iosInstallMethod: itmsUrl != nil ? .otaItms : .ipaRelease,
                otaManifestUrl: otaUrl,
                itmsServicesUrl: itmsUrl,
                altStoreUrl: altUrl
            )
        }

        return AppUpdateCheckResponseDTO(
            checkedAt: nowIso,
            source: "github-direct",
            repository: normalizedRepo,
            channel: channel,
            currentVersion: cleanCurVer,
            currentBuild: currentBuild,
            latestVersion: latestSemver.normalized,
            latestBuild: latestBuild,
            hasUpdate: hasUpdate,
            mandatory: false,
            prerelease: latest.prerelease ?? !latestSemver.prerelease.isEmpty,
            releaseName: (latest.name?.isEmpty == false) ? latest.name! : "PrivateSpace v\(latestSemver.normalized)",
            releaseNotes: latest.body ?? "",
            publishedAt: latest.published_at,
            htmlUrl: latest.html_url ?? "https://github.com/\(normalizedRepo)/releases",
            asset: resolvedAsset
        )
    }

    public static func fetchFromGithubReleases(
        repository: String,
        channel: UpdateChannel,
        currentVersion: String,
        currentBuild: Int,
        apiBaseURL: String = defaultGithubApiBase,
        urlSession: URLSession = .shared
    ) async throws -> AppUpdateCheckResponseDTO {
        guard let normalizedRepo = normalizeGithubRepo(repository) else {
            throw PrivateSpaceClientError.invalidServerURL("GitHub 仓库格式应为 owner/repo")
        }
        let trimmedBase = apiBaseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let url = URL(string: "\(trimmedBase)/repos/\(normalizedRepo)/releases?per_page=10") else {
            throw PrivateSpaceClientError.invalidServerURL(apiBaseURL)
        }

        var req = URLRequest(url: url)
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        req.setValue("PrivateSpace-IOS/2.0", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await urlSession.data(for: req)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw PrivateSpaceClientError.serverError(
                status: http.statusCode,
                code: "GITHUB_HTTP_\(http.statusCode)",
                message: "GitHub Releases 查询失败 (HTTP \(http.statusCode))"
            )
        }

        // Best-effort fetch SHA256SUMS.txt if present on the top release
        var shaMap: [String: String] = [:]
        if let rawArray = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]],
           let firstRel = rawArray.first,
           let assets = firstRel["assets"] as? [[String: Any]],
           let sumsAsset = assets.first(where: {
               guard let name = ($0["name"] as? String)?.lowercased() else { return false }
               return name == "sha256sums.txt" || name == "sha256sums"
           }),
           let sumsUrlStr = sumsAsset["browser_download_url"] as? String,
           let sumsUrl = URL(string: sumsUrlStr),
           let (sumsData, sumsResp) = try? await urlSession.data(from: sumsUrl),
           (sumsResp as? HTTPURLResponse)?.statusCode == 200,
           let sumsText = String(data: sumsData, encoding: .utf8) {
            shaMap = parseSha256Sums(sumsText)
        }

        return try resolveFromGithubReleasesData(
            data,
            repository: normalizedRepo,
            channel: channel,
            currentVersion: currentVersion,
            currentBuild: currentBuild,
            sha256Map: shaMap
        )
    }

    public static func resolveInstallActions(from info: AppUpdateCheckResponseDTO) -> [ResolvedIosInstallAction] {
        var actions: [ResolvedIosInstallAction] = []
        if let asset = info.asset {
            if let itms = asset.itmsServicesUrl, let url = URL(string: itms) {
                actions.append(
                    ResolvedIosInstallAction(
                        title: "无线 OTA 安装更新 (itms-services)",
                        subtitle: "通过 Apple 企业/Ad-Hoc 清单直接在 iPhone 桌面覆盖升级",
                        systemImage: "arrow.down.app.fill",
                        url: url
                    )
                )
            }
            if let tf = asset.testFlightUrl, let url = URL(string: tf) {
                actions.append(
                    ResolvedIosInstallAction(
                        title: "在 TestFlight 中更新",
                        subtitle: "打开 Apple TestFlight 安装最新签名构建",
                        systemImage: "airplane.circle.fill",
                        url: url
                    )
                )
            }
            if let store = asset.appStoreUrl, let url = URL(string: store) {
                actions.append(
                    ResolvedIosInstallAction(
                        title: "前往 App Store 更新",
                        subtitle: "打开 App Store 官方商店页升级",
                        systemImage: "bag.fill",
                        url: url
                    )
                )
            }
            if let alt = asset.altStoreUrl, let url = URL(string: alt) {
                actions.append(
                    ResolvedIosInstallAction(
                        title: "使用 AltStore / SideStore 安装",
                        subtitle: "自动导入 GitHub Release .ipa 进行本机自签安装",
                        systemImage: "square.and.arrow.down.on.square.fill",
                        url: url
                    )
                )
            }
            if let dl = URL(string: asset.downloadUrl) {
                actions.append(
                    ResolvedIosInstallAction(
                        title: "下载 .ipa 安装包 (\(asset.fileName))",
                        subtitle: "保存至「文件」以配合 TrollStore / Sideloadly 安装",
                        systemImage: "arrow.down.doc.fill",
                        url: dl
                    )
                )
            }
        }
        if let html = URL(string: info.htmlUrl) {
            actions.append(
                ResolvedIosInstallAction(
                    title: "打开 GitHub Release 发布页",
                    subtitle: info.repository,
                    systemImage: "safari.fill",
                    url: html
                )
            )
        }
        return actions
    }
}
