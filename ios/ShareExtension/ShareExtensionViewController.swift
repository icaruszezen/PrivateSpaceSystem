import Foundation
import Observation
import PrivateSpaceKit
import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct StagedShareAttachment: Identifiable, Sendable {
    let id: String
    let filename: String
    let mimeType: String
    let category: TransferFileCategory
    let byteSize: Int
    let stagedFileURL: URL
    let sharedText: String?
}

private struct CopiedProviderFile: Sendable {
    let fileURL: URL
    let filename: String
    let mimeType: String?
    let byteSize: Int
}

@MainActor
@Observable
private final class ShareSendProgressState {
    var currentFileIndex: Int = 0
    var currentProgress: Double = 0
}

/// Native iOS System Share Extension (`com.apple.share-services`, display name: `发送`).
/// Accepts arbitrary files, photos, videos, archives, code, packages, URLs, or text from any iOS app,
/// encrypts them on-device in `PSENC001` (`AES-256-GCM` 64 KiB chunks), and sends them to Multi-Device Transfer Space.
@objc(ShareExtensionViewController)
final class ShareExtensionViewController: UIViewController {
    private let secretStore = AppleKeychainStore(
        service: "io.privatespace.ios.keychain",
        accessGroup: nil
    )
    private lazy var localStore = EncryptedLocalVaultStore(
        appGroupIdentifier: "group.io.privatespace.ios",
        secretStore: secretStore
    )
    private let biometricService = BiometricAuthService()
    private let stagingDir: URL = FileManager.default.temporaryDirectory
        .appendingPathComponent("pss-inbound-share-\(UUID().uuidString)", isDirectory: true)

    override func viewDidLoad() {
        super.viewDidLoad()
        try? FileManager.default.createDirectory(at: stagingDir, withIntermediateDirectories: true)
        mountShareSendView()
    }

    deinit {
        Self.shredStagingDirectory(stagingDir)
    }

    private func mountShareSendView() {
        let extensionItems = (extensionContext?.inputItems as? [NSExtensionItem]) ?? []
        let targetDir = stagingDir
        let store = localStore

        let rootView = ShareExtensionSendSheetView(
            biometricService: biometricService,
            loadSession: {
                try? store.loadShareExtensionSession()
            },
            extractAttachments: {
                await Self.extractSharedAttachments(from: extensionItems, into: targetDir)
            },
            onCompleted: { [weak self] in
                guard let self else { return }
                Self.shredStagingDirectory(self.stagingDir)
                self.extensionContext?.completeRequest(returningItems: [], completionHandler: nil)
            },
            onCancel: { [weak self] in
                guard let self else { return }
                Self.shredStagingDirectory(self.stagingDir)
                let cancelErr = NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError)
                self.extensionContext?.cancelRequest(withError: cancelErr)
            }
        )

        let host = UIHostingController(rootView: rootView)
        addChild(host)
        host.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            host.view.topAnchor.constraint(equalTo: view.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        host.didMove(toParent: self)
    }

    nonisolated private static func shredStagingDirectory(_ dir: URL) {
        if let files = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.fileSizeKey]) {
            for file in files {
                if let size = (try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize),
                   size > 0,
                   size <= 8 * 1024 * 1024 {
                    let zeros = Data(repeating: 0, count: size)
                    try? zeros.write(to: file, options: .atomic)
                }
            }
        }
        try? FileManager.default.removeItem(at: dir)
    }

    static func extractSharedAttachments(
        from items: [NSExtensionItem],
        into stagingDir: URL
    ) async -> [StagedShareAttachment] {
        var results: [StagedShareAttachment] = []
        var indexCounter = 0

        for item in items {
            let sharedNote = item.attributedContentText?.string.trimmingCharacters(in: .whitespacesAndNewlines)
            let providers = item.attachments ?? []

            for provider in providers {
                indexCounter += 1
                if let staged = await extractSingleProvider(
                    provider,
                    index: indexCounter,
                    sharedText: sharedNote,
                    stagingDir: stagingDir
                ) {
                    results.append(staged)
                }
            }
        }
        return results
    }

    private static func extractSingleProvider(
        _ provider: NSItemProvider,
        index: Int,
        sharedText: String?,
        stagingDir: URL
    ) async -> StagedShareAttachment? {
        let suggested = provider.suggestedName?.trimmingCharacters(in: .whitespacesAndNewlines)

        // 1. Prefer arbitrary file representation (`public.item` / `public.content` / `public.data`)
        let candidateTypes: [UTType] = [.fileURL, .movie, .image, .pdf, .archive, .audio, .data, .item]
        for utType in candidateTypes where provider.hasItemConformingToTypeIdentifier(utType.identifier) {
            if let copied = await copyFileRepresentation(
                from: provider,
                typeIdentifier: utType.identifier,
                suggestedName: suggested,
                fallbackIndex: index,
                stagingDir: stagingDir
            ) {
                let filename = copied.filename
                let mime = TransferFileClassifier.inferMimeType(filename: filename, providedMimeType: copied.mimeType)
                let category = TransferFileClassifier.classify(filename: filename, mimeType: mime)
                return StagedShareAttachment(
                    id: UUID().uuidString,
                    filename: filename,
                    mimeType: mime,
                    category: category,
                    byteSize: copied.byteSize,
                    stagedFileURL: copied.fileURL,
                    sharedText: sharedText
                )
            }
        }

        // 2. Fallback for shared URL or plain text snippet -> save as `.txt` / `.url.txt` file
        if provider.hasItemConformingToTypeIdentifier(UTType.url.identifier),
           let urlString = await loadStringRepresentation(from: provider, typeIdentifier: UTType.url.identifier) {
            let cleanData = Data(urlString.utf8)
            let fileURL = stagingDir.appendingPathComponent("shared-link-\(index).txt")
            try? cleanData.write(to: fileURL, options: .atomic)
            let filename = TransferFileClassifier.sanitizeFilename(suggested.map { "\($0).txt" } ?? "分享链接-\(index).txt")
            return StagedShareAttachment(
                id: UUID().uuidString,
                filename: filename,
                mimeType: "text/plain",
                category: .document,
                byteSize: cleanData.count,
                stagedFileURL: fileURL,
                sharedText: sharedText ?? urlString
            )
        }

        if provider.hasItemConformingToTypeIdentifier(UTType.plainText.identifier),
           let textValue = await loadStringRepresentation(from: provider, typeIdentifier: UTType.plainText.identifier) {
            let cleanData = Data(textValue.utf8)
            let fileURL = stagingDir.appendingPathComponent("shared-text-\(index).txt")
            try? cleanData.write(to: fileURL, options: .atomic)
            let filename = TransferFileClassifier.sanitizeFilename(suggested.map { "\($0).txt" } ?? "分享文本-\(index).txt")
            return StagedShareAttachment(
                id: UUID().uuidString,
                filename: filename,
                mimeType: "text/plain",
                category: .document,
                byteSize: cleanData.count,
                stagedFileURL: fileURL,
                sharedText: sharedText
            )
        }

        return nil
    }

    private static func copyFileRepresentation(
        from provider: NSItemProvider,
        typeIdentifier: String,
        suggestedName: String?,
        fallbackIndex: Int,
        stagingDir: URL
    ) async -> CopiedProviderFile? {
        await withCheckedContinuation { continuation in
            provider.loadFileRepresentation(forTypeIdentifier: typeIdentifier) { tempURL, _ in
                guard let tempURL else {
                    continuation.resume(returning: nil)
                    return
                }
                let rawName: String
                if !tempURL.lastPathComponent.isEmpty {
                    rawName = tempURL.lastPathComponent
                } else if let suggestedName, !suggestedName.isEmpty {
                    rawName = suggestedName
                } else {
                    rawName = "shared-file-\(fallbackIndex)"
                }

                let cleanName = TransferFileClassifier.sanitizeFilename(rawName)
                let destURL = stagingDir.appendingPathComponent("\(UUID().uuidString)-\(cleanName)")
                do {
                    if FileManager.default.fileExists(atPath: destURL.path) {
                        try FileManager.default.removeItem(at: destURL)
                    }
                    try FileManager.default.copyItem(at: tempURL, to: destURL)
                    let attrs = try FileManager.default.attributesOfItem(atPath: destURL.path)
                    let size = (attrs[.size] as? Int) ?? 0
                    let inferredUT = UTType(filenameExtension: destURL.pathExtension) ?? UTType(typeIdentifier)
                    continuation.resume(
                        returning: CopiedProviderFile(
                            fileURL: destURL,
                            filename: cleanName,
                            mimeType: inferredUT?.preferredMIMEType,
                            byteSize: size
                        )
                    )
                } catch {
                    continuation.resume(returning: nil)
                }
            }
        }
    }

    private static func loadStringRepresentation(
        from provider: NSItemProvider,
        typeIdentifier: String
    ) async -> String? {
        await withCheckedContinuation { continuation in
            provider.loadItem(forTypeIdentifier: typeIdentifier, options: nil) { item, _ in
                if let url = item as? NSURL, let str = url.absoluteString {
                    continuation.resume(returning: str)
                } else if let str = item as? NSString {
                    continuation.resume(returning: str as String)
                } else if let data = item as? NSData, let str = String(data: data as Data, encoding: .utf8) {
                    continuation.resume(returning: str)
                } else {
                    continuation.resume(returning: nil)
                }
            }
        }
    }
}

private struct ShareExtensionSendSheetView: View {
    let biometricService: BiometricAuthService
    let loadSession: () -> ShareExtensionSessionRecord?
    let extractAttachments: () async -> [StagedShareAttachment]
    let onCompleted: () -> Void
    let onCancel: () -> Void

    @Environment(\.colorScheme) private var colorScheme
    @State private var isLoadingAttachments = true
    @State private var attachments: [StagedShareAttachment] = []
    @State private var sessionRecord: ShareExtensionSessionRecord?
    @State private var noteText: String = ""
    @State private var isSending = false
    @State private var progressState = ShareSendProgressState()
    @State private var errorMessage: String?
    @State private var didCompleteSend = false

    private var accentColor: Color {
        colorScheme == .dark
            ? Color(red: 0.298, green: 0.725, blue: 0.592)
            : Color(red: 0.149, green: 0.392, blue: 0.329)
    }

    private var totalBytes: Int {
        attachments.reduce(0) { $0 + $1.byteSize }
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if isLoadingAttachments {
                    Spacer()
                    ProgressView("正在读取待发送文件...")
                    Spacer()
                } else if sessionRecord == nil {
                    Spacer()
                    ContentUnavailableView(
                        "尚未解锁 PSS 会话",
                        systemImage: "lock.shield",
                        description: Text("请先打开 PSS 主应用完成一次登录解锁，即可从任意应用直接点击「发送」加密互传文件。")
                    )
                    Spacer()
                } else if attachments.isEmpty {
                    Spacer()
                    ContentUnavailableView(
                        "未检测到可发送的文件",
                        systemImage: "doc.questionmark",
                        description: Text("请返回原应用重新选择需要分享的文件。")
                    )
                    Spacer()
                } else {
                    List {
                        Section {
                            HStack(spacing: 10) {
                                Image(systemName: "lock.shield.fill")
                                    .font(.title3)
                                    .foregroundStyle(accentColor)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("发送至 \(sessionRecord?.vaultName ?? "PSS") · 多端互传空间")
                                        .font(.subheadline.weight(.semibold))
                                    Text("PSENC001 · AES-256-GCM 端到端零知识加密（共 \(attachments.count) 个文件，\(formatByteCount(totalBytes))）")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .padding(.vertical, 2)
                        }

                        Section("待发送文件 (\(attachments.count))") {
                            ForEach(attachments) { file in
                                HStack(spacing: 10) {
                                    Image(systemName: file.category.systemImage)
                                        .foregroundStyle(accentColor)
                                        .frame(width: 26)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(file.filename)
                                            .font(.subheadline.weight(.medium))
                                            .lineLimit(1)
                                        Text("\(file.category.displayName) · \(formatByteCount(file.byteSize)) · \(file.mimeType)")
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                            .lineLimit(1)
                                    }
                                    Spacer()
                                }
                            }
                        }

                        Section("加密附言（可选）") {
                            TextField("输入附言备注，随文件密文信封同步至其他设备...", text: $noteText, axis: .vertical)
                                .lineLimit(2...4)
                                .disabled(isSending)
                        }

                        if isSending {
                            Section("加密传输进度") {
                                VStack(alignment: .leading, spacing: 6) {
                                    HStack {
                                        Text("正在加密发送 (\(min(attachments.count, progressState.currentFileIndex + 1))/\(attachments.count))")
                                            .font(.caption.weight(.semibold))
                                        Spacer()
                                        Text("\(Int(progressState.currentProgress * 100))%")
                                            .font(.caption2.monospacedDigit())
                                    }
                                    ProgressView(value: progressState.currentProgress)
                                }
                            }
                        }

                        if let errorMessage {
                            Section {
                                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                                    .font(.caption)
                                    .foregroundStyle(.red)
                            }
                        }
                    }

                    VStack(spacing: 10) {
                        Button {
                            Task { await performEncryptedSend() }
                        } label: {
                            HStack(spacing: 8) {
                                if isSending {
                                    ProgressView()
                                        .tint(.white)
                                } else if didCompleteSend {
                                    Image(systemName: "checkmark.circle.fill")
                                } else {
                                    Image(systemName: "paperplane.fill")
                                }
                                Text(didCompleteSend ? "已发送" : "发送")
                                    .font(.headline.weight(.semibold))
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 13)
                            .background(accentColor, in: RoundedRectangle(cornerRadius: 14))
                            .foregroundStyle(.white)
                        }
                        .disabled(isSending || didCompleteSend)
                        .accessibilityIdentifier("ios-share-extension-send-button")
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                    .background(.ultraThinMaterial)
                }
            }
            .navigationTitle("发送")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { onCancel() }
                        .disabled(isSending)
                }
            }
            .task {
                self.sessionRecord = loadSession()
                self.attachments = await extractAttachments()
                self.isLoadingAttachments = false
            }
        }
    }

    @MainActor
    private func performEncryptedSend() async {
        guard let session = sessionRecord,
              let dekData = Data(base64Encoded: session.masterDekBase64),
              dekData.count == 32 else {
            errorMessage = "未找到有效的主密钥会话，请先打开 PSS 主应用解锁"
            return
        }

        errorMessage = nil
        isSending = true

        do {
            if biometricService.detectCapability() != .none {
                let verified = try await biometricService.authenticate(
                    reason: "验证身份以加密发送文件至多端互传空间"
                )
                guard verified else {
                    isSending = false
                    errorMessage = "身份验证已取消"
                    return
                }
            }

            let client = PrivateSpaceAPIClient(
                baseURLString: session.serverURL,
                sessionToken: session.sessionToken,
                masterDek: dekData,
                deviceName: session.deviceName
            )

            let trimmedNote = noteText.trimmingCharacters(in: .whitespacesAndNewlines)
            let totalAttachmentCount = max(1, attachments.count)
            let progressRef = progressState

            for (idx, attachment) in attachments.enumerated() {
                progressRef.currentFileIndex = idx
                progressRef.currentProgress = Double(idx) / Double(totalAttachmentCount)

                let plainData = try Data(contentsOf: attachment.stagedFileURL)
                let effectiveCaption: String
                if idx == 0 && !trimmedNote.isEmpty {
                    effectiveCaption = trimmedNote
                } else {
                    effectiveCaption = attachment.sharedText ?? ""
                }
                _ = try await client.sendTransferFile(
                    data: plainData,
                    filename: attachment.filename,
                    mimeType: attachment.mimeType,
                    caption: effectiveCaption,
                    tags: ["system-share"],
                    sourceVia: .systemShare,
                    chunkBytes: 512 * 1024
                ) { [weak progressRef] uploaded, total in
                    Task { @MainActor in
                        let fileRatio = Double(uploaded) / Double(max(1, total))
                        progressRef?.currentProgress = (Double(idx) + fileRatio) / Double(totalAttachmentCount)
                    }
                }
            }

            progressRef.currentProgress = 1.0
            didCompleteSend = true
            isSending = false
            try? await Task.sleep(nanoseconds: 250_000_000)
            onCompleted()
        } catch {
            isSending = false
            errorMessage = error.localizedDescription
        }
    }

    private func formatByteCount(_ bytes: Int) -> String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useBytes, .useKB, .useMB, .useGB]
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(max(0, bytes)))
    }
}
