import PhotosUI
import PrivateSpaceKit
import SwiftUI
import UniformTypeIdentifiers

struct TransfersTabView: View {
    @Bindable var store: VaultStore
    let onInspectCipher: (String) -> Void
    let onJumpToMediaTab: (_ isVideo: Bool) -> Void
    @Environment(\.colorScheme) private var colorScheme

    @State private var searchText = ""
    @State private var selectedFilter: TransferListFilter = .all
    @State private var draftText = ""
    @State private var replyingTo: TransferItem?
    @State private var showingFileImporter = false
    @State private var selectedPhotoItems: [PhotosPickerItem] = []
    @State private var shareFileURL: URL?
    @State private var showingShareSheet = false

    private var items: [TransferItem] {
        store.filteredTransfers(query: searchText, filter: selectedFilter)
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Filter pill strip
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(TransferListFilter.allCases) { mode in
                            let isActive = selectedFilter == mode
                            Button {
                                IOSPlatformActions.impactLight()
                                selectedFilter = mode
                            } label: {
                                Text(mode.rawValue)
                                    .font(.caption.weight(isActive ? .semibold : .medium))
                                    .foregroundStyle(
                                        isActive
                                            ? Color.white
                                            : .primary
                                    )
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 6)
                                    .background(
                                        isActive
                                            ? MineralPineTheme.primaryAccent(for: colorScheme)
                                            : MineralPineTheme.subtleFill(for: colorScheme),
                                        in: Capsule()
                                    )
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                }
                .background(MineralPineTheme.pageBackground(for: colorScheme))

                if !store.activeUploads.isEmpty {
                    VStack(spacing: 6) {
                        ForEach(store.activeUploads) { task in
                            HStack(spacing: 8) {
                                ProgressView(value: task.progress)
                                    .tint(MineralPineTheme.primaryAccent(for: colorScheme))
                                Text("\(task.filename) \(Int(task.progress * 100))%")
                                    .font(.caption2.monospacedDigit())
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                        }
                    }
                    .padding(.horizontal, 14)
                    .padding(.bottom, 6)
                }

                Divider()

                // Timeline
                ScrollViewReader { proxy in
                    ScrollView {
                        if items.isEmpty {
                            ContentUnavailableView(
                                searchText.isEmpty && selectedFilter == .all
                                    ? "多端零知识加密互传就绪"
                                    : "未找到匹配的互传记录",
                                systemImage: "arrow.left.arrow.right.circle",
                                description: Text(
                                    "电脑与手机可随时互发任意文件、图文与聊天消息，记录永久加密保存；发送的图片和视频自动归档至图库与视频库。"
                                )
                            )
                            .padding(.top, 56)
                        } else {
                            LazyVStack(spacing: 12) {
                                ForEach(items) { item in
                                    TransferMessageBubbleView(
                                        item: item,
                                        store: store,
                                        onReply: { replyingTo = item },
                                        onInspectCipher: { onInspectCipher(item.id) },
                                        onJumpToMediaTab: onJumpToMediaTab,
                                        onExportFile: { exportDecryptedTransfer(item) }
                                    )
                                    .id(item.id)
                                }
                            }
                            .padding(.horizontal, 14)
                            .padding(.vertical, 12)
                        }
                    }
                    .background(MineralPineTheme.pageBackground(for: colorScheme))
                    .onChange(of: items.count) { _, _ in
                        if let lastId = items.last?.id, searchText.isEmpty, selectedFilter == .all {
                            withAnimation(.easeOut(duration: 0.2)) {
                                proxy.scrollTo(lastId, anchor: .bottom)
                            }
                        }
                    }
                }

                Divider()

                // Reply bar + Composer
                VStack(spacing: 6) {
                    if let reply = replyingTo {
                        HStack(spacing: 8) {
                            Image(systemName: "arrowshape.turn.up.left.fill")
                                .font(.caption)
                                .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                            Text(
                                "回复 \(reply.senderDeviceName)：\(reply.originalFilename.isEmpty ? reply.text : reply.originalFilename)"
                            )
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            Spacer()
                            Button {
                                replyingTo = nil
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.top, 6)
                    }

                    HStack(alignment: .bottom, spacing: 8) {
                        Menu {
                            Button {
                                showingFileImporter = true
                            } label: {
                                Label("发送任意文件 (PDF / ZIP / IPA / 文档)", systemImage: "doc.badge.plus")
                            }
                        } label: {
                            Image(systemName: "paperclip.circle.fill")
                                .font(.system(size: 28))
                                .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                        }

                        PhotosPicker(
                            selection: $selectedPhotoItems,
                            maxSelectionCount: 6,
                            matching: .any(of: [.images, .videos])
                        ) {
                            Image(systemName: "photo.circle.fill")
                                .font(.system(size: 28))
                                .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                        }

                        TextField("输入跨端加密消息或文件备注...", text: $draftText, axis: .vertical)
                            .lineLimit(1...5)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(
                                MineralPineTheme.subtleFill(for: colorScheme),
                                in: RoundedRectangle(cornerRadius: 16, style: .continuous)
                            )

                        Button {
                            sendCurrentDraft()
                        } label: {
                            Image(systemName: "arrow.up.circle.fill")
                                .font(.system(size: 30))
                                .foregroundStyle(
                                    draftText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                                        ? Color.secondary.opacity(0.45)
                                        : MineralPineTheme.primaryAccent(for: colorScheme)
                                )
                        }
                        .disabled(draftText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
                .background(MineralPineTheme.cardBackground(for: colorScheme))
            }
            .navigationTitle("多端互传")
            .navigationBarTitleDisplayMode(.inline)
            .searchable(text: $searchText, prompt: "搜索消息、文件名、终端或 SHA-256")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task { await store.syncDelta() }
                    } label: {
                        Image(systemName: "arrow.triangle.2.circlepath")
                    }
                }
            }
            .fileImporter(
                isPresented: $showingFileImporter,
                allowedContentTypes: [.item],
                allowsMultipleSelection: true
            ) { result in
                handleImportedFiles(result)
            }
            .onChange(of: selectedPhotoItems) { _, newItems in
                guard !newItems.isEmpty else { return }
                let picked = newItems
                selectedPhotoItems = []
                Task {
                    await handlePickedPhotos(picked)
                }
            }
            .sheet(isPresented: $showingShareSheet) {
                if let url = shareFileURL {
                    TransferActivityShareSheet(fileURL: url)
                }
            }
        }
    }

    private func sendCurrentDraft() {
        let text = draftText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        let reply = replyingTo
        draftText = ""
        replyingTo = nil
        IOSPlatformActions.impactLight()
        Task {
            let preview = reply.map { $0.originalFilename.isEmpty ? String($0.text.prefix(80)) : $0.originalFilename }
            await store.sendTransferText(text, replyToId: reply?.id, replyPreview: preview)
        }
    }

    private func handleImportedFiles(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result else { return }
        let caption = draftText.trimmingCharacters(in: .whitespacesAndNewlines)
        let reply = replyingTo
        draftText = ""
        replyingTo = nil
        let preview = reply.map { $0.originalFilename.isEmpty ? String($0.text.prefix(80)) : $0.originalFilename }

        Task {
            for (index, url) in urls.enumerated() {
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                if let data = try? Data(contentsOf: url) {
                    let mime = UTType(filenameExtension: url.pathExtension)?.preferredMIMEType ?? ""
                    await store.sendTransferFileData(
                        data: data,
                        filename: url.lastPathComponent,
                        mimeType: mime,
                        caption: index == 0 ? caption : "",
                        replyToId: index == 0 ? reply?.id : nil,
                        replyPreview: index == 0 ? preview : nil
                    )
                }
            }
        }
    }

    private func handlePickedPhotos(_ picked: [PhotosPickerItem]) async {
        let caption = draftText.trimmingCharacters(in: .whitespacesAndNewlines)
        let reply = replyingTo
        draftText = ""
        replyingTo = nil
        let preview = reply.map { $0.originalFilename.isEmpty ? String($0.text.prefix(80)) : $0.originalFilename }

        for (idx, item) in picked.enumerated() {
            if let data = try? await item.loadTransferable(type: Data.self) {
                let utType = item.supportedContentTypes.first
                let isMovie = utType?.conforms(to: .movie) == true
                let ext = utType?.preferredFilenameExtension ?? (isMovie ? "mp4" : "jpg")
                let mime = utType?.preferredMIMEType ?? (isMovie ? "video/mp4" : "image/jpeg")
                let filename = "iPhone_\(Int(Date().timeIntervalSince1970))_\(idx + 1).\(ext)"
                await store.sendTransferFileData(
                    data: data,
                    filename: filename,
                    mimeType: mime,
                    caption: idx == 0 ? caption : "",
                    replyToId: idx == 0 ? reply?.id : nil,
                    replyPreview: idx == 0 ? preview : nil
                )
            }
        }
    }

    private func exportDecryptedTransfer(_ item: TransferItem) {
        Task {
            do {
                let plainData: Data
                if let mediaId = item.linkedMediaId {
                    plainData = try await store.apiClient.fetchFullMediaData(mediaId: mediaId, revision: 1)
                } else {
                    plainData = try await store.apiClient.fetchTransferData(transfer: item, preferThumbnail: false)
                }
                let safeName = item.originalFilename.isEmpty ? "transfer-\(item.id.prefix(8)).bin" : item.originalFilename
                let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent(safeName)
                try plainData.write(to: tempURL, options: .atomic)
                self.shareFileURL = tempURL
                self.showingShareSheet = true
            } catch {
                store.errorBanner = error.localizedDescription
            }
        }
    }
}

private struct TransferMessageBubbleView: View {
    let item: TransferItem
    let store: VaultStore
    let onReply: () -> Void
    let onInspectCipher: () -> Void
    let onJumpToMediaTab: (_ isVideo: Bool) -> Void
    let onExportFile: () -> Void
    @Environment(\.colorScheme) private var colorScheme

    private var isFromCurrentPlatform: Bool {
        item.senderPlatform == .ios
    }

    var body: some View {
        HStack {
            if isFromCurrentPlatform { Spacer(minLength: 36) }

            VStack(alignment: .leading, spacing: 8) {
                // Sender header
                HStack(spacing: 6) {
                    Image(systemName: platformSymbol(item.senderPlatform))
                        .font(.caption2)
                        .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                    Text(item.senderDeviceName)
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.secondary)
                    if item.sourceVia == .systemShare || item.tags.contains("system-share") {
                        Label("系统分享 · 发送", systemImage: "paperplane.fill")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(
                                MineralPineTheme.primaryAccent(for: colorScheme).opacity(0.12),
                                in: Capsule()
                            )
                    }
                    Spacer(minLength: 8)
                    if item.isPinned {
                        Image(systemName: "star.fill")
                            .font(.caption2)
                            .foregroundStyle(MineralPineTheme.amber)
                    }
                    Text(VaultFormatters.shortDate(item.createdAt))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }

                // Reply preview
                if let replyPreview = item.replyPreview, !replyPreview.isEmpty {
                    Text(replyPreview)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(
                            MineralPineTheme.subtleFill(for: colorScheme),
                            in: RoundedRectangle(cornerRadius: 6, style: .continuous)
                        )
                }

                // Inline Image / Video preview + Auto-Archive badge
                if item.messageKind == .image || item.messageKind == .video {
                    if let mediaId = item.linkedMediaId {
                        AuthenticatedMediaImageView(
                            mediaId: mediaId,
                            revision: 1,
                            fullResolution: false,
                            apiClient: store.apiClient,
                            contentMode: .fill
                        )
                        .frame(maxWidth: 260, minHeight: 150, maxHeight: 200)
                        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                    }

                    Button {
                        onJumpToMediaTab(item.messageKind == .video)
                    } label: {
                        HStack(spacing: 5) {
                            Image(systemName: item.messageKind == .video ? "film.stack" : "photo.stack")
                            Text(
                                item.messageKind == .video
                                    ? "已自动归档至私密视频库 · 查看"
                                    : "已自动归档至加密相册 · 查看"
                            )
                        }
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(
                            MineralPineTheme.primaryAccent(for: colorScheme).opacity(0.12),
                            in: Capsule()
                        )
                    }
                    .buttonStyle(.plain)
                }

                // Arbitrary file card
                if item.messageKind == .file || !item.originalFilename.isEmpty {
                    Button {
                        onExportFile()
                    } label: {
                        HStack(spacing: 10) {
                            Image(systemName: fileCategorySymbol(item.fileCategory))
                                .font(.title3)
                                .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                                .frame(width: 36, height: 36)
                                .background(
                                    MineralPineTheme.primaryAccent(for: colorScheme).opacity(0.12),
                                    in: RoundedRectangle(cornerRadius: 8, style: .continuous)
                                )
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.originalFilename.isEmpty ? "加密文件" : item.originalFilename)
                                    .font(.subheadline.weight(.medium))
                                    .foregroundStyle(.primary)
                                    .lineLimit(1)
                                Text(
                                    "\(VaultFormatters.formatBytes(item.plainSize)) · SHA-256 \(item.sha256.prefix(8))"
                                )
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                            }
                            Spacer(minLength: 4)
                            Image(systemName: "arrow.down.circle")
                                .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                        }
                        .padding(8)
                        .background(
                            MineralPineTheme.subtleFill(for: colorScheme),
                            in: RoundedRectangle(cornerRadius: 10, style: .continuous)
                        )
                    }
                    .buttonStyle(.plain)
                }

                // Message text / caption
                if !item.text.isEmpty {
                    Text(item.text)
                        .font(.body)
                        .foregroundStyle(.primary)
                        .textSelection(.enabled)
                }
            }
            .padding(12)
            .background(
                MineralPineTheme.cardBackground(for: colorScheme),
                in: RoundedRectangle(cornerRadius: 14, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .strokeBorder(MineralPineTheme.borderColor(for: colorScheme), lineWidth: 1)
            )
            .contextMenu {
                Button {
                    onReply()
                } label: {
                    Label("引用回复", systemImage: "arrowshape.turn.up.left")
                }

                if !item.text.isEmpty {
                    Button {
                        IOSPlatformActions.copySecret(item.text, expireSeconds: 0)
                        store.showToast("已复制互传文本")
                    } label: {
                        Label("复制文本", systemImage: "doc.on.doc")
                    }
                }

                if item.hasBlob || item.linkedMediaId != nil {
                    Button {
                        onExportFile()
                    } label: {
                        Label("解密导出 / 分享文件", systemImage: "square.and.arrow.up")
                    }
                }

                Button {
                    Task {
                        await store.updateTransfer(
                            id: item.id,
                            patch: UpdateTransferRequest(isPinned: !item.isPinned)
                        )
                    }
                } label: {
                    Label(item.isPinned ? "取消星标收藏" : "星标收藏", systemImage: item.isPinned ? "star.slash" : "star")
                }

                Button {
                    onInspectCipher()
                } label: {
                    Label("透视零知识密文信封", systemImage: "lock.doc")
                }

                Button(role: .destructive) {
                    Task { await store.deleteTransferPermanently(id: item.id) }
                } label: {
                    Label("永久删除此记录", systemImage: "trash")
                }
            }

            if !isFromCurrentPlatform { Spacer(minLength: 36) }
        }
    }

    private func platformSymbol(_ p: DevicePlatform) -> String {
        switch p {
        case .ios: return "iphone"
        case .android: return "candybarphone"
        case .web: return "laptopcomputer"
        case .api: return "terminal"
        }
    }

    private func fileCategorySymbol(_ c: TransferFileCategory?) -> String {
        switch c {
        case .document: return "doc.richtext"
        case .archive: return "doc.zipper"
        case .audio: return "waveform"
        case .code: return "chevron.left.forwardslash.chevron.right"
        case .package: return "shippingbox"
        case .image: return "photo"
        case .video: return "film"
        case .other, .none: return "doc.fill"
        }
    }
}

private struct TransferActivityShareSheet: UIViewControllerRepresentable {
    let fileURL: URL

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [fileURL], applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
