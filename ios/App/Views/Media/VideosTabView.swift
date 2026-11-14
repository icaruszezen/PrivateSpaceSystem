import AVFoundation
import AVKit
import CoreMedia
import PhotosUI
import PrivateSpaceKit
import SwiftUI
import UniformTypeIdentifiers

struct VideosTabView: View {
    @Bindable var store: VaultStore
    let onInspectCipher: (String) -> Void
    @Environment(\.colorScheme) private var colorScheme

    @State private var searchQuery: String = ""
    @State private var showTrash = false
    @State private var onlyPinned = false
    @State private var videoPickerItems: [PhotosPickerItem] = []
    @State private var activeVideo: MediaItem?

    var body: some View {
        NavigationStack {
            let videos = store.filteredMedia(
                kind: .video,
                albumId: nil,
                showTrash: showTrash,
                onlyPinned: onlyPinned,
                query: searchQuery
            )

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    // Active Resumable Chunk Uploads
                    if !store.activeUploads.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(store.activeUploads) { task in
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        Label("512KiB 断点续传：\(task.filename)", systemImage: "arrow.up.doc.fill")
                                            .font(.caption.weight(.semibold))
                                            .lineLimit(1)
                                        Spacer()
                                        Text("\(Int(task.progress * 100))%")
                                            .font(.caption2.monospacedDigit())
                                    }
                                    ProgressView(value: task.progress)
                                }
                            }
                        }
                        .padding(12)
                        .background(MineralPineTheme.cardBackground(for: colorScheme), in: RoundedRectangle(cornerRadius: 14))
                    }

                    // Filter Chips
                    HStack(spacing: 8) {
                        FilterChipButton(
                            title: "全部视频",
                            icon: "film.stack",
                            isSelected: !showTrash && !onlyPinned
                        ) {
                            showTrash = false
                            onlyPinned = false
                        }
                        FilterChipButton(
                            title: "星标收藏",
                            icon: "star.fill",
                            isSelected: onlyPinned
                        ) {
                            onlyPinned.toggle()
                            showTrash = false
                        }
                        FilterChipButton(
                            title: "回收站",
                            icon: "trash",
                            isSelected: showTrash
                        ) {
                            showTrash.toggle()
                        }
                        Spacer()
                    }

                    if videos.isEmpty {
                        ContentUnavailableView(
                            "暂无私密流式视频",
                            systemImage: "play.rectangle.on.rectangle",
                            description: Text("支持 4K/1080P 视频 512KiB 分片断点续传，服务端按 PSENC001 64KiB 加密并通过 HTTP 206 秒开流式解密播放")
                        )
                        .padding(.vertical, 44)
                    } else {
                        VStack(spacing: 12) {
                            ForEach(videos) { vid in
                                Button {
                                    activeVideo = vid
                                } label: {
                                    VideoCinemaCard(video: vid, apiClient: store.apiClient)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
                .padding(16)
            }
            .background(MineralPineTheme.pageBackground(for: colorScheme))
            .navigationTitle("私密影院")
            .searchable(text: $searchQuery, prompt: "搜索视频标题、编码或标签")
            .refreshable {
                await store.syncDelta()
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    PhotosPicker(
                        selection: $videoPickerItems,
                        maxSelectionCount: 3,
                        matching: .videos
                    ) {
                        Image(systemName: "plus.circle.fill")
                            .font(.title3)
                    }
                }
            }
            .onChange(of: videoPickerItems) { _, pickedList in
                guard !pickedList.isEmpty else { return }
                let copy = pickedList
                videoPickerItems = []
                Task {
                    for (idx, item) in copy.enumerated() {
                        if let rawData = try? await item.loadTransferable(type: Data.self) {
                            let utType = item.supportedContentTypes.first
                            let ext = utType?.preferredFilenameExtension ?? "mp4"
                            let mime = utType?.preferredMIMEType ?? "video/mp4"
                            let fname = "VID_\(Int(Date().timeIntervalSince1970))_\(idx + 1).\(ext)"
                            await store.uploadMediaData(
                                data: rawData,
                                filename: fname,
                                mimeType: mime,
                                kind: .video
                            )
                        }
                    }
                }
            }
            .sheet(item: $activeVideo) { vid in
                let liveVid = store.snapshot.media[vid.id] ?? vid
                VideoCinemaPlayerSheet(
                    video: liveVid,
                    store: store,
                    onInspectCipher: {
                        let id = liveVid.id
                        activeVideo = nil
                        onInspectCipher(id)
                    }
                )
            }
        }
    }
}

private struct VideoCinemaCard: View {
    let video: MediaItem
    let apiClient: PrivateSpaceAPIClient
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ZStack(alignment: .bottomTrailing) {
                ZStack {
                    Rectangle()
                        .fill(Color.black.opacity(0.84))
                        .frame(height: 184)

                    if video.hasThumbnail {
                        AuthenticatedMediaImageView(
                            mediaId: video.id,
                            revision: video.revision,
                            fullResolution: false,
                            apiClient: apiClient,
                            contentMode: .fill
                        )
                        .frame(height: 184)
                        .clipped()
                    }

                    Image(systemName: "play.circle.fill")
                        .font(.system(size: 48))
                        .foregroundStyle(.white.opacity(0.92))
                        .shadow(radius: 8)
                }
                .clipShape(RoundedRectangle(cornerRadius: 12))

                Text(VaultFormatters.formatDuration(video.durationMs))
                    .font(.caption2.monospacedDigit().weight(.bold))
                    .foregroundStyle(.white)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(.black.opacity(0.68), in: RoundedRectangle(cornerRadius: 6))
                    .padding(8)
            }

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(video.title)
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                    Spacer()
                    Text("HTTP 206 流式")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(MineralPineTheme.primaryAccent(for: colorScheme))
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(
                            MineralPineTheme.primaryAccent(for: colorScheme).opacity(0.12),
                            in: Capsule()
                        )
                }

                Text(
                    "\(video.width > 0 ? "\(video.width)×\(video.height) · " : "")\(VaultFormatters.formatBytes(video.byteSize)) · PSENC001 (\(video.chunkCount) 块)"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .background(MineralPineTheme.cardBackground(for: colorScheme), in: RoundedRectangle(cornerRadius: 16))
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .strokeBorder(MineralPineTheme.borderColor(for: colorScheme), lineWidth: 1)
        )
    }
}

// MARK: - Native AVKit HTTP 206 Partial Content Cinema Player Sheet

struct VideoCinemaPlayerSheet: View {
    let video: MediaItem
    @Bindable var store: VaultStore
    let onInspectCipher: () -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var player: AVPlayer?
    @State private var playbackRate: Float = 1.0
    @State private var streamError: String?

    private let supportedRates: [Float] = [0.75, 1.0, 1.25, 1.5, 2.0]

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ZStack {
                        Color.black
                            .frame(height: 230)
                        if let player {
                            VideoPlayer(player: player)
                                .frame(height: 230)
                        } else if let streamError {
                            Text(streamError)
                                .font(.caption)
                                .foregroundStyle(.white)
                                .padding()
                        } else {
                            ProgressView()
                                .tint(.white)
                        }
                    }
                    .listRowInsets(EdgeInsets())

                    HStack(spacing: 16) {
                        Button {
                            seekBy(-10)
                        } label: {
                            Label("后退 10s", systemImage: "gobackward.10")
                                .font(.caption.weight(.semibold))
                        }
                        .buttonStyle(.bordered)

                        Button {
                            seekBy(10)
                        } label: {
                            Label("快进 10s", systemImage: "goforward.10")
                                .font(.caption.weight(.semibold))
                        }
                        .buttonStyle(.bordered)

                        Spacer()

                        Menu {
                            ForEach(supportedRates, id: \.self) { rate in
                                Button(String(format: "%.2gx 倍速", rate)) {
                                    playbackRate = rate
                                    player?.rate = rate
                                }
                            }
                        } label: {
                            Text(String(format: "%.2gx", playbackRate))
                                .font(.caption.monospacedDigit().weight(.bold))
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(Color.secondary.opacity(0.15), in: Capsule())
                        }
                    }
                }

                Section("加密流式媒体参数") {
                    LabeledContent("原始文件名", value: video.originalFilename)
                    if video.width > 0 {
                        LabeledContent("分辨率", value: "\(video.width) × \(video.height)")
                    }
                    if let codec = video.videoCodec {
                        LabeledContent("视频编码", value: codec.uppercased())
                    }
                    LabeledContent("明文体积", value: VaultFormatters.formatBytes(video.byteSize))
                    LabeledContent("磁盘密文 (.psenc)", value: "\(VaultFormatters.formatBytes(video.encryptedSize)) (\(video.chunkCount) 块)")
                    LabeledContent("SHA-256 摘要", value: String(video.sha256.prefix(16)) + "…")
                }

                Section("安全审计与管理") {
                    Button {
                        onInspectCipher()
                    } label: {
                        Label("透视 PSENC001 分块密文与 FEK 封装参数", systemImage: "lock.doc.fill")
                    }

                    Button {
                        Task {
                            await store.updateMedia(
                                id: video.id,
                                patch: UpdateMediaRequest(isPinned: !video.isPinned)
                            )
                        }
                    } label: {
                        Label(video.isPinned ? "取消星标收藏" : "设为星标收藏", systemImage: "star")
                    }

                    Button(role: .destructive) {
                        Task {
                            player?.pause()
                            if video.isTrashed {
                                await store.deleteMediaPermanently(id: video.id)
                            } else {
                                await store.updateMedia(
                                    id: video.id,
                                    patch: UpdateMediaRequest(isTrashed: true)
                                )
                            }
                            dismiss()
                        }
                    } label: {
                        Label(video.isTrashed ? "彻底擦除磁盘 .psenc 密文" : "移入回收站", systemImage: "trash")
                    }
                }
            }
            .navigationTitle(video.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("完成") {
                        player?.pause()
                        dismiss()
                    }
                }
            }
            .task {
                do {
                    let (url, headers) = try await store.apiClient.makeAuthenticatedStreamDescriptor(
                        mediaId: video.id,
                        revision: video.revision
                    )
                    let asset = AVURLAsset(
                        url: url,
                        options: ["AVURLAssetHTTPHeaderFieldsKey": headers]
                    )
                    let item = AVPlayerItem(asset: asset)
                    let avPlayer = AVPlayer(playerItem: item)
                    self.player = avPlayer
                    avPlayer.play()
                } catch {
                    self.streamError = error.localizedDescription
                }
            }
            .onDisappear {
                player?.pause()
                player = nil
            }
        }
    }

    private func seekBy(_ deltaSeconds: Double) {
        guard let player else { return }
        let current = player.currentTime().seconds
        let nextTime = max(0, (current.isFinite ? current : 0) + deltaSeconds)
        player.seek(to: CMTime(seconds: nextTime, preferredTimescale: 600))
    }
}
