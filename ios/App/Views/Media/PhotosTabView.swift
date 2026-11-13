import PhotosUI
import PrivateSpaceKit
import SwiftUI
import UniformTypeIdentifiers

struct PhotosTabView: View {
    @Bindable var store: VaultStore
    let onInspectCipher: (String) -> Void
    @Environment(\.colorScheme) private var colorScheme

    @State private var searchQuery: String = ""
    @State private var selectedAlbumId: String?
    @State private var showTrash = false
    @State private var onlyPinned = false
    @State private var pickerItems: [PhotosPickerItem] = []
    @State private var activeLightboxMedia: MediaItem?
    @State private var showingNewAlbumAlert = false
    @State private var newAlbumName = ""

    private let gridColumns = [
        GridItem(.flexible(), spacing: 6),
        GridItem(.flexible(), spacing: 6),
        GridItem(.flexible(), spacing: 6),
    ]

    var body: some View {
        NavigationStack {
            let photos = store.filteredMedia(
                kind: .image,
                albumId: selectedAlbumId,
                showTrash: showTrash,
                onlyPinned: onlyPinned,
                query: searchQuery
            )

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    // Resumable Upload Progress Queue
                    if !store.activeUploads.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(store.activeUploads) { task in
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        Label("512KiB 分片加密上传：\(task.filename)", systemImage: "lock.icloud.fill")
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

                    // Encrypted Albums Filter Bar
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            FilterChipButton(
                                title: "全部原图",
                                icon: "photo.stack",
                                isSelected: selectedAlbumId == nil && !showTrash && !onlyPinned
                            ) {
                                selectedAlbumId = nil
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

                            ForEach(store.sortedAlbums) { album in
                                FilterChipButton(
                                    title: album.name,
                                    icon: "rectangle.stack.fill",
                                    isSelected: selectedAlbumId == album.id
                                ) {
                                    selectedAlbumId = (selectedAlbumId == album.id) ? nil : album.id
                                    showTrash = false
                                }
                            }

                            FilterChipButton(
                                title: "回收站",
                                icon: "trash",
                                isSelected: showTrash
                            ) {
                                showTrash.toggle()
                                selectedAlbumId = nil
                            }
                        }
                    }

                    if photos.isEmpty {
                        ContentUnavailableView(
                            "暂无加密相册影像",
                            systemImage: "photo.badge.plus",
                            description: Text("导入的照片将以 PSENC001 64KiB 分块 AES-256-GCM 密文存储，服务端磁盘零明文留存")
                        )
                        .padding(.vertical, 44)
                    } else {
                        LazyVGrid(columns: gridColumns, spacing: 6) {
                            ForEach(photos) { photo in
                                Button {
                                    activeLightboxMedia = photo
                                } label: {
                                    GeometryReader { geo in
                                        ZStack(alignment: .bottomLeading) {
                                            AuthenticatedMediaImageView(
                                                mediaId: photo.id,
                                                revision: photo.revision,
                                                fullResolution: false,
                                                apiClient: store.apiClient,
                                                contentMode: .fill
                                            )
                                            .frame(width: geo.size.width, height: geo.size.width)
                                            .clipped()

                                            if photo.isPinned {
                                                Image(systemName: "star.fill")
                                                    .font(.caption2)
                                                    .foregroundStyle(.yellow)
                                                    .padding(6)
                                                    .background(.black.opacity(0.45), in: Circle())
                                                    .padding(5)
                                            }
                                        }
                                    }
                                    .aspectRatio(1, contentMode: .fit)
                                    .background(MineralPineTheme.subtleFill(for: colorScheme))
                                    .clipShape(RoundedRectangle(cornerRadius: 8))
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
                .padding(14)
            }
            .background(MineralPineTheme.pageBackground(for: colorScheme))
            .navigationTitle("加密相册")
            .searchable(text: $searchQuery, prompt: "搜索照片标题、文件名或标签")
            .refreshable {
                await store.syncDelta()
            }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        newAlbumName = ""
                        showingNewAlbumAlert = true
                    } label: {
                        Label("新建相册", systemImage: "folder.badge.plus")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    PhotosPicker(
                        selection: $pickerItems,
                        maxSelectionCount: 12,
                        matching: .images
                    ) {
                        Image(systemName: "plus.circle.fill")
                            .font(.title3)
                    }
                }
            }
            .onChange(of: pickerItems) { _, newItems in
                guard !newItems.isEmpty else { return }
                let itemsCopy = newItems
                pickerItems = []
                Task {
                    for (idx, picked) in itemsCopy.enumerated() {
                        if let rawData = try? await picked.loadTransferable(type: Data.self) {
                            let utType = picked.supportedContentTypes.first
                            let ext = utType?.preferredFilenameExtension ?? "jpg"
                            let mime = utType?.preferredMIMEType ?? "image/jpeg"
                            let fname = "IMG_\(Int(Date().timeIntervalSince1970))_\(idx + 1).\(ext)"
                            await store.uploadMediaData(
                                data: rawData,
                                filename: fname,
                                mimeType: mime,
                                kind: .image,
                                albumId: selectedAlbumId
                            )
                        }
                    }
                }
            }
            .alert("新建加密相册", isPresented: $showingNewAlbumAlert) {
                TextField("相册名称", text: $newAlbumName)
                Button("取消", role: .cancel) {}
                Button("创建") {
                    let trimmed = newAlbumName.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !trimmed.isEmpty else { return }
                    Task { await store.createAlbum(name: trimmed, kind: "image") }
                }
            }
            .fullScreenCover(item: $activeLightboxMedia) { media in
                let liveMedia = store.snapshot.media[media.id] ?? media
                PhotoDarkroomLightboxView(
                    media: liveMedia,
                    store: store,
                    onInspectCipher: {
                        let id = liveMedia.id
                        activeLightboxMedia = nil
                        onInspectCipher(id)
                    }
                )
            }
        }
    }
}

// MARK: - Darkroom Fullscreen Lightbox (Pinch Zoom, 90° Rotate, Mirror Flip, PSENC001 Info)

struct PhotoDarkroomLightboxView: View {
    let media: MediaItem
    @Bindable var store: VaultStore
    let onInspectCipher: () -> Void
    @Environment(\.dismiss) private var dismiss

    @State private var zoomScale: CGFloat = 1.0
    @State private var gestureScale: CGFloat = 1.0
    @State private var rotationDegrees: Double = 0
    @State private var mirroredHorizontally = false
    @State private var editingTitleSheet = false
    @State private var editedTitle = ""

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            AuthenticatedMediaImageView(
                mediaId: media.id,
                revision: media.revision,
                fullResolution: true,
                apiClient: store.apiClient,
                contentMode: .fit
            )
            .scaleEffect(x: mirroredHorizontally ? -1 : 1, y: 1)
            .rotationEffect(.degrees(rotationDegrees))
            .scaleEffect(min(5.0, max(1.0, zoomScale * gestureScale)))
            .gesture(
                MagnifyGesture()
                    .onChanged { value in
                        gestureScale = value.magnification
                    }
                    .onEnded { value in
                        zoomScale = min(5.0, max(1.0, zoomScale * value.magnification))
                        gestureScale = 1.0
                    }
            )
            .onTapGesture(count: 2) {
                withAnimation(.spring(response: 0.25, dampingFraction: 0.8)) {
                    zoomScale = zoomScale > 1.05 ? 1.0 : 2.5
                }
            }

            VStack {
                // Top Bar
                HStack {
                    Button {
                        dismiss()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .font(.title2)
                            .foregroundStyle(.white.opacity(0.88))
                    }

                    VStack(alignment: .leading, spacing: 2) {
                        Text(media.title)
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(.white)
                            .lineLimit(1)
                        Text("\(media.width)×\(media.height) · \(VaultFormatters.formatBytes(media.byteSize)) · \(media.chunkCount) 密文块")
                            .font(.caption2)
                            .foregroundStyle(.white.opacity(0.7))
                    }
                    Spacer()

                    Button {
                        editedTitle = media.title
                        editingTitleSheet = true
                    } label: {
                        Image(systemName: "pencil.circle")
                            .font(.title3)
                            .foregroundStyle(.white)
                    }
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 12)
                .background(.black.opacity(0.45))

                Spacer()

                // Darkroom Transform & Crypto Controls
                HStack(spacing: 22) {
                    Button {
                        withAnimation(.easeInOut(duration: 0.2)) {
                            rotationDegrees += 90
                        }
                    } label: {
                        VStack(spacing: 4) {
                            Image(systemName: "rotate.right")
                            Text("旋转")
                                .font(.caption2)
                        }
                    }

                    Button {
                        withAnimation(.easeInOut(duration: 0.2)) {
                            mirroredHorizontally.toggle()
                        }
                    } label: {
                        VStack(spacing: 4) {
                            Image(systemName: "arrow.left.and.right.righttriangle.left.righttriangle.right")
                            Text("镜像")
                                .font(.caption2)
                        }
                    }

                    Button {
                        Task {
                            await store.updateMedia(
                                id: media.id,
                                patch: UpdateMediaRequest(isPinned: !media.isPinned)
                            )
                        }
                    } label: {
                        VStack(spacing: 4) {
                            Image(systemName: media.isPinned ? "star.fill" : "star")
                            Text(media.isPinned ? "已星标" : "星标")
                                .font(.caption2)
                        }
                    }

                    Button {
                        onInspectCipher()
                    } label: {
                        VStack(spacing: 4) {
                            Image(systemName: "lock.doc.fill")
                            Text("PSENC001")
                                .font(.caption2)
                        }
                    }

                    Button(role: .destructive) {
                        Task {
                            if media.isTrashed {
                                await store.deleteMediaPermanently(id: media.id)
                            } else {
                                await store.updateMedia(
                                    id: media.id,
                                    patch: UpdateMediaRequest(isTrashed: true)
                                )
                            }
                            dismiss()
                        }
                    } label: {
                        VStack(spacing: 4) {
                            Image(systemName: "trash")
                            Text(media.isTrashed ? "彻底擦除" : "删除")
                                .font(.caption2)
                        }
                    }
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 24)
                .padding(.vertical, 14)
                .background(.ultraThinMaterial, in: Capsule())
                .padding(.bottom, 18)
            }
        }
        .alert("编辑照片标题", isPresented: $editingTitleSheet) {
            TextField("标题", text: $editedTitle)
            Button("取消", role: .cancel) {}
            Button("保存") {
                Task {
                    await store.updateMedia(
                        id: media.id,
                        patch: UpdateMediaRequest(title: editedTitle)
                    )
                }
            }
        }
    }
}
