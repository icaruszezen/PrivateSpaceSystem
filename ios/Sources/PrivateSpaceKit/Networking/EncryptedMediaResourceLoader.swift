#if canImport(AVFoundation)
import AVFoundation
import Foundation
import UniformTypeIdentifiers

/// On-the-fly Zero-Knowledge `AVAssetResourceLoaderDelegate` for `AVPlayer`.
/// Intercepts `psenc-stream://<mediaId>` byte-range requests from `AVFoundation`, fetches only the
/// overlapping `PSENC001` 64 KiB encrypted chunks via `HTTP 206`, and decrypts them in memory via `AES-256-GCM`.
public final class EncryptedMediaResourceLoader: NSObject, AVAssetResourceLoaderDelegate, @unchecked Sendable {
    public static let customScheme = "psenc-stream"

    private let media: MediaItem
    private let apiClient: PrivateSpaceAPIClient
    private let loaderQueue = DispatchQueue(label: "io.privatespace.ios.psenc-resource-loader")
    private let lock = NSLock()
    private var inFlightTasks: [ObjectIdentifier: Task<Void, Never>] = [:]

    public init(media: MediaItem, apiClient: PrivateSpaceAPIClient) {
        self.media = media
        self.apiClient = apiClient
        super.init()
    }

    public static func makeStreamingAsset(
        for media: MediaItem,
        apiClient: PrivateSpaceAPIClient
    ) throws -> (asset: AVURLAsset, loader: EncryptedMediaResourceLoader) {
        guard let url = URL(string: "\(customScheme)://vault.local/\(media.id)") else {
            throw PrivateSpaceClientError.invalidServerURL(media.id)
        }
        let loader = EncryptedMediaResourceLoader(media: media, apiClient: apiClient)
        let asset = AVURLAsset(url: url)
        asset.resourceLoader.setDelegate(loader, queue: loader.loaderQueue)
        return (asset, loader)
    }

    public func cancelAllRequests() {
        lock.lock()
        let tasks = Array(inFlightTasks.values)
        inFlightTasks.removeAll()
        lock.unlock()
        for task in tasks {
            task.cancel()
        }
    }

    public func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest
    ) -> Bool {
        guard loadingRequest.request.url?.scheme == Self.customScheme else {
            return false
        }

        let requestKey = ObjectIdentifier(loadingRequest)
        let mediaCopy = self.media
        let client = self.apiClient

        let task = Task { [weak self] in
            defer {
                self?.removeTask(for: requestKey)
            }

            do {
                let blobMeta: EncryptedBlobKeyMetaDto
                if let existingMeta = mediaCopy.blobKeyBundle?.main {
                    blobMeta = existingMeta
                } else {
                    let record = try await client.fetchEncryptedMediaRecord(id: mediaCopy.id)
                    guard let fetchedMeta = record.mediaBlobs?.main else {
                        throw PrivateSpaceClientError.e2eeDecryptionFailed("视频缺少 PSENC001 密钥元数据")
                    }
                    blobMeta = fetchedMeta
                }

                if let contentInfo = loadingRequest.contentInformationRequest {
                    let uti = UTType(mimeType: mediaCopy.mimeType)?.identifier ?? UTType.mpeg4Movie.identifier
                    contentInfo.contentType = uti
                    contentInfo.isByteRangeAccessSupported = true
                    contentInfo.contentLength = Int64(blobMeta.plainSize)
                }

                if let dataRequest = loadingRequest.dataRequest {
                    let startOffset = Int(max(0, dataRequest.currentOffset > 0 ? dataRequest.currentOffset : dataRequest.requestedOffset))
                    if startOffset >= blobMeta.plainSize {
                        loadingRequest.finishLoading()
                        return
                    }

                    let endOffset: Int
                    if dataRequest.requestsAllDataToEndOfResource {
                        // Cap single streaming window to 2 MiB so AVPlayer progressively requests chunks
                        endOffset = min(blobMeta.plainSize - 1, startOffset + 2 * 1024 * 1024 - 1)
                    } else {
                        let reqLen = max(1, dataRequest.requestedLength)
                        endOffset = min(blobMeta.plainSize - 1, startOffset + reqLen - 1)
                    }

                    let decryptedSlice = try await client.fetchDecryptedMediaByteRange(
                        mediaId: mediaCopy.id,
                        startPlainByte: startOffset,
                        endPlainByte: endOffset,
                        blobMeta: blobMeta
                    )
                    if Task.isCancelled { return }
                    dataRequest.respond(with: decryptedSlice)
                }

                loadingRequest.finishLoading()
            } catch {
                if !Task.isCancelled {
                    loadingRequest.finishLoading(with: error)
                }
            }
        }

        lock.lock()
        inFlightTasks[requestKey] = task
        lock.unlock()
        return true
    }

    public func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        didCancel loadingRequest: AVAssetResourceLoadingRequest
    ) {
        let key = ObjectIdentifier(loadingRequest)
        lock.lock()
        let task = inFlightTasks.removeValue(forKey: key)
        lock.unlock()
        task?.cancel()
    }

    private func removeTask(for key: ObjectIdentifier) {
        lock.lock()
        inFlightTasks.removeValue(forKey: key)
        lock.unlock()
    }
}
#endif
