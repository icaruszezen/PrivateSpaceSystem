import PrivateSpaceKit
import SwiftUI

enum PrimaryVaultTab: String, Hashable {
    case passwords
    case photos
    case videos
    case notes
    case security
}

struct MainTabShellView: View {
    @Bindable var store: VaultStore
    @State private var selectedTab: PrimaryVaultTab = .passwords
    @State private var inspectedCipherItemId: String?

    var body: some View {
        TabView(selection: $selectedTab) {
            PasswordsTabView(
                store: store,
                onInspectCipher: { id in inspectedCipherItemId = id }
            )
            .tabItem {
                Label("密码库", systemImage: "key.fill")
            }
            .tag(PrimaryVaultTab.passwords)

            PhotosTabView(
                store: store,
                onInspectCipher: { id in inspectedCipherItemId = id }
            )
            .tabItem {
                Label("相册", systemImage: "photo.on.rectangle.angled")
            }
            .tag(PrimaryVaultTab.photos)

            VideosTabView(
                store: store,
                onInspectCipher: { id in inspectedCipherItemId = id }
            )
            .tabItem {
                Label("影院", systemImage: "play.rectangle.fill")
            }
            .tag(PrimaryVaultTab.videos)

            NotesTabView(
                store: store,
                onInspectCipher: { id in inspectedCipherItemId = id }
            )
            .tabItem {
                Label("笔记", systemImage: "doc.text.fill")
            }
            .tag(PrimaryVaultTab.notes)

            SecuritySyncTabView(
                store: store,
                onInspectCipher: { id in inspectedCipherItemId = id }
            )
            .tabItem {
                Label("安全", systemImage: "checkmark.shield.fill")
            }
            .tag(PrimaryVaultTab.security)
        }
        .sheet(
            isPresented: Binding(
                get: { inspectedCipherItemId != nil },
                set: { if !$0 { inspectedCipherItemId = nil } }
            )
        ) {
            if let itemId = inspectedCipherItemId {
                CipherInspectorSheet(itemId: itemId, apiClient: store.apiClient)
            }
        }
    }
}
