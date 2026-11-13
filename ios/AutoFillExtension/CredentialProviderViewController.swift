import AuthenticationServices
import PrivateSpaceKit
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// Native iOS System Password & 2FA TOTP AutoFill Extension (`ASCredentialProviderViewController`).
/// Reads the `AES-256-GCM` encrypted App Group credential store (`group.io.privatespace.ios`)
/// protected by Keychain & Face ID / Touch ID.
@objc(CredentialProviderViewController)
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let secretStore = AppleKeychainStore(
        service: "io.privatespace.ios.keychain",
        accessGroup: nil
    )
    private lazy var localStore = EncryptedLocalVaultStore(
        appGroupIdentifier: "group.io.privatespace.ios",
        secretStore: secretStore
    )
    private let biometricService = BiometricAuthService()

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let domains = serviceIdentifiers.map(\.identifier)
        mountSwiftUIPicker(domains: domains, targetRecordId: nil)
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        // Always require biometric/user confirmation before releasing decrypted vault credentials
        let err = NSError(
            domain: ASExtensionErrorDomain,
            code: ASExtensionError.userInteractionRequired.rawValue
        )
        extensionContext.cancelRequest(withError: err)
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        let recordId = (credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity)?.recordIdentifier
        let serviceId = credentialRequest.credentialIdentity.serviceIdentifier.identifier
        mountSwiftUIPicker(domains: [serviceId], targetRecordId: recordId)
    }

    private func mountSwiftUIPicker(domains: [String], targetRecordId: String?) {
        let rootView = AutoFillCredentialPickerView(
            domains: domains,
            targetRecordId: targetRecordId,
            biometricService: biometricService,
            loadRecords: { [localStore] in
                (try? localStore.loadAutoFillCredentials(matching: domains)) ?? []
            },
            onSelect: { [weak self] record in
                self?.completeAutoFill(with: record)
            },
            onCancel: { [weak self] in
                let err = NSError(
                    domain: ASExtensionErrorDomain,
                    code: ASExtensionError.userCanceled.rawValue
                )
                self?.extensionContext.cancelRequest(withError: err)
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

    private func completeAutoFill(with record: AutoFillCredentialRecord) {
        // If entry has RFC 6238 2FA secret, copy fresh TOTP code to local-only clipboard for 30s
        if !record.totpSecret.isEmpty,
           let totp = try? TotpGenerator.generateTotp(record.totpSecret) {
            UIPasteboard.general.setItems(
                [[UTType.plainText.identifier: totp.code]],
                options: [
                    .localOnly: true,
                    .expirationDate: Date().addingTimeInterval(30),
                ]
            )
        }

        let credential = ASPasswordCredential(user: record.username, password: record.password)
        extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
    }
}

private struct AutoFillCredentialPickerView: View {
    let domains: [String]
    let targetRecordId: String?
    let biometricService: BiometricAuthService
    let loadRecords: () -> [AutoFillCredentialRecord]
    let onSelect: (AutoFillCredentialRecord) -> Void
    let onCancel: () -> Void

    @State private var unlocked = false
    @State private var records: [AutoFillCredentialRecord] = []
    @State private var query = ""
    @State private var authFailedMessage: String?

    private var filteredRecords: [AutoFillCredentialRecord] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return records }
        return records.filter {
            $0.title.lowercased().contains(q)
                || $0.username.lowercased().contains(q)
                || $0.domain.lowercased().contains(q)
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                if !unlocked {
                    VStack(spacing: 16) {
                        Image(systemName: "faceid")
                            .font(.system(size: 42))
                            .foregroundStyle(Color(red: 0.149, green: 0.392, blue: 0.329))
                        Text("验证身份以自动填充密码")
                            .font(.headline)
                        if let authFailedMessage {
                            Text(authFailedMessage)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Button("通过面容 ID / 锁屏密码解锁") {
                            Task { await unlockAndLoad() }
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    .padding()
                } else if filteredRecords.isEmpty {
                    ContentUnavailableView(
                        "未找到匹配凭据",
                        systemImage: "key.slash",
                        description: Text("请先打开 PrivateSpace 主应用完成解锁同步")
                    )
                } else {
                    List(filteredRecords) { rec in
                        Button {
                            onSelect(rec)
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(rec.title)
                                        .font(.subheadline.weight(.semibold))
                                        .foregroundStyle(.primary)
                                    Text(rec.username.isEmpty ? rec.domain : "\(rec.username) · \(rec.domain)")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if !rec.totpSecret.isEmpty {
                                    Text("含 2FA")
                                        .font(.caption2.weight(.bold))
                                        .padding(.horizontal, 7)
                                        .padding(.vertical, 3)
                                        .background(Color.secondary.opacity(0.14), in: Capsule())
                                }
                            }
                        }
                    }
                    .searchable(text: $query, prompt: "搜索 PrivateSpace 凭据")
                }
            }
            .navigationTitle("PrivateSpace 自动填充")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { onCancel() }
                }
            }
            .task {
                await unlockAndLoad()
            }
        }
    }

    @MainActor
    private func unlockAndLoad() async {
        do {
            let ok = try await biometricService.authenticate(
                reason: "验证身份以填充 PrivateSpace 加密密码"
            )
            guard ok else {
                authFailedMessage = "身份验证已取消"
                return
            }
            let loaded = loadRecords()
            self.records = loaded
            self.unlocked = true

            if let targetRecordId,
               let exact = loaded.first(where: { $0.id == targetRecordId }) {
                onSelect(exact)
            }
        } catch {
            authFailedMessage = error.localizedDescription
        }
    }
}
