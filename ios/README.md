# PrivateSpace Native iOS (`Swift 6` · `SwiftUI` · `iOS 17+`)

`ios/` 是面向 **iPhone 与 iPad** 打造的原生 Apple 生态客户端，基于 **SwiftUI + Observation + CryptoKit + Keychain Services + LocalAuthentication + AVKit + AuthenticationServices** 构建，与 PrivateSpace 自部署加密后端实现 **端到端零明文落盘（Zero-Plaintext at Rest）** 与实时增量同步。

## 架构与目录结构

- **`Package.swift` & `Sources/PrivateSpaceKit/`**：跨 iOS / iPadOS / macOS 共享的核心加密与同步引擎包：
  - `Models/VaultModels.swift`：与服务端 `src/shared/types.ts` 一一对应的强类型 `Codable & Sendable` 协议模型。
  - `Crypto/TotpGenerator.swift`：基于 Apple `CryptoKit` (`HMAC<Insecure.SHA1>` / `HMAC<SHA256>`) 的零依赖 RFC 6238 动态口令与 `otpauth://` 解析器。
  - `Crypto/PasswordGenerator.swift`：基于 `SecRandomCopyBytes` 无偏拒绝采样的 CSPRNG 随机密码/助记词生成器、口令熵评估、密码库安全健康审计与主流浏览器/1Password/Bitwarden CSV 解析器。
  - `Storage/KeychainStore.swift` & `EncryptedLocalVaultStore.swift`：硬件级 iOS Keychain 保管会话令牌与本地 256 位主密钥，采用 `PSCACHE1` (`HKDF-SHA256` + `AES-256-GCM` + `AAD`) 加密持久化离线快照与 App Group 自动填充凭据库，注销时执行全零覆写擦除（File Shredding）。
  - `Security/BiometricAuthService.swift`：封装 `LocalAuthentication` 面容 ID (`Face ID`) / 触控 ID (`Touch ID`) / 视网膜 ID (`Optic ID`) 解锁与后台超时自动锁定策略。
  - `Networking/PrivateSpaceAPIClient.swift`：基于 `URLSessionConfiguration.ephemeral`（杜绝明文响应写入系统 `Cache.db`）的完整 REST v1 客户端，支持 **`512 KiB` 分片断点续传 + `SHA-256` 校验**、`AVURLAsset` HTTP `206 Partial Content` 认证流媒体描述符与 W3C **SSE 实时游标监听流**。
  - `Sync/VaultStore.swift`：`@MainActor @Observable` 全局状态与离线变更队列（Outbox）协调器。
- **`App/` (`PrivateSpaceIOS`)**：原生 SwiftUI 5 栏移动工作台：
  1. **密码库**：安全健康度审计看板、分类筛选、每秒刷新圆形倒计时环 TOTP、**本地专属 30 秒自动销毁剪贴板**（阻止通用剪贴板跨设备泄露）、自定义隐藏字段、历史密码回溯与 CSV 导入。
  2. **加密相册**：加密相册集管理、`PhotosPicker` 多图分片加密上传、**暗房级全屏灯箱**（双指捏合缩放、双击放大、90° 旋转、水平镜像、`PSENC001` 密文块透视）。
  3. **私密影院**：大体积视频 `512 KiB` 断点续传、原生 `AVKit` `VideoPlayer` 对接服务端 `PSENC001` HTTP `206` 随机分块实时解密流（秒开拖动、`±10s` 跳转、`0.75×–2.0×` 倍速）。
  4. **加密笔记**：Markdown 编辑 / 交互式待办复选框预览、快捷排版栏、多标签筛选与离线队列自动同步。
  5. **安全与同步**：SSE 实时状态与 `sync_seq` 游标、Face ID 与后台自动锁定设置、App 切换器毛玻璃防窥护盾、四维密文存储统计、多端会话远程吊销、零重写主密码轮换与底层 SQLite / `PSENC001` 十六进制密文透视镜。
- **`AutoFillExtension/` (`PrivateSpaceAutoFill`)**：系统级 `ASCredentialProviderViewController` 密码自动填充扩展，支持在 Safari 与第三方 App 中按关联域名匹配填充账号密码，并在填充时自动复制 30 秒有效期的 2FA 动态口令。

---

## 构建、测试与真机安装指南（macOS + Xcode 16+）

### 1. 运行核心密码学与同步套件测试

```bash
cd ios
swift test
```

### 2. 生成 Xcode 工程并在 iOS 模拟器或真机运行

本目录提供标准 [XcodeGen](https://github.com/yonaskolb/XcodeGen) 工程规范 [`project.yml`](./project.yml)：

```bash
brew install xcodegen
cd ios
xcodegen generate
open PrivateSpaceIOS.xcodeproj
```

命令行无签名构建 iOS Simulator 验证：

```bash
xcodebuild \
  -project PrivateSpaceIOS.xcodeproj \
  -scheme PrivateSpaceIOS \
  -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO \
  build
```

### 3. 启用系统级密码自动填充（真机）

1. 在 Xcode 的 `Signing & Capabilities` 中为 `PrivateSpaceIOS` 与 `PrivateSpaceAutoFill` 选择您的 Apple Developer Team，并确认 App Group（`group.io.privatespace.ios`）一致；
2. 若需关联自部署域名自动匹配，可在服务端 `.env` 配置 `APPLE_APP_ID=<TeamID>.io.privatespace.ios`（服务端已自动暴露 `/.well-known/apple-app-site-association`）；
3. 安装至 iPhone 后，前往 **系统设置 → 通用 → 自动填充与密码**，开启 **PrivateSpace**。
