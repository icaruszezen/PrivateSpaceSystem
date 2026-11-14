# PrivateSpace 架构与加密同步规范

## 1. 信封加密与分层密钥体系（Envelope Encryption）

系统面向 **文本笔记（`note`）、密码凭据（`password`）、加密图片（`image`）、私密视频（`video`）** 四类核心资产，采用多层密钥隔离与全量静态认证加密（AEAD at Rest）设计：

1. **口令密钥派生（KDF）**
   - 唯一管理员密码经 NFKC 归一化后，输入 `scrypt (N=32768, r=8, p=1)` 与 256 位随机盐 `kdf_salt`，派生 64 字节材料：
     - 前 32 字节作为 **密钥加密密钥（KEK）**；
     - 后 32 字节经 `SHA-256` 摘要作为常量时间口令校验值 `auth_verifier`（通过 `crypto.timingSafeEqual` 比对）。
2. **空间主密钥封装（256-bit DEK）**
   - 初始化时由 CSPRNG 生成 256 位随机空间主密钥 `DEK`。
   - 使用 `KEK` 通过 `AES-256-GCM`（绑定 `AAD = "privatespace:dek:v1"`）加密包裹 `DEK`，将密文信封存入 `admin_config`。
   - **零重写主密码轮换**：当管理员修改主密码时，仅需用新密码派生的 `KEK` 重新包裹 32 字节 `DEK`，底层海量笔记、密码与 GB 级 `.psenc` 视频密文均无需重加密。
3. **逐记录子密钥与防篡改认证加密（SQLite 元数据与敏感载荷）**
   - 每次新建或编辑文本、密码、媒体元数据或相册时，生成全新 128 位随机 `item_salt` 与 96 位随机 `nonce`。
   - 通过 `HKDF-SHA256(DEK, item_salt, "privatespace:item:v1:<domain>:<id>")` 派生仅属于该条目当前版本的 256 位加密子密钥。
   - 使用 `AES-256-GCM` 加密全部敏感字段（包括密码库的 `password` / `totpSecret` / `customFields` / `history` 以及媒体的 `filename` / `title` / `description` / `tags` / `sha256`），并将 `{ v, id, type, rev }` 作为 `AAD` 注入认证标签计算，防止跨行密文替换或版本回退攻击。
4. **`PSENC001` 分块认证加密媒体存储（`.psenc` Blob Store）**
   - 每个原图、缩略图或视频文件分配独立的随机 256 位 **文件加密密钥（FEK）**；`FEK` 经 `HKDF-SHA256(DEK, wrap_salt, "privatespace:blob-fek:v1:<blobId>")` 封装后存入 `media_blobs` 表。
   - 原始字节流按 **`64 KiB`（65,536 字节）** 切分为等长分块，写入带 `32B` `PSENC001` 魔数文件头的 `.psenc` 容器：
     - 每个分块生成独立随机 `12B` Nonce，并以 `AAD = "privatespace:blob:v1:<blobId>:chunk:<index>:len:<plainLen>"` 执行 `AES-256-GCM` 认证加密，阻止任何分块截断、重排或比特篡改。
   - **$O(1)$ 随机访问 HTTP `206` 流式解密（含 `HEAD` 预检支持）**：收到浏览器 `<video>`、iOS `AVPlayer`（`AVURLAsset`）或 Android `ExoPlayer` 的 `HEAD` 探测与 `Range: bytes=start-end` 请求时，服务端零拷贝返回精确 `Content-Range` 头或仅解密覆盖该字节区间的 `64 KiB` 密文块实时推流，支持 GB 级高清视频零等待拖动进度条。
   - **安全擦除（Shredding）**：条目彻底销毁时，先对磁盘 `.psenc` 文件全量覆写零字节并 `fsync`，再解除目录链接。
5. **会话内存零残留保护**
   - 进程启动时在易失内存中生成 256 位临时密钥 `runtimeSecret`。
   - 设备会话中的 `DEK` 由 `HKDF(runtimeSecret || clientSessionSecret)` 加密存储；普通请求在 `finally` 块立即执行 `dek.fill(0)`，流式媒体响应在同步解封 `FEK` 后立即擦除 `DEK`，并在流结束时擦除 `FEK`。

---

## 2. 面向 Web / iOS / Android 的多端同步与断点续传协议

统一数据表 `vault_items` 以 `item_type IN ('note', 'password', 'image', 'video')` 管理四类资产，配合 `media_albums` 与 `sync_tombstones` 实现全端一致视图：

- **双模认证与设备指纹识别**：
  - 网页端默认使用 `HttpOnly; SameSite=Lax` Cookie（`pss_session`）；
  - iOS / Android 客户端通过 `POST /api/v1/auth/login`（或首次启动调用 `POST /api/v1/auth/setup`）获取 `token`，在 API 请求头携带 `Authorization: Bearer pss_<sessionId>.<secret>`，服务端同时支持识别 `PrivateSpace-IOS` 与 `CFNetwork/... Darwin/...` 原生客户端标识。
- **单调游标增量同步（`sync_seq`）与 SSE 实时推送**：
  - 任何端创建、编辑、归档、移入回收站或彻底销毁条目时，全局序列号 `sync_seq` 原子递增，并通过 `/api/v1/sync/stream`（带 `X-Accel-Buffering: no` 防反代缓冲）广播最新游标。
  - 客户端持久化本地加密快照中的 `lastSyncSeq`，调用 `GET /api/v1/sync?since_seq=<lastSyncSeq>` 即可一次拉取分类增量（`notes`, `passwords`, `media`, `albums`）与永久销毁墓碑 `deleted`。
- **离线变更队列（Outbox）与断点续传（Resumable Uploads）**：
  - 移动端在无网状态下可将新建/修改操作写入本机 `AES-256-GCM` 加密队列，重连后先重放 Outbox 再拉取增量游标。
  - 大体积原图与 ProRes / 4K 视频通过 `POST /api/v1/media/uploads/init` → `PUT /api/v1/media/uploads/:id/chunks/:index` → `POST /api/v1/media/uploads/:id/complete` 分片上传，并校验整文件 `SHA-256`。

---

## 3. Apple iOS 客户端安全架构（[`ios/`](../ios/README.md) & `/ios`）

1. **本机二次加密缓存（`PSCACHE1` Envelope）**
   - 原生 Swift `EncryptedLocalVaultStore` 在设备首次解锁时通过 `SecRandomCopyBytes` 生成 256 位随机设备密钥存入 iOS Keychain（`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`，禁止迁移与明文备份）。
   - 本地快照经 `HKDF-SHA256` 派生上下文子密钥（`vault-snapshot` / `autofill-records`），封装为 `[8B "PSCACHE1" 魔数][16B Salt][12B Nonce][Ciphertext][16B Tag]` 并附加 `NSFileProtectionComplete` 文件级硬件保护；退出登录时执行全零覆写销毁。
2. **零磁盘 HTTP 缓存与流式播放**
   - `PrivateSpaceAPIClient` 强制使用 `URLSessionConfiguration.ephemeral`（禁用 `URLCache`、`HTTPCookieStorage` 与凭据磁盘持久化）。
   - 视频影院通过 `AVURLAsset(url:options: ["AVURLAssetHTTPHeaderFieldsKey": ["Authorization": "Bearer ..."]])` 直连服务端 HTTP `206` 分块解密流，避免在 iPhone 本地磁盘落地临时明文视频文件。
3. **系统级密码与 2FA 自动填充扩展（`PrivateSpaceAutoFill`）**
   - 扩展继承 `ASCredentialProviderViewController`，通过共享加密 App Group 容器（`group.io.privatespace.shared`）读取 `AutoFillCredentialRecord` 列表，按归一化域名匹配目标站点或通过 `ASCredentialIdentityStore` 快速填充账号、口令，同时将实时计算的 6 位 RFC 6238 动态验证码写入系统剪贴板（30 秒后自动过期清除）。
   - 服务端内置 `GET /.well-known/apple-app-site-association`，声明 `applinks` 与 `webcredentials` 以支持系统级关联域名信任。
