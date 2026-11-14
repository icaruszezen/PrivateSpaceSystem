# PrivateSpace 端到端零知识加密（Zero-Knowledge E2EE v2）与多端同步规范

## 1. 威胁模型：为什么服务器密码 / Root 权限泄露不会导致数据泄露？

在 **`ZERO_KNOWLEDGE_E2EE_V2`** 架构下，自部署服务器被严格视作 **不可信盲存储与密文同步中继（Untrusted Blind Ciphertext Relay）**：

- **即使攻击者获取了宿主机 SSH / Root 密码**：
  1. **静态落盘拖库零泄密**：拷贝整个 `/data/vault.db` 与 `/data/blobs/**/*.psenc` 仅能获得 `AES-256-GCM` 密文与被 `KEK` 加密包裹的 `wrappedDek`；`sessions` 表仅保存令牌哈希，不含任何密钥列。
  2. **内存转储与请求嗅探零泄密**：服务端进程内存中永远不存在 `KEK`、`DEK`、`FEK` 或明文主密码；所有加解密均在用户终端（浏览器、Android App、iOS App）本地完成，服务端甚至主动拦截任何携带明文字段的请求（`400 E2EE_REQUIRED`）。
  3. **不可逆双路密钥隔离**：服务端持有的 `auth_verifier = scrypt(authKey, verifier_salt)` 与加密分支 `KEK` 经密码学单向隔离，即便 `admin_config` 全表泄露也无法反推 `KEK` 或解封 `DEK`，攻击者面对的是 `310,000` 次迭代 `PBKDF2-HMAC-SHA256` + `AES-256-GCM` 的离线密码学强度边界。

---

## 2. 分层零知识密钥体系与算法规范（Web / Android / iOS 跨语言互通）

### 2.1 客户端双路主密钥派生（PBKDF2 + HKDF Split-Key Auth）
1. 用户输入的主密码经 Unicode **`NFKC`** 归一化编码为 UTF-8 字节流。
2. 客户端使用 256 位随机盐 `kdf_salt` 执行 `PBKDF2-HMAC-SHA256`（默认 `iterations = 310,000`，输出 64 字节 `masterSeed`）：
   - `KEK = masterSeed[0..32]`（**仅保留在客户端瞬时内存，用完立即覆写清零，永不发送给服务器**）；
   - `authSeed = masterSeed[32..64]`。
3. 客户端继续派生认证密钥：`authKey = HKDF-SHA256(ikm = authSeed, salt = kdf_salt, info = "privatespace:e2ee:auth-key:v2", len = 32)`。
4. 登录时客户端先通过 `GET /api/v1/auth/params` 获取 `kdf_salt` 与 `kdf_params`（**未认证状态下服务端绝不返回 `wrappedDek`**），计算并仅提交 `authKey`；服务端通过 `scrypt(N=16384, r=8, p=1)` 与常量时间 `timingSafeEqual` 验证通过后，方才签发盲会话令牌并返回 `wrappedDek`，由客户端在本地使用 `KEK` 解封 `DEK`。

### 2.2 空间主密钥封装（256-bit Master DEK）与无损轮换
- 首次初始化时，客户端 CSPRNG 生成 32 字节随机主密钥 `DEK`，计算密钥指纹 `HMAC-SHA256(DEK, "privatespace:key-fingerprint:v1")[0..6]`（`XXXX-XXXX-XXXX`）。
- 客户端使用 `AES-256-GCM(key = KEK, iv = 12B, aad = "privatespace:e2ee:dek:v2")` 将 `DEK` 封装为 `wrappedDek = { iv, tag, ciphertext }` 上传存储。
- **零重写主密码轮换**：修改主密码时，客户端校验当前密码后用新密码派生新 `KEK'` 与 `authKey'`，在本地重封装同一把 `DEK` 提交至 `POST /api/v1/auth/change-password`，全库笔记、密码与 GB 级 `.psenc` 媒体密文均无需重新加密。

### 2.3 逐记录子密钥与防回滚认证加密（`cipherVersion = 2`）
- 每次在客户端创建或更新笔记（`note`）、密码（`password`）、媒体元数据（`image` / `video`）或相册（`album`）时：
  - 客户端生成全新 `16B` 随机 `itemSalt` 与 `12B` 随机 `nonce`；
  - 派生独立条目子密钥：`itemKey = HKDF-SHA256(ikm = DEK, salt = itemSalt, info = "privatespace:item:v2:<type>:<id>", len = 32)`；
  - 构造规范化 JSON `AAD = {"v":2,"id":"<id>","type":"<type>","rev":<revision>}`，执行 `AES-256-GCM` 认证加密。
- 即使恶意服务器管理员篡改密文、交换两条记录的数据库行或回滚旧版密文，客户端解密时均会因 GCM Tag / AAD 校验失败立即阻断告警。

### 2.4 客户端 `PSENC001` 分块认证加密媒体与 HTTP `206` 随机解密
- 每个原图、客户端生成的封面缩略图或视频在上传前均在终端分配独立随机 256 位 **文件加密密钥（`FEK`）** 与 `12B` 随机 `baseNonce`：
  - `FEK` 经 `blobKek = HKDF-SHA256(DEK, fekSalt, "privatespace:blob-kek:v1:<blobId>")` + `AES-256-GCM(aad = "fek:<blobId>")` 封装后随元数据保存；
  - 容器头部固定 `20` 字节：`[8B "PSENC001" 魔数][4B uint32BE chunkPlainSize (65536)][8B uint64BE totalPlainSize]`；
  - 明文按 **`64 KiB`（65,536 字节）** 分块，第 `i` 块的 `12B` Nonce 由 `baseNonce` 后 8 字节异或 `uint64BE(i)` 确定性导出，绑定 `AAD = "psenc:v1:<blobId>:<i>:<isFinal?1:0>"` 生成 `[plainLen 密文 + 16B GCM Tag]`。
- **大文件分片加密断点续传**：客户端按 `64 KiB` 整数倍切片，在本地流式加密每一片 `PSENC001` 块后上传至 `/api/v1/media/uploads/:id/chunks/:partIndex`，服务端盲拼接并校验 `PSENC001` 头部与精确密文字节长度后原子入库。
- **$O(1)$ 客户端 HTTP `206` 按需范围解密**：服务端 `/api/v1/media/:id/blob`（及 `/stream`）仅对 `.psenc` 密文执行字节区间响应（携带 `X-PrivateSpace-Cipher: PSENC001`），客户端通过 `computeEncryptedRangeForPlainRange` 计算覆盖目标明文区间的密文块偏移并就地解密校验。

---

## 3. 全平台客户端安全实现（Web / Android / Apple iOS）

1. **双引擎跨环境密码学内核（`src/shared/cryptoPrimitives.ts`）**
   - 优先调用硬件加速的原生 WebCrypto `crypto.subtle`（HTTPS / `localhost` / Node 24）；当用户通过家庭局域网非安全上下文（如 `http://192.168.x.x:8080`）访问时，无缝回退至内置恒定语义一致的纯 TypeScript 密码学实现（SHA-256 / HMAC / PBKDF2 / HKDF / AES-256-GCM），确保内网自部署开箱即用。
2. **Android 原生硬件保险箱（[`mobile/`](../mobile/README.md)）**
   - Kotlin `PrivateSpaceNativePlugin` 通过 `AndroidKeyStore` 硬件不可导出密钥加密存储 `{ token, dekBase64 }`，配合 `BiometricPrompt` 指纹/面容与 6 位 PIN 实现无需重输主密码的本地秒级零知识解锁，默认开启 `FLAG_SECURE` 防截屏与敏感剪贴板 30 秒自动擦除。
3. **Apple iOS 原生 Swift 引擎与 `AVPlayer` 流式解密代理（[`ios/`](../ios/README.md)）**
   - `VaultE2EECrypto.swift` 使用 Apple `CommonCrypto`（`CCKeyDerivationPBKDF`）与 `CryptoKit`（`HKDF<SHA256>`、`AES.GCM`、`HMAC<SHA256>`）100% 对齐 `ZERO_KNOWLEDGE_E2EE_V2` 二进制向量。
   - `EncryptedMediaResourceLoader.swift` 实现 `AVAssetResourceLoaderDelegate` 拦截自定义 `psenc-stream://` 协议，将 `AVPlayer` 的随机拖动请求实时映射为对服务端 `.psenc` 的 `HTTP 206` 密文分块拉取并在内存中即时通过 `AES.GCM.open` 解密喂给解码器，全程无明文临时视频文件落盘。
   - `PrivateSpaceAutoFill` 扩展从 Keychain / App Group `PSCACHE1` 二次加密容器中按域名匹配填充账号口令并自动复制 30s 有效期的 TOTP 验证码。
