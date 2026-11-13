# PrivateSpace 架构与加密同步规范

## 1. 信封加密与分层密钥体系（Envelope Encryption）

为兼顾高强度静态加密（Encryption at Rest）与后续密码框、图片、视频大文件扩展能力，系统采用多层密钥隔离设计：

1. **口令密钥派生（KDF）**
   - 唯一管理员密码经 NFKC 归一化后，输入 `scrypt (N=32768, r=8, p=1)` 与 256 位随机盐 `kdf_salt`，派生 64 字节材料：
     - 前 32 字节作为 **密钥加密密钥（KEK）**；
     - 后 32 字节经 `SHA-256` 摘要作为常量时间口令校验值 `auth_verifier`（通过 `crypto.timingSafeEqual` 比对）。
2. **空间主密钥封装（256-bit DEK）**
   - 初始化时由 CSPRNG 生成 256 位随机空间主密钥 `DEK`。
   - 使用 `KEK` 通过 `AES-256-GCM`（绑定 `AAD = "privatespace:dek:v1"`）加密包裹 `DEK`，将密文信封存入 `admin_config`。
   - **优势**：当管理员轮换主密码时，仅需用新密码派生的 `KEK` 重新包裹 32 字节 `DEK`，无需解密或重写底层海量存储条目。
3. **逐记录子密钥与防篡改认证加密**
   - 每次新建或编辑记录时，生成全新 128 位随机 `item_salt` 与 96 位随机 `nonce`。
   - 通过 `HKDF-SHA256(DEK, item_salt, "privatespace:item:v1:<type>:<id>")` 派生仅属于该记录当前版本的 256 位加密子密钥。
   - 使用 `AES-256-GCM` 加密完整敏感载荷（`title`, `content`, `excerpt`, `tags`, `format`, `wordCount`），并将 `{ v, id, type, rev }` 作为 `AAD` 注入认证标签计算，防止攻击者在数据库层面跨行替换密文或回退版本号。
4. **会话内存零残留保护**
   - 进程启动时在易失内存中生成 256 位临时密钥 `runtimeSecret`。
   - 设备会话中的 `DEK` 由 `HKDF(runtimeSecret || clientSessionSecret)` 加密存储；每次请求认证通过后按需解封并在 `finally` 块立即执行 `dek.fill(0)` 擦除明文缓冲。容器重启后旧会话自动失效并要求重新解锁。

---

## 2. 面向 Web / Android / iOS 的多端同步协议

统一数据表 `vault_items` 以 `item_type` 区分条目类型（当前实现 `'note'`，后续平滑扩展 `'password' | 'image' | 'video'`）：

- **认证方式**：
  - 网页端默认使用 `HttpOnly; SameSite=Lax` Cookie（`pss_session`）；
  - Android / iOS 原生应用通过 `POST /api/v1/auth/login` 获取 `token`，并在请求头携带 `Authorization: Bearer pss_<sessionId>.<secret>`。
- **增量同步游标（`sync_seq`）**：
  - 每次创建、更新、归档、移入回收站或彻底销毁，全局单调序列号 `sync_seq` 原子递增。
  - 客户端保存本地 `lastSyncSeq`，调用 `GET /api/v1/sync?since_seq=<lastSyncSeq>` 即可仅拉取增量变更条目 `items` 与永久删除墓碑 `deleted`。
- **乐观并发控制（Optimistic Concurrency）**：
  - `PATCH /api/v1/notes/:id` 支持传入 `expectedRevision`；若其他端已先行提交新版本，接口返回 `409 REVISION_CONFLICT`，客户端可执行安全合并提示而非静默覆盖。
