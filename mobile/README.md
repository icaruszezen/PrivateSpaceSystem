# PrivateSpace Android 手机客户端 (`com.privatespace.mobile`)

`mobile/` 是 **PrivateSpace · 私密空间** 的原生 **Android 手机端应用**（基于 **Capacitor 6 + Kotlin 原生安全插件 + React 19 + TypeScript** 构建），同时导出跨平台离线优先同步 SDK（[`PrivateSpaceMobileClient`](./src/syncClient.ts)）。

## 核心架构与功能全景

### 1. 原生 Android 硬件级安全桥接（[`PrivateSpaceNativePlugin.kt`](./android/app/src/main/java/com/privatespace/mobile/PrivateSpaceNativePlugin.kt)）
- **`AndroidKeyStore` AES-256-GCM 密钥保管库**：使用硬件级 `KeyGenParameterSpec` 生成不可导出的 256 位主密钥，将会话凭据（`pss_...`）与快捷 PIN 元数据封装为 `v1.<iv>.<ciphertext>` 密文保存，设备磁盘零明文令牌残留。
- **`BiometricPrompt` 指纹 / 面容快锁**：集成 `androidx.biometric:biometric`，支持 6 位快捷 PIN 码与系统生物识别秒级解封会话密钥。
- **`FLAG_SECURE` 防截屏与后台高斯遮蔽**：在 `MainActivity.onCreate` 首帧渲染前默认挂载 `WindowManager.LayoutParams.FLAG_SECURE`，防止多任务切换卡片泄密及恶意录屏，可在「安全」页按需切换。
- **Android 13+ 敏感剪贴板遮罩与定时擦除**：复制密码或 2FA 验证码时自动标记 `ClipDescription.EXTRA_IS_SENSITIVE` 隐藏系统悬浮预览，并在 30 秒后通过常量时间 `SHA-256` 摘要比对精准擦除剪贴板（绝不误删用户后续复制的普通文本）。
- **系统分享菜单（`Intent.ACTION_SEND`）与一键配对深链（`privatespace://pair`）**：支持从浏览器或其他 App 直接将链接/文本「分享」至 PrivateSpace 加密笔记；支持点击或粘贴 `privatespace://pair?server=...&vault=...` 配对码一键填入自部署服务器地址。
- **自部署内网与私有根证书兼容（[`network_security_config.xml`](./android/app/src/main/res/xml/network_security_config.xml)）**：原生信任系统证书与用户自签根证书（mkcert / Caddy Internal CA），同时兼容家庭局域网（`192.168.x.x`）与 Tailscale（`100.x.y.z`）直连。

### 2. 五大手机触控工作区
1. **密码保险箱（`密码`）**：实时刷新 RFC 6238 动态两步验证码（30s 环形倒计时）、安全健康评分与风险过滤（弱口令 / 重复密码 / 未开启 2FA）、CSPRNG 随机密码与助记词组生成器、CSV 批量导入、自定义隐藏字段与历史密码版本回溯。
2. **加密相册（`相册`）**：支持手机相机直拍加密入库（`capture="environment"`）与相册多选原图分块上传、相册目录管理、暗房级全屏查看器（90° 旋转、双倍缩放、幻灯片轮播）与 `.psenc` 分块密文透视。
3. **私密影院（`影院`）**：`512 KiB` 分片断点续传 + `SHA-256` 校验上传手机 4K 视频，基于 `HTTP 206 Partial Content` 实现 $O(1)$ 任意进度条秒拖播放、`±10s` 快进退与倍速控制。
4. **私密笔记（`笔记`）**：支持 Markdown 源码编辑与安全渲染预览切换、单手快捷排版工具栏、待办清单勾选、置顶/归档/回收站与永久覆写销毁。
5. **安全中心（`安全`）**：深浅双色主题（Warm Editorial Paper / Deep Graphite Ink）、防截屏护盾开关、剪贴板自动擦除开关、6 位 PIN + 生物识别配置、多端在线设备管理与远程一键吊销、主密码无损轮换（KEK 重封装）以及底层 `AES-256-GCM` / `PSENC001` 原始密文十六进制透视器。

### 3. 离线优先缓存与队列回放（[`syncClient.ts`](./src/syncClient.ts)）
- 内置 `IndexedDbVaultPersistence` 本地持久化同步快照与 `lastSyncSeq` 游标。
- 飞行模式或弱网离线时新建/编辑笔记与密码自动进入本地离线变更队列（`PendingQueuedMutation`），恢复联网后在 `syncDelta()` 中自动按序回放并替换为服务端权威 UUID；在线时通过 `/api/v1/sync/stream` SSE 实时感知多端游标变更。

---

## 本地开发、测试与编译 APK

### 1. 手机端热重载调试（浏览器模拟或局域网真机访问）
```bash
# 终端 1：启动后端服务（监听 8080）
npm run dev:server

# 终端 2：启动手机端 Vite 开发服务器（监听 5174 并代理 /api）
npm run dev:mobile
```
生产环境下，后端服务亦在 `http://<server>:8080/mobile/` 内置托管移动端伴侣 Web 包。

### 2. 编译原生 Android 安装包（APK）与运行 Kotlin 单元测试
环境要求：**JDK 17** 与 **Android SDK（Platform 34）**（设置环境变量 `ANDROID_HOME`）。

```bash
# 构建 dist/mobile、同步 Capacitor Android 工程并运行 Kotlin JUnit 单元测试
npm run android:test

# 编译可直接安装至安卓手机的 Debug APK
npm run android:apk
```
生成的 APK 位于：
`mobile/android/app/build/outputs/apk/debug/app-debug.apk`

可通过 `adb` 直接安装至已开启 USB 调试的安卓手机：
```bash
adb install -r mobile/android/app/build/outputs/apk/debug/app-debug.apk
```
