# Android & iOS 自动更新与 GitHub 仓库 / App 参数配置完整指南

PrivateSpace 为 **Android 原生端（APK）**、**iOS 原生 SwiftUI 端（IPA / OTA / TestFlight）** 及 **`/ios` 独立主屏幕 Web 端（PWA）** 提供统一的 **GitHub Releases 自动版本检测、SHA-256 完整性校验与一键升级** 能力，同时支持私有 GitHub 仓库服务端免暴露 Token 代理及局域网离线分发。

---

## 一、整体自动更新工作流架构

1. **发版构建（GitHub Actions）**：当向仓库推送语义化标签（如 `v0.5.0` 或 `v0.6.0-beta.1`）时，[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) 自动注入版本号与递增构建号（如 `0.5.0` → `500`），编译签名 **Android APK** 与 **iOS IPA + `ios-ota-manifest.plist`**，生成 `SHA256SUMS.txt` 与结构化清单 `release-manifest.json`，并自动发布到 **GitHub Releases**。
2. **版本检测（双模式自适应）**：
   - **跟随自托管服务端网关（默认推荐，`sourceMode = server`）**：App 请求自部署节点的 `GET /api/v1/updates/check?platform=android|ios`，由服务端带缓存查询 `GITHUB_REPO`（若配置 `GITHUB_TOKEN` 则可代理私有仓库安装包下载，避免在手机端暴露 Token）；若服务端处于无外网环境，客户端支持回退或读取服务端本地目录 `${DATA_DIR}/releases/release-manifest.json`。
   - **直连自定义 GitHub 仓库（`sourceMode = github`）**：App 直接请求 `https://api.github.com/repos/<owner>/<repo>/releases` 并解析最新匹配资产与 SHA-256 摘要，适合公开 Fork 仓库独立分发。
3. **端侧安装与完整性校验**：
   - **Android 原生端**：通过 `PrivateSpaceNativePlugin.downloadAndInstallApk` 流式下载 APK 至应用专属缓存目录，**强制校验 SHA-256 哈希一致后**通过 `FileProvider` + `REQUEST_INSTALL_PACKAGES` 调起系统安装器完成覆盖升级（若尚未授予“安装未知应用”权限则自动引导跳转系统授权页）。
   - **iOS 端**：支持 **Apple 无线 OTA 直装**（`itms-services://?action=download-manifest&url=...`）、**TestFlight / App Store 跳转**、**AltStore / SideStore 一键导入**、**`.ipa` 下载**，以及 **`/ios` Web PWA 缓存一键热刷新**。

---

## 二、GitHub 仓库参数配置（Actions 权限、Secrets 与 Variables）

进入您的 GitHub 仓库（如 Fork 后的 `<你的用户名>/PrivateSpaceSystem`）→ **Settings**：

### 1. 开启 GitHub Actions 自动发版写入权限
前往 **Settings → Actions → General → Workflow permissions**：
- 勾选 **Read and write permissions**，点击 **Save**（允许 `mobile-release` 任务在推送 `v*.*.*` 标签时自动创建 GitHub Release 并上传 APK/IPA 资产）。

### 2. 配置 Android 正式签名密钥（Repository Secrets — 强烈推荐）
> **重要提示**：Android 系统要求覆盖升级（保留本地 KeyStore 数据不卸载重装）的旧版与新版 APK **必须使用同一个 Keystore 签名**，否则系统会报错 `INSTALL_FAILED_UPDATE_INCOMPATIBLE`。若未配置以下 Secrets，CI 会自动回退为生成 `debug` 签名测试包。

#### 第 1 步：在本地电脑生成一次专属 Android 签名证书并转为 Base64
```bash
keytool -genkeypair -v \
  -keystore privatespace-release.jks \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -alias privatespace

# 输出单行 Base64 字符串（复制输出内容填入 GitHub Secret）
base64 -w 0 privatespace-release.jks 2>/dev/null || base64 -i privatespace-release.jks | tr -d '\n'
```

#### 第 2 步：前往 `Settings → Secrets and variables → Actions → Secrets` 添加：

| Secret 名称 | 是否必填 | 参数说明与示例 |
| :--- | :--- | :--- |
| `ANDROID_KEYSTORE_BASE64` | 推荐必填 | 上一步生成的 `.jks` / `.keystore` 文件单行 Base64 字符串 |
| `ANDROID_KEYSTORE_PASSWORD` | 推荐必填 | Keystore 密钥库密码 |
| `ANDROID_KEY_ALIAS` | 推荐必填 | 密钥别名（如上例中的 `privatespace`） |
| `ANDROID_KEY_PASSWORD` | 可选 | 密钥条目密码（若与 `ANDROID_KEYSTORE_PASSWORD` 相同可留空） |

### 3. 配置 iOS 签名 / TestFlight 自动上传参数（Repository Secrets — 按需选配）
> 若您拥有 Apple Developer 账号并希望 CI 自动导出已签名的 Ad-Hoc / Enterprise OTA `.ipa` 或自动上传至 **TestFlight**，可在 **Actions → Secrets** 添加以下密钥；**若全部留空，CI 仍会正常通过编译并自动打包 `PrivateSpace-iOS-vX.Y.Z-unsigned.ipa` 供 AltStore / SideStore / TrollStore 自签安装**。

| Secret 名称 | 适用场景 | 参数说明 |
| :--- | :--- | :--- |
| `IOS_BUILD_CERTIFICATE_BASE64` | 签名 IPA / OTA | Apple Distribution `.p12` 证书文件的 Base64 编码字符串 |
| `IOS_P12_PASSWORD` | 签名 IPA / OTA | 导出 `.p12` 证书时设置的密码 |
| `IOS_PROVISION_PROFILE_BASE64` | 签名 IPA / OTA | 主应用（`io.privatespace.ios`）`.mobileprovision` 描述文件的 Base64 |
| `IOS_AUTOFILL_PROVISION_PROFILE_BASE64` | 签名 IPA（含自动填充扩展） | 自动填充扩展（`io.privatespace.ios.autofill`）`.mobileprovision` 的 Base64 |
| `APPSTORE_ISSUER_ID` | 自动上传 TestFlight | App Store Connect → 用户和访问 → 整合 → 密钥 中的 **Issuer ID** |
| `APPSTORE_KEY_ID` | 自动上传 TestFlight | App Store Connect API 密钥的 **Key ID**（如 `2X9R4HXF34`） |
| `APPSTORE_PRIVATE_KEY` | 自动上传 TestFlight | 下载的 `AuthKey_<KEY_ID>.p8` 文件完整文本内容（含 `-----BEGIN PRIVATE KEY-----`） |

### 4. 配置应用包名与分发渠道变量（Repository Variables — 可选）
前往 **`Settings → Secrets and variables → Actions → Variables`**，可按需覆盖默认 App 标识：

| Variable 名称 | 默认值 | 参数说明 |
| :--- | :--- | :--- |
| `ANDROID_APPLICATION_ID` | `com.privatespace.mobile` | Android APK 的 `applicationId` |
| `ANDROID_MIN_SUPPORTED_VERSION` | 空 | 低于该版本的 Android 客户端将弹出**安全强制升级**弹窗（如 `0.4.0`） |
| `IOS_BUNDLE_ID` | `io.privatespace.ios` | iOS 主应用 `PRODUCT_BUNDLE_IDENTIFIER` |
| `APPLE_TEAM_ID` | 空 | 10 位 Apple Developer Team ID（配置 iOS 真机证书签名时必填，如 `A1B2C3D4E5`） |
| `IOS_EXPORT_METHOD` | `ad-hoc` | Xcode 导出方式：`ad-hoc`、`enterprise`、`app-store` 或 `development` |
| `IOS_OTA_BASE_URL` | 空 | 自部署 HTTPS 域名（如 `https://vault.example.com`），用于生成指向服务端 `/api/v1/updates/ios-manifest.plist` 的无线 OTA 链接 |
| `IOS_TESTFLIGHT_URL` | 空 | TestFlight 公开或内部测试邀请链接（如 `https://testflight.apple.com/join/xxxxxx`） |
| `IOS_APP_STORE_ID` | 空 | App Store 数字应用 ID（如 `6500000000`） |
| `IOS_MIN_SUPPORTED_VERSION` | 空 | 低于该版本的 iOS 客户端将触发强制升级提示 |

---

## 三、自部署服务端 `.env` 参数配置

在部署 Docker 容器或 Node.js 服务时，编辑项目根目录 `.env`（参考 [`.env.example`](../.env.example)）：

```dotenv
# 1. 指定您自己的 GitHub 发布仓库（若 Fork 了本项目，请改为 <你的GitHub用户名>/PrivateSpaceSystem）
GITHUB_REPO=icaruszezen/PrivateSpaceSystem

# 2. 若仓库为 Private 私有仓库，或希望避免服务器 IP 触发 GitHub 匿名 60 次/小时限流：
#    在 GitHub -> Settings -> Developer settings -> Personal access tokens -> Fine-grained tokens 创建只读 Token：
#    Repository access: Only select repositories (勾选 PrivateSpaceSystem)
#    Permissions -> Repository permissions -> Contents: Read-only
GITHUB_TOKEN=github_pat_xxxxxxxxxxxxxxxxxxxxxxxxx

# 3. 默认版本通道：stable（稳定版）或 beta（包含 -beta/-rc 预发布版）
UPDATE_CHANNEL=stable
UPDATE_CACHE_TTL_SECONDS=300

# 4. Android 与 iOS 客户端包名及可选强制升级基线、iOS 分发链接
ANDROID_APPLICATION_ID=com.privatespace.mobile
ANDROID_MIN_SUPPORTED_VERSION=

APPLE_APP_ID=TEAMID.io.privatespace.ios
IOS_BUNDLE_ID=io.privatespace.ios
IOS_MIN_SUPPORTED_VERSION=
IOS_TESTFLIGHT_URL=
IOS_APP_STORE_ID=
IOS_OTA_MANIFEST_URL=
```

> **纯内网 / 离线局域网自定义发版（免 GitHub 访问）**：
> 若自部署服务器处于完全隔离的内网，只需将构建好的 `.apk`、`.ipa` 与 `release-manifest.json` 放入 `${DATA_DIR}/releases/` 目录，服务端 `/api/v1/updates/check` 与 `/api/v1/updates/download/:platform` 会自动优先使用本地清单并计算 SHA-256 分发给内网手机端！

---

## 四、Android 与 iOS 客户端 App 内参数配置方法

解锁进入手机客户端后，切换至底部第 5 栏 **「安全」** → 找到 **「软件版本与 GitHub 自动更新」** 卡片：

1. **自动检查开关**：默认开启「启动与切回前台时自动检查新版本」，每次解锁或从后台恢复时自动静默比对 SemVer 版本号。
2. **版本通道切换**：
   - **Stable 正式稳定版**：仅检测正式 Release（如 `v0.5.0`）。
   - **Beta 预览测试版**：同时接收带 `-beta.1` / `-rc.1` 后缀的 Pre-release 构建。
3. **GitHub 分发源模式切换**：
   - **跟随服务端网关（推荐）**：无需在每台手机重复填写仓库参数，自动继承自部署服务端 `.env` 的 `GITHUB_REPO`、私有仓库代理下载通道及动态生成的 Apple OTA `ios-manifest.plist`。
   - **直连 GitHub 仓库**：切换后输入任意公开仓库地址 `owner/repo`（例如 `yourname/PrivateSpaceSystem`，也支持直接粘贴 `https://github.com/yourname/PrivateSpaceSystem` URL 自动清洗），点击 **保存** 即可直连该仓库的 GitHub Releases。

---

## 五、如何一键发布新版本触发手机端自动更新

完成代码修改后，只需推送符合 SemVer 规范的 `v*.*.*` Git 标签：

```bash
# 1. 可选：同步更新 package.json 版本号
npm version 0.5.0 --no-git-tag-version
git add package.json
git commit -m "chore(release): bump version to 0.5.0"

# 2. 创建并推送版本标签（预发布版可使用 v0.5.0-beta.1）
git tag v0.5.0
git push origin main --tags
```

推送后约 3–6 分钟，GitHub Actions 将自动完成全量测试、编译签名 Android APK 与 iOS IPA、计算 SHA-256 并发布到仓库 **Releases** 页面；所有已安装的 Android 与 iOS 客户端下次打开或点击「检查更新」即可收到 `v0.5.0` 升级通知并一键完成更新。
