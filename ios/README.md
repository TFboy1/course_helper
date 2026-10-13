# Flutter iOS 客户端

本目录构建仓库现有 Flutter 移动客户端，包括账号管理、学习通活动、雨课堂动态二维码签到、PPT 和课堂答题。网页版批量签到是独立功能，详情见仓库根目录说明。

使用 Flutter **3.41.8 / Dart 3.11.5** 和锁定的依赖。最低 iOS 13，支持 iPhone、iPad。复用现有移动端页面，不额外增加原生界面或 WebView 客户端。

## 已完成的 iOS 适配

- 修复 Podfile 中不存在的 `parse_KV_file` 调用，使用 Flutter 标准的 Generated.xcconfig 读取方式。
- 配置相机、相册、前台定位、通知权限宏；补充相册读权限说明。
- 注册系统通知代理，并设置 iOS 本地通知显示参数。
- 扫码在权限弹窗和应用切换期间正确等待相机操作，统一防止重复返回扫码结果。
- iOS 初始化百度地图、定位 SDK 鉴权；支持通过 `--dart-define=BAIDU_IOS_AK=...` 配置与实际 Bundle ID 绑定的 iOS AK。
- 修正定位结果判定：Android 独有的 `locType` 不再用于 iOS，校验 iOS 错误码及有效坐标，避免将 iOS 正常定位判成失败。
- 雨课堂 PPT 页面在 iOS 暂停时关闭连接、回到前台时重连；Android 继续使用现有前台服务。iOS 系统会限制后台运行，不能保证锁屏后持续接收课堂 WebSocket 消息。

真实登录、签到、地图鉴权、摄像头和课堂连接仍需在本人设备上使用有效账号核对。页面操作由你自行验证，构建流程只编译和打包。

## 从 Windows 获取待签名 IPA

GitHub 工作流：[ios-flutter.yml](../.github/workflows/ios-flutter.yml)。推送已授权的 `codex/ios-webclient` 分支会自动使用 macOS runner 编译 iPhone Release 包；工作流进入默认分支后也可以手动运行。

成功后在该次 Actions 运行的 Artifacts 下载 `course-helper-ios-unsigned`，包含：

- `CourseHelper-ios-unsigned.ipa`：真实编译的 arm64 iPhone 包，需要签名。
- `INSTALL.txt`：安装条件说明。
- `SHA256.txt`：该次安装包校验值。

**待签名 IPA 不能直接安装。** 不会用自签名证书冒充 Apple 安装签名。当前没有 Apple 证书、描述文件或账号授权，云端流程只生成待签名包。

### 没有付费开发者账号时

可以在自己的 Windows 电脑使用 [AltStore 官方安装说明](https://faq.altstore.io/getting-started/how-to-install-altstore-windows)，由你本人在本地输入自己的 Apple ID，将 IPA 签名安装到自己的 iPhone。普通 Apple ID 的个人签名有有效期和数量限制，须按工具提示刷新；不能作为所有人通用的安装签名。请不要把 Apple ID 密码、验证码或签名私钥提交到源码或聊天中。

当前客户端不启用 APNs 推送能力，避免依赖付费账号的推送签名权限；已收到的课堂消息可通过本地通知提示。应用后台被系统暂停时不能靠本地通知替代服务端 APNs 推送。

### 有有效证书时

用于多台已登记 iPhone 的 Ad Hoc 安装，需要 Apple Developer Program、包含私钥的 Apple Distribution 证书、与 App ID 和设备 UDID 对应的描述文件。参考 [Apple Ad Hoc 描述文件说明](https://developer.apple.com/help/account/provisioning-profiles/create-an-ad-hoc-provisioning-profile)。

## 在 Mac 上构建已签名 IPA

安装 Xcode、iOS SDK、CocoaPods 和 Flutter 3.41.8。打开 `ios/Runner.xcworkspace`，将 Runner 的 Bundle Identifier、Signing & Capabilities 的 Team 和自动签名配置为你自己的账号；首次需先安装 Flutter 依赖。

```bash
flutter pub get --enforce-lockfile
flutter build ipa --release --export-method ad-hoc
```

也可以使用 Xcode 导出时生成的配置：

```bash
flutter build ipa --release --export-options-plist=/absolute/path/ExportOptions.plist
```

产物位于 `build/ios/ipa/`。这些命令使用自己的有效签名材料，无法通过项目源码凭空获得 Apple 签名。官方步骤见 [Flutter iOS 发布说明](https://docs.flutter.dev/deployment/ios)。

需要地图、定位功能时，使用百度开放平台与最终 Bundle ID 对应的 iOS AK：

```bash
flutter build ipa --release --export-method ad-hoc --dart-define=BAIDU_IOS_AK=你的iOS_AK
```

GitHub 构建同样可设置 Actions Secret `BAIDU_IOS_AK`。现有仓库的历史 AK 不保证适用于你自己的签名 Bundle ID；错误绑定会使地图、定位鉴权失败，不影响两个平台的二维码签到构建。

证书 `.p12`、私钥 `.p8`、描述文件 `.mobileprovision` 和 IPA 已加入忽略规则，避免误提交。分发安装包时须同时提供对应源码，遵守根目录 GPL-3.0 LICENSE。
