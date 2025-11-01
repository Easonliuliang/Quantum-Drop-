发布与打包指南

概览
- 触发方式：推送 tag（形如 v0.1.1）或手动触发 GitHub Actions 的 Release Bundles 工作流。
- 产物：macOS/Windows/Linux 三平台安装包与应用包，会自动附加到对应 tag 的 GitHub Release 中。

环境与版本锁定
- Node 版本：.nvmrc（18.18.0），CI 使用 node-version-file 保持一致。
- Rust 工具链：rust-toolchain.toml（stable，含 rustfmt/clippy）。
- 包管理：建议本地使用 npm ci（与 CI 保持一致）。

如何发版
1. 更新 version（如有需要）：package.json 和/或 src-tauri/tauri.conf.json。
2. 推送 tag：git tag -a v0.1.1 -m "v0.1.1" && git push origin v0.1.1。
3. 进入 GitHub Actions，等待 Release Bundles 工作流完成。
4. 产物在 Releases 页面可见并可下载。

代码签名（Windows/Linux 简述）
- Windows 代码签名
  - 准备 EV/标准代码签名证书（建议 EV）。
  - CI 方案 A（自托管/Runner 安装证书）：使用 signtool.exe 对 .exe/.msi 进行签名。
  - CI 方案 B（云密钥服务）：用 Azure Key Vault 或者类似服务托管证书，流水线中远程签名。
  - Tauri 可通过打包后自定义签名步骤集成（例如在 构建后/发布前 步骤调用 signtool）。

- Linux 包签名
  - deb/rpm 需要用 GPG 私钥签名，便于仓库/来源校验。
  - AppImage 可附带签名/校验文件，或通过发行渠道校验。
  - 一般做法：在 CI 中通过 actions/checkout 拉取密钥（存于 GitHub Secrets），在打包后执行签名命令并替换产物。

macOS（补充说明）
- 如果对外发包，建议加入开发者签名与公证（notarization），以避免 Gatekeeper 阻断。
- 目前本仓库默认使用未签名包用于内部测试。

注意事项
- 图标：src-tauri/tauri.conf.json 中的 bundle.icon 如启用，需提供有效 PNG（各尺寸），否则会阻塞打包。
- CI 构建缓存：可按需加入 Rust/Node 缓存以提速（actions/cache）。
- 如果需要自动创建 Release 而非仅上传到 tag 对应 Release，工作流已包含 softprops/action-gh-release 完成这一动作。
