# 开发说明

## 安装依赖

```powershell
npm install
```

## 启动开发模式

```powershell
npm run tauri dev
```

## 构建前端

```powershell
npm run build
```

## 构建 Windows 安装包

```powershell
npm run tauri build
```

## 构建 macOS 安装包

macOS DMG 必须在 Mac 或 GitHub macOS Runner 中构建：

```bash
npm ci
npm run tauri build -- \
  --target aarch64-apple-darwin \
  --bundles dmg \
  --config src-tauri/tauri.macos.conf.json
```

GitHub Actions 入口为 `.github/workflows/build-macos.yml`。构建产物位于
`src-tauri/target/aarch64-apple-darwin/release/bundle/dmg/`，详细说明见
`docs/macos.md`。

## 本地目录约定

- 源码修改、依赖安装、构建和测试应在开发目录进行。
- GitHub 发布目录只保留准备提交的干净文件，不放 `node_modules`、`dist`、`src-tauri/target`、安装包、日志和临时截图。
