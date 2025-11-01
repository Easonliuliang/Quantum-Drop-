# Repository Guidelines

## 项目结构与模块组织
- `src/` 存放 React/TypeScript 前端界面；共享状态放在 `src/store`，服务与工具放在 `src/lib`，量子穿梭实验功能集中在 `src/quantum`。
- `src/components/` 负责展示与交互组件，建议使用 PascalCase 文件夹并提供 `index.ts` 导出；Story 与测试文件就地放在同级目录。
- `src-tauri/` 包含 Rust 端运行时（入口见 `src/main.rs`）及 Tauri 配置。自定义 Rust 工具应放入 `src-tauri/src/services`，不要直接修改 `gen/`。
- `docs/` 存储架构文档，`test/` 与 `src/test/` 保存集成测试夹具；`dist/` 与 `target/` 为构建产物，勿手工改动。

## 构建、测试与开发命令
- `npm run dev`（或 `dev:ui`）启动 Vite 开发服务器并启用热更新。
- `npm run tauri:dev` 启动完整桌面壳，会在运行前自动构建 UI。
- `npm run build` 生成生产环境前端包至 `dist/`；需要生成安装包时运行 `npm run tauri:build`。
- `npm run lint`、`npm run test` 分别执行 ESLint 与 Vitest；`npm run check` 会串行运行 lint、test、`cargo fmt --check` 以及 `cargo clippy`。

## 编码风格与命名约定
- 统一使用 TypeScript ES 模块，2 空格缩进与尾随逗号；避免隐式 `any`，提交前可依赖 ESLint 自动修复。
- 组件使用 PascalCase，hooks 与工具使用 camelCase，共享常量使用 SCREAMING_SNAKE_CASE。
- 副作用逻辑保留在 hooks 或 `src-tauri` 命令内；除入口文件外优先使用具名导出。

## 测试规范
- UI 组件测试与源码同目录，命名为 `*.test.tsx`；跨模块集成测试放置于 `test/`。
- 本地运行 `npm run test`，关键模块覆盖率建议保持在 80% 以上；调试时可用 `npm run test -- --ui`。
- Rust 模块的单元测试写在 `src-tauri/src/*`，端到端测试放在 `src-tauri/tests`；通过 `cargo test --manifest-path src-tauri/Cargo.toml` 执行。

## 提交与合并请求指南
- 遵循 Conventional Commits（如 `feat(ui): quantum tunnel animation`），范围保持精炼。
- 每个 PR 需说明行为变化、关联 issue，并在 UI 改动时附上截图或录屏。
- 在请求评审前务必跑通 `npm run check`，同步更新相关文档，并在说明中标注配置或迁移调整。 
