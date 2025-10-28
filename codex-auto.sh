#!/bin/zsh
mkdir -p logs
cat <<'EOF' | codex exec --sandbox danger-full-access 2>&1 | tee logs/codex_auto_$(date +%H-%M).log
You are operating on a Tauri + Rust + Node project. Execute these steps end-to-end, no prompts:

1. Expand README.md (Overview, Features, Folder Structure, Quick Start, Troubleshooting, AETHER OS design).
2. Create .editorconfig, .gitignore, CONTRIBUTING.md, CODE_OF_CONDUCT.md, docs/ARCHITECTURE.md.
3. Fix all warnings via cargo clippy.
4. Add GitHub Actions CI for build + lint + test.
5. Add scripts/dev.sh and scripts/check.sh.
6. Run validation and commit changes.
EOF
