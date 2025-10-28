# Contributing to Courier Agent

Welcome! Courier Agent is the data-plane intelligence for the AETHER OS ecosystem. Contributions that improve resilience, observability, and developer experience are especially appreciated.

## Development Flow

1. **Fork & branch** – use feature branches named `feat/<topic>` or `fix/<topic>`.
2. **Install toolchains** – ensure Rust (1.77+), Node.js (18.17+), and the Tauri prerequisites for your platform are available.
3. **Bootstrap dependencies**  
   ```bash
   npm install
   ```
4. **Run the dev shell**  
   ```bash
   ./scripts/dev.sh
   ```
5. **Validate before pushing**  
   ```bash
   ./scripts/check.sh
   ```

## Commit & PR Guidelines

- Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore:` …).
- Write focused commits; avoid bundling unrelated changes.
- Update documentation and tests alongside code changes.
- Open a draft PR early if you want feedback—tag maintainers when the change stabilises.

## Code Style

- Rust follows `rustfmt` defaults and must pass `cargo clippy -- -D warnings`.
- TypeScript adheres to the project ESLint profile (`npm run lint`).
- Prefer small, composable modules; add comments only where intent is non-obvious.

## Security & Incident Reporting

Report suspected vulnerabilities privately via security@aetheros.dev. Coordinated disclosure (90 days) is requested so patches can be prepared for downstream users.

## Communication Channels

- **Issues** – bug reports and feature requests.
- **Discussions** – architecture debates, UX research, and roadmap alignment.
- **Release Notes** – summarise user-facing changes; automation will compile highlights from merged PRs.

Thank you for helping Courier Agent evolve into the backbone of AETHER’s data presence layer.⚛
