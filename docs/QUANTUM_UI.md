# Quantum Tunnel Interface

Courier Agent's quantum tunnel mode reframes file transfer into a lightweight, sensory experience. The interface follows three guiding principles inspired by the **量子跃迁用户体验设计** document:

- **Observer first** – confirmation collapses the transfer, so every state speaks directly to the person watching.
- **Timeless motion** – remove discrete progress bars; instead, show evolving fields that imply continual motion.
- **Spaceless connection** – routes fade into ambience, hinting at naturally entangled devices rather than distant peers.

## Visual Stages

The tunnel transitions through three distinct moments:

1. **Quantum cloud** (`preparing`, `pairing`, `connecting`)
   - Swirling field condenses as routes handshake.
   - Copy: "量子云凝聚" / "纠缠配对中" / "量子通道对齐".
2. **Photon tunnel** (`transferring`)
   - Photon stream and starlight animations signal energy flow.
   - Copy: "量子隧穿中 · 粒子流穿越势垒".
3. **Wave collapse** (`finalizing`, `done`)
   - Field contracts into starlight bursts as data reassembles.
   - Copy: "波函数坍缩" / "观测到量子态".

Failures map to `error` with "纠缠中断" messaging and enable the “继续跃迁” resume CTA whenever chunk metadata supports recovery.

## Status Language

`QuantumStatusIndicator` renders the friendly vocabulary for every phase and falls back to the same text for hints if the transport layer does not provide richer messages.

| Phase | Title | Description |
| --- | --- | --- |
| preparing | 量子云凝聚 | 正在建立量子纠缠场 |
| pairing | 纠缠配对中 | 同步观测窗口 |
| connecting | 量子通道对齐 | 等待波函数共振 |
| transferring | 量子隧穿中 | 粒子流穿越势垒 |
| finalizing | 波函数坍缩 | 能量正在收敛 |
| done | 观测到量子态 | 数据重组完成 |
| error | 纠缠中断 | 等待重新建立量子场 |

Hints prefer transport messages, otherwise they use copy derived from the table above, with overrides for finalisation and error cases.

## Settings & Persistence

- `settings.quantumMode` defaults to `true` and persists alongside existing runtime settings.
- The Settings panel exposes a "Quantum tunnel interface" toggle and synchronises the Zustand store so panels switch instantly.
- When the toggle is off, the legacy progress bar, route chips, and numeric ETA return.
- `settings.minimalQuantumUI` defaults to `true` and enables the textless quantum dropzone for send/receive; toggling it reverts to the original form-driven UI.

## Immersive Dropzone (zero-copy UI)

- `QuantumDropzone` renders a full-bleed, text-free surface for initiating transfers. It layers a singularity core, rotating rings, particle field, and drag orbit sensor to express each phase (`cloud`, `tunnel`, `collapse`, `decohere`).
- Route skins (`qdz--lan`, `qdz--p2p`, `qdz--relay`) adjust gradients, particle colours, and motion speed so the lane is recognisable at a glance without labels.
- The send panel binds `onFiles` to the existing `startSend` workflow; the receive panel reuses the component in a disabled state to visualise “awaiting files”.
- Icon-only buttons keep the P2P and relay smoke tests accessible without introducing visible copy. Each button exposes descriptive `aria-label`s for assistive tech.
- CSS honours `prefers-reduced-motion` by disabling all keyframe animations while retaining the layered visuals, ensuring the experience remains functional for users who opt out of motion.

## Reduced Motion & Audio

- Animations are pure CSS with `prefers-reduced-motion: reduce` guards that disable the photon stream, starlight pulse, and drag-zone glow.
- A compact WebAudio helper (`playQuantumPing`) plays short tones on stage transitions. Browsers without `AudioContext` simply skip playback.

## Drag & Resume

- `QuantumDropzone` now powers drag-and-drop sends when the immersive mode is active; the legacy `QuantumDragZone` appears when `minimalQuantumUI` is disabled.
- All panels consume the shared status-to-phase helper so every task always presents a phase, even when the backend only reports a high-level status.

Refer to `src/components/QuantumTunnel.tsx` for the stage layout and to `src/lib/quantumPhases.ts` for the shared copy map.
