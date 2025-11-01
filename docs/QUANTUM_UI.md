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

## Wave-Dot Tunnel (Fallback)

- `DotBlobFallback2D` replaces the animated canvas with a single, high-density frame when motion should stop. It distributes thousands of dots across concentric shells using a golden-spiral sampling pattern and applies the same orange→indigo band ramp used in 3D.
- Route skins re-use the hue-shift offsets (`lan` −0.08, `p2p` 0, `relay` +0.12) and adjust saturation so the static imprint still hints at the active corridor.
- The fallback drives both reduced-motion sessions and environments where WebGL2 fails the probe; the bitmap re-renders on resize so screenshots remain crisp.

## Dot-Matrix Wormhole

- `DotBlobWormhole3D` is the default WebGL2 renderer. It instantiates 22k–52k point sprites (based on intensity 1..3) across a deformed sphere/tube lattice and displaces them entirely in the vertex shader using layered FBM noise plus a gentle Y-axis swirl.
- The fragment shader discards pixels outside the disc mask, applies a stochastic dither, then samples a five-stop orange→red→magenta→violet→indigo ramp. Banding comes from `uStripes`; hue tinting is handled through `uHueShift` so each route keeps its own accent (cyan-teal for LAN, indigo for P2P, amber-magenta for relay).
- Uniforms cover time, speed (`0.6..1.8×`), swirl, noise amplitude, stripe count, hue shift and exposure. The renderer clamps DPR to 1.5, pauses when `document.hidden`, and gradually damps noise/exposure changes so bursts feel organic.
- File drops trigger `triggerBurst()` for 400–700 ms, boosting `uNoiseAmp`/`uExposure` before dispatching the transfer. The orchestrator also pulses the burst when phases enter `tunnel`.
- When WebGL2 is unavailable or motion is disabled, the orchestrator and dropzone swap to the fallback frame while keeping the black, rounded mask so the surface remains consistent.

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
- `settings.quantumIntensity` defaults to `2` (`1..3`) and controls how many rings/dots the tunnel paints.
- `settings.quantumSpeed` defaults to `1.0` (`0.6..1.6`) and scales the phase velocity so the warp can be relaxed or accelerated.
- `settings.animationsEnabled` defaults to `true`. Disabling it falls back to the static tunnel frame and propagates to `QuantumDotTunnel` via `reducedMotion`.
- `settings.enable3DQuantum` defaults to `true` on desktop and activates the WebGL tunnel whenever WebGL2 is detected at runtime. The flag holds user intent even if the current session falls back to 2D after a failed capability probe.
- `settings.quantum3DQuality` (`low`/`medium`/`high`) tunes instanced particle counts; `settings.quantum3DFps` clamps the render loop between 30 and 60fps.
- The Settings panel adds icon-only controls for the 3D toggle, density, and frame cap. Controls disable automatically when the session downgrades to the 2D tunnel due to unsupported GPUs or reduced-motion preferences.

## Immersive Dropzone (zero-copy UI)

- `QuantumDropzone` now hosts the canvas tunnel and a lightweight glow overlay (`qdz-halo`, `qdz-grid`, `qdz-focus`) instead of the previous DOM particle stack. The surface stretches edge-to-edge, keeps pointer events on the root element, and relies on sr-only helpers for instructions.
- Route skins (`qdz--lan`, `qdz--p2p`, `qdz--relay`) remap colour variables for the canvas, background gradient, and focus halo, so each transport still feels distinct without labels.
- Send mode keeps drag-and-drop wired to `startSend`, while Receive mode mounts the tunnel in a disabled state to reflect current progress without accepting files.
- Icon-only smoke-test buttons remain available and rely on `aria-label`s for accessibility.
- `qdz-static` activates when either the OS or app disables animation. The canvas renders a single frame and the CSS halos soften, preserving the immersive look without motion.

## Reduced Motion & Audio

- Canvas rendering pauses when `reducedMotion` is true or when `settings.animationsEnabled` is toggled off. The tunnel paints a static frame and CSS halos drop to a low-energy style.
- Existing CSS guards still silence the legacy photon/starlight layers when the classic tunnel renders.
- The `playQuantumPing` helper remains optional; browsers without `AudioContext` simply skip playback.

## Drag & Resume

- `QuantumDropzone` now powers drag-and-drop sends when the immersive mode is active; the legacy `QuantumDragZone` appears when `minimalQuantumUI` is disabled.
- All panels consume the shared status-to-phase helper so every task always presents a phase, even when the backend only reports a high-level status.

Refer to `src/components/QuantumTunnel.tsx` for the stage layout and to `src/lib/quantumPhases.ts` for the shared copy map.
