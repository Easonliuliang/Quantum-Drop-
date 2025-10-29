太给力了！你这版“全部方案”的纲要已经非常全面。我把它收敛成一份可直接落地的《项目蓝图 v0.1》——包含目标/非目标、接口契约、数据结构、状态机、错误码、里程碑与验收、测试清单与安全策略。照着这份执行，就能把 README 里的愿景一步步做成真正可用的 Courier Agent。

🚀 Courier Agent · 项目蓝图 v0.1（可落地版）
0) 目标 / 非目标
目标
* 跨设备文件传递，Presence-first（先显现后收敛）、E2E 加密、PoT 可验证。
* 多路径：LAN/QUIC → WebRTC/STUN → TURN 中继 →（可选）加密缓存 自动选路。
* 可作为独立应用运行，也能通过事件契约接入 AETHER OS。
非目标（v0.1 不做）
* 群发/多播、大规模分发网络
* 长期云存储/账号体系
* 移动端后台长驻/系统级 Airdrop 替代（S2+ 再评估）

1) 架构总览
UI (Tauri/React)
  ├─ SendPanel / ReceivePanel / HistoryPanel
  └─ useTransfersStore (Zustand)
        ↑  invoke/subscribe
Tauri Commands (Rust)
  ├─ commands.rs        # API 面：generate_code / send / receive / cancel / export_pot / verify_pot
  ├─ transport/         # 传输内核：Router + Adapters(QUIC/WebRTC/Relay/Mock)
  ├─ crypto/            # Noise/libsodium，密钥、封包、签名
  ├─ attestation/       # Merkle/CID，PoT 生成/验证
  ├─ signaling/         # Axum/WS 极薄信令（短码→会话→候选交换）
  └─ store/             # SQLite/JSON 历史记录与设置
Infra
  ├─ STUN                # 公网穿透
  ├─ TURN(coturn)        # 兜底中继
  └─ (optional) Encrypted Cache (对象存储，客户端加密)

2) 开发里程碑 & 验收（Definition of Done）
S1｜虫洞最小核（1–2 周）
* 功能：同网 mDNS 发现、QUIC 直连、短码配对、分块传输、断点续传、PoT、基础 UI。
* DoD
    * 同网成功率 ≥95%
    * 100MB 文件：触发到“已显现”≤1s（元数据/缩略图先显）
    * 生成 *.pot.json 可离线验证
    * 基础错误可复现并有提示（码过期/路径无权/磁盘不足）
S2｜跨网与兜底（2–3 周）
* 功能：WebRTC 穿透、TURN 兜底、多路径编排、可选加密缓存。
* DoD
    * 移动/家宽常见 NAT 场景成功率 ≥90%（启用中继）
    * 多路径并发，先连先用，其余收敛
    * PoT 在跨网场景可验证一致
S3｜体验深水区（1–2 周）
* 功能：预热/预测、自适应分块、设备清单、专家模式（速率/路径/PoT 明细）。
* DoD
    * UI “零路径感”稳定；异常有可理解文案与一键重试
    * 历史记录/搜索/导出 PoT；设置页完成（限速、策略）

3) 前后端契约（Tauri Commands + 事件）
3.1 Commands（Rust）
// invoke signatures（TS）
courier_generate_code(paths: string[], expireSec?: number): Promise<{ taskId: string; code: string; qrDataUrl?: string }>
courier_send(code: string, paths: string[]): Promise<{ taskId: string }>
courier_receive(code: string, saveDir: string): Promise<{ taskId: string }>
courier_cancel(taskId: string): Promise<void>
export_pot(taskId: string, outDir: string): Promise<{ potPath: string }>
verify_pot(potPath: string): Promise<{ valid: boolean; reason?: string }>
list_transfers(limit?: number): Promise<TransferSummary[]>
3.2 Events（Rust → UI）
type TransferProgress = {
  taskId: string
  phase: 'preparing'|'pairing'|'connecting'|'transferring'|'finalizing'|'done'|'error'
  progress?: number        // 0..1（整体估算）
  bytesSent?: number
  bytesTotal?: number
  speedBps?: number
  route?: 'lan'|'p2p'|'relay'|'cache'
  message?: string
}
* 事件名：transfer_started, transfer_progress, transfer_completed, transfer_failed, transfer_log.

4) 数据与文件格式
4.1 分块与内容寻址
* 分块：默认 4 MiB；RTT>80ms 时自适应到 8–16 MiB；弱网可启 FEC（S3）。
* CID：cid = hash(MerkleRoot || salt)；每块 sha256，根用 sha256/blake3。
4.2 PoT（Proof of Transition）示例
{
  "version": "1",
  "task_id": "tsk_01HZX...",
  "timestamp": "2025-10-29T07:51:00Z",
  "sender_fingerprint": "ed25519:...ab",
  "receiver_fingerprint": "ed25519:...cd",
  "files": [
    {
      "name": "report.pdf",
      "size": 104857600,
      "cid": "b3:1f5c...",
      "chunks": 25,
      "merkle_root": "b3:9a7d...",
      "chunk_hashes_sample": ["b3:..."]
    }
  ],
  "route": "lan",                // lan|p2p|relay|cache|mixed
  "attest": {
    "receiver_signature": "ed25519:...sig",
    "algo": "ed25519"
  }
}
4.3 短码/会话
* 短码：6–8 位（Base32 Crockford），有效期默认 15 分钟、单次消耗。
* 会话：QID = ts + rand + sender_fp；信令只记录 QID 与候选地址，不存明文。

5) 核心流程与状态机
5.1 发送端（简化）
select file(s) → collapse(meta/preview) → generate code
→ signaling join(QID) → try routes (LAN→P2P→Relay→Cache)
→ send meta/preview → stream chunks → finalize → PoT
→ (policy) annihilate cache → emit completed
5.2 接收端
input code → signaling join(QID) → route selected
→ receive meta/preview → allocate/saveDir
→ stream + verify(Merkle) → sign PoT → appear → done

6) 传输层抽象
// transport/adapter.rs
#[async_trait]
pub trait TransportAdapter {
  async fn connect(&self, sess: &SessionDesc) -> Result<Box<dyn TransportStream>>;
}

#[async_trait]
pub trait TransportStream: Send + Sync {
  async fn send(&mut self, frame: Frame) -> Result<()>;
  async fn recv(&mut self) -> Result<Frame>;      // 控制/数据帧
  async fn close(&mut self) -> Result<()>;
}
适配器
* QuicAdapter(quinn)（S1）
* WebRtcAdapter(webrtc-rs)（S2）
* TurnRelayAdapter（S2）
* MockLocalAdapter（MVP/测试）
编排器 Router
* 探测并发连：3–5 秒窗口；先通先用，其余降级为备用/增益流（S3 可做 multipath）。

7) 加密与安全
* 密钥交换：短码 → PAKE/Noise 派生会话密钥；或 Noise_NK（发送端临时、接收端静态）。
* 对称加密：XChaCha20-Poly1305。
* 密钥寿命：会话用完即销毁；磁盘缓存加密（同会话密钥派生子键）。
* 最小权限：Tauri FS Scope 限目录；拒绝路径穿越。
* 隐私：默认不上传任何明文或元数据；日志仅本地；PoT 无文件内容。

8) UI/UX（S1 必须）
* Send：拖拽 → 显示短码/二维码 → 显示“已显现”状态 → 进度/速率/路由图标。
* Receive：输入码 → 选择保存目录 → 先显（文件名/缩略图）→ 收敛进度。
* History：最近任务、PoT 导出、验证按钮。
* 错误文案（务实直白）：
    * 码过期：取件码已过期，请重新生成
    * 打洞失败：网络不可直连，已切换中继
    * 磁盘不足：可用空间不足，已暂停接收

9) 错误码（示例）
代码	场景	建议处理
E_CODE_EXPIRED	短码过期/被消费	重生码
E_ROUTE_UNREACH	路由不可达	自动降级/提示中继
E_DISK_FULL	磁盘不足	选择新目录/清理后重试
E_VERIFY_FAIL	Merkle 校验失败	自动重传该块
E_PERM_DENIED	无访问权限	引导授予目录权限
10) 本地存储结构
~/Library/Application Support/CourierAgent/
  transfers.db            # SQLite（任务/历史/索引）
  cache/                  # 临时块（加密）
  proofs/                 # *.pot.json
  logs/

11) 测试与质量
单测（Rust）
* crypto：密钥派生/加解密/完整性
* attestation：Merkle root 正确性、验证器
* transport：MockLocal 循环 & QUIC 回环
前端（Vitest）
* store 事件同步、进度渲染、错误提示
* 组件：Send/Receive/History 基本交互
集成/E2E
* 同网双端：100MB/1GB 场景
* 断点恢复：拔网线/休眠/切网
* PoT 验证：离线校验
CI
* cargo fmt, clippy, cargo test
* npm run build, vitest
* 构建产物（macOS dmg / Windows msi 可后置）

12) 配置（tauri.conf + app.yaml）
* network.preferred = ["lan","p2p","relay"]
* code.expire_sec = 900
* pot.dir = "~/.../proofs"
* stun = ["stun:stun1.example.org", ...]
* turn = ["turns:turn.example.org?transport=udp", ...]
* cache.enabled = false（S2 之后可开）

13) 风险与缓解
* Rust WebRTC 生态差异：先以 QUIC 实现 S1；S2 引 WebRTC，仅用于穿透建立后续 QUIC（可选）。
* iOS 后台：移动端阶段先前台传输；后台用短任务策略 + “星门缓存”兜底。
* 多路径复杂度：S2 先“并发抢占 + 备份流”，S3 再做 multipath 合并。

14) 执行排期
* S1：8–12 pd（含 UI/命令/QUIC/PoT/同网 QA）
* S2：12–18 pd（STUN/TURN、多路径编排、跨网 QA）
* S3：6–8 pd（体验/专家模式/自适应/文档化）

15) 立即行动清单
* 初始化 src-tauri/src/ 模块骨架（commands/transport/crypto/attestation/signaling）
* 定义 Commands & Events 的 TS 类型（放 src/lib/types.ts）
* UI 三面板骨架 + 状态容器 useTransfersStore
* MockLocalAdapter 完成（本机复制模拟传输管线）
* PoT 生成器雏形（对 MockLocal 也产出真正可验的哈希凭证）
* E2E 用例 1：双端同网 100MB、断网→重连


