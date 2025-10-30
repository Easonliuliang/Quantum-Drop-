import type { TransferPhase, TransferStatus } from "./types";

export const QUANTUM_PHASE_COPY: Record<
  TransferPhase,
  { title: string; description: string }
> = {
  preparing: {
    title: "量子云凝聚",
    description: "正在建立量子纠缠场",
  },
  pairing: {
    title: "纠缠配对中",
    description: "同步观测窗口",
  },
  connecting: {
    title: "量子通道对齐",
    description: "等待波函数共振",
  },
  transferring: {
    title: "量子隧穿中",
    description: "粒子流穿越势垒",
  },
  finalizing: {
    title: "波函数坍缩",
    description: "能量正在收敛",
  },
  done: {
    title: "观测到量子态",
    description: "数据重组完成",
  },
  error: {
    title: "纠缠中断",
    description: "等待重新建立量子场",
  },
};

const QUANTUM_HINT_OVERRIDES: Partial<Record<TransferPhase, string>> = {
  finalizing: "波函数正在收束，准备观测",
  done: "观测完成，跃迁已稳定",
};

export const quantumHintForPhase = (
  phase: TransferPhase,
  status: TransferStatus,
  progressMessage?: string
) => {
  const message = progressMessage?.trim();
  if (message) {
    return message;
  }
  if (phase === "error") {
    return status === "cancelled"
      ? "纠缠已解除，静待下一次跃迁"
      : "量子态退相干，可尝试重新建立纠缠";
  }
  const override = QUANTUM_HINT_OVERRIDES[phase];
  if (override) {
    return override;
  }
  return QUANTUM_PHASE_COPY[phase].description;
};
