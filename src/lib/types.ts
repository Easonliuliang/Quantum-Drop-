export type TransferTab = "send" | "receive" | "history";

export type TransferDirection = "send" | "receive";
export type TransferStatus =
  | "pending"
  | "inprogress"
  | "completed"
  | "cancelled"
  | "failed";
export type TransferPhase =
  | "preparing"
  | "pairing"
  | "connecting"
  | "transferring"
  | "finalizing"
  | "done"
  | "error";
export type TransferRoute = "lan" | "p2p" | "relay" | "cache";

export interface TransferFileSummary {
  name: string;
  size: number;
}

export interface TransferSummaryRaw {
  task_id: string;
  code?: string | null;
  direction: TransferDirection;
  status: TransferStatus;
  created_at: string;
  updated_at: string;
  files: TransferFileSummary[];
  pot_path?: string | null;
}

export interface TransferSummary {
  taskId: string;
  code?: string;
  direction: TransferDirection;
  status: TransferStatus;
  createdAt: string;
  updatedAt: string;
  files: TransferFileSummary[];
  potPath?: string;
}

export interface TransferLifecycleEventPayload {
  task_id: string;
  direction: TransferDirection;
  code?: string | null;
  message?: string | null;
}

export interface TransferLifecycleEvent {
  taskId: string;
  direction: TransferDirection;
  code?: string;
  message?: string;
}

export interface TransferProgressEventPayload {
  task_id: string;
  phase: TransferPhase;
  progress?: number | null;
  bytes_sent?: number | null;
  bytes_total?: number | null;
  speed_bps?: number | null;
  route?: TransferRoute | null;
  message?: string | null;
}

export interface TransferProgressEvent {
  taskId: string;
  phase: TransferPhase;
  progress?: number;
  bytesSent?: number;
  bytesTotal?: number;
  speedBps?: number;
  route?: TransferRoute;
  message?: string;
}

export interface TransferLogEventPayload {
  task_id: string;
  message: string;
}

export interface TransferLogEvent {
  taskId: string;
  message: string;
  timestamp: string;
}

export interface GenerateCodeResponse {
  taskId: string;
  code: string;
  qrDataUrl?: string | null;
}

export interface TaskResponse {
  taskId: string;
}

export interface ExportPotResponse {
  potPath: string;
}

export interface VerifyPotResponse {
  valid: boolean;
  reason?: string | null;
}
