export type TransferTab = "send" | "receive" | "history" | "settings";

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
  route?: TransferRoute | null;
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
  route?: TransferRoute;
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

export interface TransferProgressPayload {
  task_id: string;
  phase: TransferPhase;
  progress?: number | null;
  bytes_sent?: number | null;
  bytes_total?: number | null;
  speed_bps?: number | null;
  route?: TransferRoute | null;
  message?: string | null;
  resume?: TransferResumeState | null;
}

export interface TransferProgress {
  taskId: string;
  phase: TransferPhase;
  progress?: number;
  bytesSent?: number;
  bytesTotal?: number;
  speedBps?: number;
  route?: TransferRoute;
  message?: string;
  resume?: TransferResumeState;
}

export interface TransferResumeState {
  chunkSize: number;
  totalChunks: number;
  receivedChunks: boolean[];
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

export interface P2pSmokeTestResponse {
  route: string;
  bytesEchoed: number;
}

export type ErrorCode =
  | "E_UNKNOWN"
  | "E_INVALID_INPUT"
  | "E_NOT_FOUND"
  | "E_CODE_EXPIRED"
  | "E_ROUTE_UNREACH"
  | "E_DISK_FULL"
  | "E_VERIFY_FAIL"
  | "E_PERM_DENIED";

export interface SettingsPayload {
  preferredRoutes: string[];
  codeExpireSec: number;
  relayEnabled: boolean;
  chunkPolicy: ChunkPolicySettings;
}

export interface ChunkPolicySettings {
  adaptive: boolean;
  minBytes: number;
  maxBytes: number;
}

export type CourierGenerateCodeCommand = (
  paths: string[],
  expireSec?: number
) => Promise<GenerateCodeResponse>;

export type CourierSendCommand = (
  code: string,
  paths: string[]
) => Promise<TaskResponse>;

export type CourierReceiveCommand = (
  code: string,
  saveDir: string
) => Promise<TaskResponse>;

export type CourierCancelCommand = (taskId: string) => Promise<void>;

export type ExportPotCommand = (taskId: string) => Promise<ExportPotResponse>;

export type VerifyPotCommand = (potPath: string) => Promise<VerifyPotResponse>;

export type LoadSettingsCommand = () => Promise<SettingsPayload>;
export type UpdateSettingsCommand = (
  payload: SettingsPayload
) => Promise<SettingsPayload>;

export type ListTransfersCommand = (
  limit?: number
) => Promise<TransferSummaryRaw[]>;

export type CourierP2pSmokeTestCommand = () => Promise<P2pSmokeTestResponse>;
export type CourierRelaySmokeTestCommand = () => Promise<P2pSmokeTestResponse>;

export interface CourierCommands {
  courierGenerateCode: CourierGenerateCodeCommand;
  courierSend: CourierSendCommand;
  courierReceive: CourierReceiveCommand;
  courierCancel: CourierCancelCommand;
  exportPot: ExportPotCommand;
  verifyPot: VerifyPotCommand;
  listTransfers: ListTransfersCommand;
  courierP2pSmokeTest: CourierP2pSmokeTestCommand;
  courierRelaySmokeTest: CourierRelaySmokeTestCommand;
  loadSettings: LoadSettingsCommand;
  updateSettings: UpdateSettingsCommand;
}
