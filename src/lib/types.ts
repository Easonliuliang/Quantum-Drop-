export interface FileAttestation {
  name: string;
  size: number;
  cid: string;
  merkle_root: string;
  chunks: number;
  chunk_hashes_sample: string[];
}

export interface TransitionReceipt {
  version: number;
  transfer_id: string;
  session_id: string;
  sender_identity: string;
  receiver_identity: string;
  files: FileAttestation[];
  timestamp_start: string;
  timestamp_complete: string | null;
  route_type: string;
  sender_signature: string | null;
  receiver_signature: string | null;
}

export interface VerifyPotResponse {
  valid: boolean;
  reason?: string;
  receipt?: TransitionReceipt;
}
