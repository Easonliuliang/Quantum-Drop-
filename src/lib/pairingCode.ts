/**
 * 临时配对码系统
 *
 * 用于设备发现的短期连接码，类似 Zoom 会议号
 * 底层加密身份对用户透明
 */

// 配对码有效期（秒）
const CODE_EXPIRY_SECONDS = 180; // 3分钟

// 生成随机配对码（6位大写字母数字）
function generateCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 去掉容易混淆的 0OI1
  let code = '';
  const array = new Uint8Array(6);
  crypto.getRandomValues(array);
  for (let i = 0; i < 6; i++) {
    code += chars[array[i] % chars.length];
  }
  return code;
}

export interface PairingSession {
  code: string;
  createdAt: number;
  expiresAt: number;
}

let currentSession: PairingSession | null = null;
let onCodeChange: ((session: PairingSession) => void) | null = null;

// 获取或创建配对码
export function getPairingCode(): PairingSession {
  const now = Date.now();

  // 如果没有或已过期，生成新的
  if (!currentSession || now >= currentSession.expiresAt) {
    currentSession = {
      code: generateCode(),
      createdAt: now,
      expiresAt: now + CODE_EXPIRY_SECONDS * 1000,
    };
    onCodeChange?.(currentSession);
  }

  return currentSession;
}

// 刷新配对码（手动）
export function refreshPairingCode(): PairingSession {
  const now = Date.now();
  currentSession = {
    code: generateCode(),
    createdAt: now,
    expiresAt: now + CODE_EXPIRY_SECONDS * 1000,
  };
  onCodeChange?.(currentSession);
  return currentSession;
}

// 获取剩余时间（秒）
export function getRemainingSeconds(): number {
  if (!currentSession) return 0;
  return Math.max(0, Math.ceil((currentSession.expiresAt - Date.now()) / 1000));
}

// 监听配对码变化
export function onPairingCodeChange(callback: (session: PairingSession) => void) {
  onCodeChange = callback;
}

// 验证输入的配对码格式
export function isValidCodeFormat(code: string): boolean {
  return /^[A-Z0-9]{6}$/i.test(code);
}

// 格式化配对码显示（加空格）
export function formatCode(code: string): string {
  return code.slice(0, 3) + ' ' + code.slice(3);
}
