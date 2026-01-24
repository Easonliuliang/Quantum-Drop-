/**
 * Quantum Drop Signaling Server for Cloudflare Workers
 *
 * 使用 Durable Objects 维护 WebSocket 连接状态
 */

export interface Env {
  SIGNALING_ROOM: DurableObjectNamespace;
}

// 主 Worker 入口
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // CORS 头
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    // 处理 CORS 预检
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // 健康检查
    if (url.pathname === "/" || url.pathname === "/health") {
      return new Response(
        JSON.stringify({
          status: "ok",
          service: "quantumdrop-signaling",
          version: "1.0.0-cf",
          runtime: "cloudflare-workers",
        }),
        {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // WebSocket 连接
    if (url.pathname === "/ws") {
      const sessionId = url.searchParams.get("sessionId");
      if (!sessionId) {
        return new Response("Missing sessionId parameter", {
          status: 400,
          headers: corsHeaders,
        });
      }

      // 获取或创建对应 session 的 Durable Object
      const id = env.SIGNALING_ROOM.idFromName(sessionId);
      const room = env.SIGNALING_ROOM.get(id);

      // 转发请求到 Durable Object
      return room.fetch(request);
    }

    return new Response("Not Found", { status: 404, headers: corsHeaders });
  },
};

// ============ Durable Object: SignalingRoom ============

interface SessionDescription {
  type: "offer" | "answer" | "pranswer";
  sdp: string;
}

interface IceCandidate {
  candidate: string;
  sdpMLineIndex?: number | null;
  sdpMid?: string | null;
}

interface SessionDesc {
  sessionId: string;
  offer?: SessionDescription | null;
  answer?: SessionDescription | null;
  candidates: IceCandidate[];
  signerDeviceId?: string | null;
  signerDeviceName?: string | null;
  signerPublicKey?: string | null;
  signature?: string | null;
}

interface PeerInfo {
  deviceId: string;
  deviceName?: string;
  publicKey?: string;
}

export class SignalingRoom {
  private state: DurableObjectState;
  private sessions: Map<string, WebSocket> = new Map();
  private peerInfo: Map<string, PeerInfo> = new Map();
  private sessionState: SessionDesc;

  constructor(state: DurableObjectState) {
    this.state = state;
    this.sessionState = {
      sessionId: "",
      candidates: [],
    };
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const sessionId = url.searchParams.get("sessionId") || "unknown";
    const deviceId = url.searchParams.get("deviceId") || crypto.randomUUID();
    const deviceName = url.searchParams.get("deviceName") || undefined;
    const publicKey = url.searchParams.get("publicKey") || undefined;

    // 初始化 session 状态
    if (!this.sessionState.sessionId) {
      this.sessionState.sessionId = sessionId;
    }

    // 创建 WebSocket 对
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    // 生成 peer ID
    const peerId = crypto.randomUUID();

    // 保存 peer 信息
    this.peerInfo.set(peerId, { deviceId, deviceName, publicKey });

    // 接受 WebSocket 连接
    this.state.acceptWebSocket(server, [peerId]);

    // 保存到 sessions map
    this.sessions.set(peerId, server);

    console.log(`[${sessionId}] Peer ${peerId} (${deviceId}) connected. Total: ${this.sessions.size}`);

    // 如果有现有状态，发送给新连接的 peer
    if (this.sessionState.offer || this.sessionState.answer || this.sessionState.candidates.length > 0) {
      server.send(JSON.stringify(this.sessionState));
    }

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer) {
    const peerId = this.state.getTags(ws)[0];
    const peerInfo = this.peerInfo.get(peerId);

    try {
      const data = typeof message === "string" ? message : new TextDecoder().decode(message);
      const update = JSON.parse(data) as SessionDesc;

      // 确保 sessionId 匹配
      update.sessionId = this.sessionState.sessionId;

      // 合并状态
      if (update.offer) {
        this.sessionState.offer = update.offer;
      }
      if (update.answer) {
        this.sessionState.answer = update.answer;
      }
      if (update.candidates && update.candidates.length > 0) {
        this.sessionState.candidates.push(...update.candidates);
      }

      // 构建广播消息
      const broadcast: SessionDesc = {
        ...this.sessionState,
        signerDeviceId: update.signerDeviceId || peerInfo?.deviceId,
        signerDeviceName: update.signerDeviceName || peerInfo?.deviceName,
        signerPublicKey: update.signerPublicKey || peerInfo?.publicKey,
        signature: update.signature,
      };

      const broadcastStr = JSON.stringify(broadcast);

      // 广播给其他所有 peer
      for (const [otherId, otherWs] of this.sessions) {
        if (otherId !== peerId) {
          try {
            otherWs.send(broadcastStr);
          } catch (err) {
            console.error(`Failed to send to peer ${otherId}:`, err);
          }
        }
      }
    } catch (err) {
      console.error(`Invalid message from ${peerId}:`, err);
      try {
        ws.send(JSON.stringify({ error: "INVALID_MESSAGE", reason: String(err) }));
      } catch {
        // ignore
      }
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string) {
    const peerId = this.state.getTags(ws)[0];
    console.log(`[${this.sessionState.sessionId}] Peer ${peerId} disconnected: ${code} ${reason}`);

    this.sessions.delete(peerId);
    this.peerInfo.delete(peerId);

    // 如果没有连接了，清空状态
    if (this.sessions.size === 0) {
      this.sessionState = {
        sessionId: this.sessionState.sessionId,
        candidates: [],
      };
    }
  }

  async webSocketError(ws: WebSocket, error: unknown) {
    const peerId = this.state.getTags(ws)[0];
    console.error(`[${this.sessionState.sessionId}] WebSocket error for ${peerId}:`, error);

    this.sessions.delete(peerId);
    this.peerInfo.delete(peerId);
  }
}
