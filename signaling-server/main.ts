/**
 * Quantum Drop Signaling Server for Deno Deploy
 *
 * Handles WebRTC signaling (SDP/ICE exchange) between peers.
 * Ported from src-tauri/src/signaling/server.rs
 */

// Types matching the client-side signaling protocol

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

interface PeerHandle {
  socket: WebSocket;
  deviceId: string;
  deviceName?: string;
  publicKey?: string;
}

interface SessionEntry {
  state: SessionDesc;
  peers: Map<string, PeerHandle>;
}

// Session registry - stores all active sessions
class SessionRegistry {
  private sessions = new Map<string, SessionEntry>();

  register(
    sessionId: string,
    peerId: string,
    peer: PeerHandle
  ): SessionDesc | null {
    let entry = this.sessions.get(sessionId);

    if (!entry) {
      entry = {
        state: {
          sessionId,
          candidates: [],
        },
        peers: new Map(),
      };
      this.sessions.set(sessionId, entry);
    }

    entry.peers.set(peerId, peer);

    // Return existing state if there's any SDP or candidates
    if (entry.state.offer || entry.state.answer || entry.state.candidates.length > 0) {
      return { ...entry.state };
    }
    return null;
  }

  mergeAndBroadcast(
    sessionId: string,
    fromPeerId: string,
    update: SessionDesc
  ): void {
    const entry = this.sessions.get(sessionId);
    if (!entry) return;

    // Merge the update into session state
    if (update.offer) {
      entry.state.offer = update.offer;
    }
    if (update.answer) {
      entry.state.answer = update.answer;
    }
    if (update.candidates && update.candidates.length > 0) {
      entry.state.candidates.push(...update.candidates);
    }

    // Copy signer info to broadcast
    const snapshot: SessionDesc = {
      ...entry.state,
      signerDeviceId: update.signerDeviceId,
      signerDeviceName: update.signerDeviceName,
      signerPublicKey: update.signerPublicKey,
      signature: update.signature,
    };

    // Broadcast to all other peers in the session
    for (const [peerId, peer] of entry.peers) {
      if (peerId !== fromPeerId) {
        try {
          peer.socket.send(JSON.stringify(snapshot));
        } catch (err) {
          console.error(`Failed to send to peer ${peerId}:`, err);
        }
      }
    }
  }

  remove(sessionId: string, peerId: string): void {
    const entry = this.sessions.get(sessionId);
    if (!entry) return;

    entry.peers.delete(peerId);

    // Clean up empty sessions
    if (entry.peers.size === 0) {
      this.sessions.delete(sessionId);
    }
  }

  getStats(): { sessions: number; peers: number } {
    let peers = 0;
    for (const entry of this.sessions.values()) {
      peers += entry.peers.size;
    }
    return { sessions: this.sessions.size, peers };
  }
}

const registry = new SessionRegistry();

function generatePeerId(): string {
  return crypto.randomUUID();
}

function handleWebSocket(
  socket: WebSocket,
  sessionId: string,
  deviceId: string,
  deviceName?: string,
  publicKey?: string
): void {
  const peerId = generatePeerId();
  const peer: PeerHandle = {
    socket,
    deviceId: deviceId || `peer-${peerId}`,
    deviceName,
    publicKey,
  };

  socket.onopen = () => {
    console.log(`[${sessionId}] Peer ${peerId} connected`);

    // Register peer and send existing session state if any
    const existingState = registry.register(sessionId, peerId, peer);
    if (existingState) {
      try {
        socket.send(JSON.stringify(existingState));
      } catch (err) {
        console.error(`Failed to send initial state to ${peerId}:`, err);
      }
    }
  };

  socket.onmessage = (event) => {
    try {
      const data = typeof event.data === "string" ? event.data : "";
      const update = JSON.parse(data) as SessionDesc;

      // Ensure session ID matches
      update.sessionId = sessionId;

      // Attach signer info if not present
      if (!update.signerDeviceId) {
        update.signerDeviceId = peer.deviceId;
      }
      if (!update.signerDeviceName && peer.deviceName) {
        update.signerDeviceName = peer.deviceName;
      }
      if (!update.signerPublicKey && peer.publicKey) {
        update.signerPublicKey = peer.publicKey;
      }

      registry.mergeAndBroadcast(sessionId, peerId, update);
    } catch (err) {
      console.error(`[${sessionId}] Invalid message from ${peerId}:`, err);
      try {
        socket.send(JSON.stringify({ error: "INVALID_MESSAGE", reason: String(err) }));
      } catch {
        // Ignore send errors
      }
    }
  };

  socket.onclose = () => {
    console.log(`[${sessionId}] Peer ${peerId} disconnected`);
    registry.remove(sessionId, peerId);
  };

  socket.onerror = (err) => {
    console.error(`[${sessionId}] WebSocket error for ${peerId}:`, err);
    registry.remove(sessionId, peerId);
  };
}

function handleRequest(request: Request): Response {
  const url = new URL(request.url);

  // Health check endpoint
  if (url.pathname === "/health" || url.pathname === "/") {
    const stats = registry.getStats();
    return new Response(
      JSON.stringify({
        status: "ok",
        service: "quantumdrop-signaling",
        version: "1.0.0",
        stats,
      }),
      {
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  // WebSocket upgrade for /ws
  if (url.pathname === "/ws") {
    const upgrade = request.headers.get("upgrade") || "";
    if (upgrade.toLowerCase() !== "websocket") {
      return new Response("Expected WebSocket upgrade", { status: 426 });
    }

    const sessionId = url.searchParams.get("sessionId");
    if (!sessionId) {
      return new Response("Missing sessionId parameter", { status: 400 });
    }

    const deviceId = url.searchParams.get("deviceId") || "";
    const deviceName = url.searchParams.get("deviceName") || undefined;
    const publicKey = url.searchParams.get("publicKey") || undefined;

    const { socket, response } = Deno.upgradeWebSocket(request);
    handleWebSocket(socket, sessionId, deviceId, deviceName, publicKey);
    return response;
  }

  return new Response("Not Found", { status: 404 });
}

// Deno Deploy entry point
Deno.serve({ port: 8000 }, handleRequest);

console.log("Quantum Drop Signaling Server running on http://localhost:8000");
