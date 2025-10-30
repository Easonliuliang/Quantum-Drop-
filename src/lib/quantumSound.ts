type QuantumTone = "pair" | "tunnel" | "collapse";

const contextRef: { current?: AudioContext } = {};

const TONE_PRESETS: Record<QuantumTone, { frequency: number; gain: number; duration: number }> =
  {
    pair: { frequency: 220, gain: 0.12, duration: 0.18 },
    tunnel: { frequency: 420, gain: 0.1, duration: 0.22 },
    collapse: { frequency: 540, gain: 0.08, duration: 0.26 },
  };

const resolveContext = async () => {
  if (typeof window === "undefined") {
    return null;
  }
  const AudioCtor: typeof AudioContext | undefined =
    window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!AudioCtor) {
    return null;
  }
  if (!contextRef.current) {
    contextRef.current = new AudioCtor();
  }
  if (contextRef.current.state === "suspended") {
    try {
      await contextRef.current.resume();
    } catch {
      // ignore resume failures triggered outside user gestures
    }
  }
  return contextRef.current;
};

export const playQuantumPing = async (tone: QuantumTone) => {
  const ctx = await resolveContext();
  if (!ctx) {
    return;
  }
  const preset = TONE_PRESETS[tone];
  const now = ctx.currentTime;
  const oscillator = ctx.createOscillator();
  const gainNode = ctx.createGain();

  oscillator.type = "sine";
  oscillator.frequency.setValueAtTime(preset.frequency, now);
  oscillator.detune.setValueAtTime(tone === "tunnel" ? 18 : tone === "collapse" ? -26 : 0, now);

  gainNode.gain.setValueAtTime(preset.gain, now);
  gainNode.gain.exponentialRampToValueAtTime(0.0001, now + preset.duration);

  oscillator.connect(gainNode);
  gainNode.connect(ctx.destination);

  oscillator.start(now);
  oscillator.stop(now + preset.duration);
};
