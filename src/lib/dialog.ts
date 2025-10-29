import { open } from "@tauri-apps/plugin-dialog";

export const pickFiles = async (): Promise<string[]> => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  const result = (await open({ multiple: true })) as unknown;
  if (typeof result === "string") {
    return [result];
  }
  if (Array.isArray(result)) {
    return result.filter((item): item is string => typeof item === "string");
  }
  return [];
};

export const pickDirectory = async (): Promise<string | null> => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  const result = (await open({ directory: true, multiple: false })) as unknown;
  return typeof result === "string" ? result : null;
};

export const pickPotFile = async (
  defaultPath?: string
): Promise<string | null> => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  const result = (await open({
    multiple: false,
    defaultPath,
    filters: [{ name: "Proof of Transition", extensions: ["pot.json"] }],
  })) as unknown;
  return typeof result === "string" ? result : null;
};
