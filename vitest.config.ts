import { fileURLToPath } from "node:url";
import path from "node:path";
import { mergeConfig, defineConfig } from "vitest/config";
import viteConfig from "./vite.config";

const currentDir = path.dirname(fileURLToPath(import.meta.url));

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      environment: "jsdom",
      globals: true,
      setupFiles: ["./vitest.setup.ts"]
    },
    resolve: {
      alias: {
        "@tauri-apps/plugin-dialog": path.resolve(
          currentDir,
          "src/test/mocks/tauri-dialog.ts"
        )
      }
    }
  })
);
