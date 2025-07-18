import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node", // Required for miniflare v4
    globals: true,
    setupFiles: ["./tests/setup.ts"],
  },
  // resolve: {
  //   alias: {
  //     "@": "./src",
  //   },
  // },
});
