import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The console only talks to the local SOC API, through this proxy.
// No external origins, CDNs or hosted assets are used.
// SOC_API_PORT must match the backend's (default 8000; Splunk Web also uses
// 8000, so on a machine running Splunk start both with e.g. SOC_API_PORT=8001).
const apiPort = process.env.SOC_API_PORT ?? "8000";
if (!/^\d{4,5}$/.test(apiPort)) throw new Error(`Invalid SOC_API_PORT: ${apiPort}`);

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": { target: `http://127.0.0.1:${apiPort}`, changeOrigin: false },
    },
  },
});
