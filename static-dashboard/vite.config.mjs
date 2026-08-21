import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const root = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig(({ command }) => {
  const base = process.env.PAGES_BASE_PATH || "/";
  if (!/^\/(?:[A-Za-z0-9._-]+\/)?$/.test(base)) throw new Error("PAGES_BASE_PATH must be / or a single repository path ending in /");
  if (command === "build") validateApiOrigin(process.env.VITE_API_BASE_URL);
  return {
    root,
    base,
    plugins: [react()],
    build: {
      outDir: fileURLToPath(new URL("../dist-pages", import.meta.url)),
      emptyOutDir: true,
    },
  };
});

function validateApiOrigin(value) {
  if (!value) throw new Error("VITE_API_BASE_URL is required for the static production build");
  const url = new URL(value);
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if ((!local && url.protocol !== "https:") || (local && !["http:", "https:"].includes(url.protocol)) || url.origin !== value.replace(/\/$/, "") || url.username || url.password) {
    throw new Error("VITE_API_BASE_URL must be a trusted HTTPS origin without a path, query, credentials, or fragment");
  }
}
