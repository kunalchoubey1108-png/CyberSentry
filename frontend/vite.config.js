import { fileURLToPath, URL } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // The Evaluation view imports eval/results/metrics.json from the
    // repo root, which sits outside the Vite root (frontend/).
    fs: {
      allow: [fileURLToPath(new URL('..', import.meta.url))],
    },
  },
})