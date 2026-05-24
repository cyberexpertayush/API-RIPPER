import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    host: 'localhost',
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        ws: true,
        // Suppress ECONNRESET noise when backend restarts or WS connections drop
        configure: (proxy) => {
          proxy.on('error', (err) => {
            if (err.message.includes('ECONNRESET') || err.message.includes('ECONNREFUSED')) {
              // Silently ignore connection reset/refused — backend will reconnect
              return;
            }
            console.error('[vite] ws proxy error:', err.message);
          });
        },
      },
    },
  },
})
