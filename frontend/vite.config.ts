import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/events': 'http://127.0.0.1:8000',
      '/incidents': 'http://127.0.0.1:8000',
      '/investigations': 'http://127.0.0.1:8000',
      '/dashboard': 'http://127.0.0.1:8000',
      '/auth': 'http://127.0.0.1:8000',
      '/assistant': 'http://127.0.0.1:8000',
      '/threat-intel': 'http://127.0.0.1:8000',
      '/simulation': 'http://127.0.0.1:8000',
      '/audit': 'http://127.0.0.1:8000',
      '/responses': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
      '/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true
      }
    }
  }
})

