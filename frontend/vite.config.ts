import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],

  build: {
    // Written straight onto the Maven output path so the jar packaging step picks
    // the built UI up as classpath resources. Spring Boot serves META-INF/resources
    // automatically, which is what makes the single-jar deployment work.
    outDir: 'target/classes/META-INF/resources',
    emptyOutDir: true,
  },

  server: {
    port: 5173,
    // Development only: the UI runs on Vite for hot reload while API calls are
    // forwarded to the Spring Boot process. In production both are the same origin.
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
});
