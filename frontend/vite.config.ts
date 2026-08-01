/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],

  /**
   * Unit tests, run by `npm test` and by the Maven build alongside the typecheck.
   *
   * jsdom rather than a browser: these cover pure functions and the small amount of
   * rendering logic that decides *what a cell claims* — three different empty states that
   * must not read as each other. Anything to do with layout, measurement or the rendering
   * loop stays a browser check, since AGENTS.md records that requestAnimationFrame and
   * ResizeObserver do not fire in a hidden pane and would not fire here either.
   */
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
    // Testing Library registers its own afterEach cleanup only when the globals are there.
    // Without it every render stacks into one document.body and a query for "is this absent"
    // finds the previous test's node — which produced two failures that looked like component
    // bugs and were not.
    globals: true,
  },

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
