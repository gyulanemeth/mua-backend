import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    setupFiles: ['dotenv/config'],
    testTimeout: 10000,
    coverage: {
      reporter: ['text', 'json', 'html'],
      lines: 100,
      functions: 100,
      statements: 100,
      branches: 100
    }
  }
})
