import { describe, test, expect, beforeAll, afterEach, afterAll } from 'vitest'
import createApiServer from 'express-async-api'
import mongoose from 'mongoose'
import request from 'supertest'
import turnstile from './turnstile.js'

import createMongooseMemoryServer from 'mongoose-memory'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

describe('turnstile route test', () => {
  let app
  let originalEnv

  beforeAll(async () => {
    await mongooseMemoryServer.start()
    await mongooseMemoryServer.connect('test-db')
    process.env.TURNSTILE_SITE_KEY = 'test-site-key'
    originalEnv = process.env

    app = createApiServer((e) => ({
      status: e.status,
      error: { name: e.name, message: e.message }
    }), () => {})
    turnstile({ apiServer: app })
    app = app._expressServer
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
    process.env = originalEnv
  })

  afterAll(async () => {
    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })

  test('success get turnstile config', async () => {
    const res = await request(app)
      .get('/v1/turnstile')
      .send()

    expect(res.body.status).toBe(200)
    expect(res.body.result.siteKey).toBe('test-site-key')
  })
})
