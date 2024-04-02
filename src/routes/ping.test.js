import request from 'supertest'
import { expect } from 'vitest'
import mongoose from 'mongoose'
import createServer from './index.js'

import createMongooseMemoryServer from 'mongoose-memory'
const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

describe('ping routes', () => {
  let app
  beforeAll(async () => {
    await mongooseMemoryServer.start()
    await mongooseMemoryServer.connect('test-db')

    app = createServer()
    app = app._expressServer
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
  })

  afterAll(async () => {
    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })

  test('/v1/ping', async () => {
    const res = await request(app).get('/v1/ping')
      .send()
    expect(res.status).toBe(200)
    expect(res.body.status).toBe(200)
    expect(res.body.result).toBe('pong')
  })

  test('/v1/ping/mongo - success', async () => {
    const res = await request(app).get('/v1/ping/mongo')
      .send()

    expect(res.status).toBe(200)
    expect(res.body.status).toBe(200)
    expect(res.body.result).toBe('pong')
  })

  test('/v1/ping/mongo - error', async () => {
    await mongooseMemoryServer.disconnect()
    const res = await request(app).get('/v1/ping/mongo')
      .send()

    expect(res.status).toBe(500)
    expect(res.body.status).toBe(500)
    expect(res.body.error).toBe('MongoDB connection is not ready')
    await mongooseMemoryServer.connect('test-db')
  })
})

