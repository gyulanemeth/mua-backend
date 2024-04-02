import { describe, test, expect, beforeAll } from 'vitest'
import request from 'supertest'
import jwt from 'jsonwebtoken'

import createServer from './index.js'

const secrets = process.env.SECRETS.split(' ')

describe('config testing  /v1/config', () => {
  let app
  beforeAll(async () => {
    app = createServer()
    app = app._expressServer
  })

  test('success get config ', async () => {
    const token = jwt.sign({ type: 'admin' }, secrets[0])
    const res = await request(app)
      .get('/v1/config').set('authorization', 'Bearer ' + token).send()
    expect(res.body.status).toBe(200)
  })

  test('get config unAuthorized header error   ', async () => {
    const token = jwt.sign({ type: 'value' }, secrets[0])
    const res = await request(app)
      .get('/v1/config').set('authorization', 'Bearer ' + token).send()
    expect(res.body.status).toBe(403)
  })
})
