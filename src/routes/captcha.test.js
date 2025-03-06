import { describe, test, expect, beforeAll, afterEach, afterAll } from 'vitest'
import createApiServer from 'express-async-api'
import mongoose from 'mongoose'
import request from 'supertest'
import captcha from './captcha.js'

import createMongooseMemoryServer from 'mongoose-memory'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

describe('captcha test', () => {
  let app
  let originalEnv
  beforeAll(async () => {
    await mongooseMemoryServer.start()
    await mongooseMemoryServer.connect('test-db')
    process.env.NODE_ENV = 'development'
    process.env.SECRETS = 'verylongsecret1 verylongsecret2'
    process.env.APP_URL = 'http://app.emailfox.link/'
    process.env.BLUEFOX_TRANSACTIONAL_EMAIL_API_URL = 'http://app.emailfox.link/v1/send-transactional'
    process.env.BLUEFOX_API_KEY = '<your_bluefox_api_key>'
    process.env.BLUEFOX_TEMPLATE_ID_ACCOUNT_FINALIZE_REGISTRATION = '123123'
    process.env.BLUEFOX_TEMPLATE_ID_ACCOUNT_FORGOT_PASSWORD = '123123'
    process.env.BLUEFOX_TEMPLATE_ID_ACCOUNT_INVITATION = '123123'
    process.env.BLUEFOX_TEMPLATE_ID_ACCOUNT_LOGIN_SELECT = '123123'
    process.env.BLUEFOX_TEMPLATE_ID_ACCOUNT_VERIFY_EMAIL = '123123'

    process.env.TEST_STATIC_SERVER_URL = 'http://localhost:10007/'
    process.env.CDN_BASE_URL = 'http://localhost:10007/'
    process.env.AWS_BUCKET_PATH = './tmp/'
    process.env.AWS_BUCKET_NAME = 'bluefox'
    process.env.AWS_FOLDER_NAME = 'mua-accounts'
    process.env.AWS_REGION = '<your_aws_region>'
    process.env.AWS_ACCESS_KEY_ID = '<your_aws_access_key_id>'
    process.env.AWS_SECRET_ACCESS_KEY = '<your_aws_secret_access_key>'
    process.env.ALPHA_MODE = 'false'
    process.env.MAX_FILE_SIZE = '5242880'
    originalEnv = process.env
    app = createApiServer((e) => {
      if (e.code === 'LIMIT_FILE_SIZE') {
        return {
          status: 413,
          error: {
            name: 'PAYLOAD_TOO_LARGE',
            message: 'File size limit exceeded. Maximum file size allowed is ' + (Number(20000) / (1024 * 1024)).toFixed(2) + 'mb'
          }
        }
      }
      return {
        status: e.status,
        error: {
          name: e.name,
          message: e.message
        }
      }
    }, () => {})
    captcha({ apiServer: app })
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

  test('success generate svg', async () => {
    const res = await request(app)
      .get('/v1/captcha')
      .send()

    expect(res.body.status).toBe(200)
  })
})
