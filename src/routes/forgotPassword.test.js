import { describe, test, expect, beforeAll, afterEach, afterAll, vi } from 'vitest'
import createApiServer from 'express-async-api'
import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import request from 'supertest'
import captcha from '../helpers/captcha.js'
import createMongooseMemoryServer from 'mongoose-memory'

import forgotPassword from './forgotPassword.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

const AccountTestModel = mongoose.model('AccountTest', new mongoose.Schema({
  name: { type: String },
  urlFriendlyName: { type: String, unique: true },
  logo: { type: String }
}, { timestamps: true }))

const UserTestModel = mongoose.model('UserTest', new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/ },
  password: { type: String },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  accountId: { type: mongoose.Schema.Types.ObjectId, ref: 'Account', required: true },
  profilePicture: { type: String }
}, { timestamps: true }))

const SystemAdminTestModel = mongoose.model('Test', new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/, unique: true },
  password: { type: String },
  profilePicture: { type: String }
}, { timestamps: true }))

describe('Accounts forgot-password test', () => {
  let app
  let secrets
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
    process.env.BLUEFOX_TEMPLATE_ID_ADMIN_VERIFY_EMAIL = '123123'
    process.env.BLUEFOX_TEMPLATE_ID_ADMIN_FORGOT_PASSWORD = '123123'
    process.env.BLUEFOX_TEMPLATE_ID_ADMIN_INVITATION = '123123'

    process.env.TEST_STATIC_SERVER_URL = 'http://localhost:10007/'
    process.env.CDN_BASE_URL = 'http://localhost:10007/'
    process.env.AWS_BUCKET_PATH = './tmp/'
    process.env.AWS_BUCKET_NAME = 'bluefox'
    process.env.AWS_FOLDER_NAME = 'mua-auth'
    process.env.AWS_REGION = '<your_aws_region>'
    process.env.AWS_ACCESS_KEY_ID = '<your_aws_access_key_id>'
    process.env.AWS_SECRET_ACCESS_KEY = '<your_aws_secret_access_key>'
    process.env.ALPHA_MODE = 'false'
    process.env.MAX_FILE_SIZE = '5242880'
    secrets = process.env.SECRETS.split(' ')
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
    forgotPassword({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel, SystemAdminModel: SystemAdminTestModel })
    app = app._expressServer
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
  })

  afterAll(async () => {
    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })

  test('success send forget password  /v1/accounts/:accountId/forgot-password/send', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const captchaData = captcha.generate(secrets)

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/send')
      .set('authorization', 'Bearer ' + token)
      .send({ email: user1.email, captchaText: captchaData.text, captchaProbe: captchaData.probe })
    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('error captcha send forget password  /v1/accounts/:accountId/forgot-password/send', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const captchaData = captcha.generate(secrets)

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/send')
      .set('authorization', 'Bearer ' + token)
      .send({ email: user1.email, captchaText: 'test', captchaProbe: captchaData.probe })
    expect(res.body.status).toBe(400)
    await fetchSpy.mockRestore()
  })

  test('error fetch', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ error: { name: 'error', message: 'error test' }, status: 400 })
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])
    const captchaData = captcha.generate(secrets)

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/send')
      .set('authorization', 'Bearer ' + token)
      .send({ email: user1.email, captchaText: captchaData.text, captchaProbe: captchaData.probe })
    expect(res.body.status).toBe(400)
    await fetchSpy.mockRestore()
  })
  test('send forget password error user not found  /v1/accounts/:accountId/forgot-password/send', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])
    const captchaData = captcha.generate(secrets)

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/send')
      .set('authorization', 'Bearer ' + token)
      .send({ email: 'user3@gmail.com', captchaText: captchaData.text, captchaProbe: captchaData.probe })
    expect(res.body.status).toBe(401)
  })

  test('send forget password for wrong account  /v1/accounts/:accountId/forgot-password/send', async () => {
    const id = new mongoose.Types.ObjectId()
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()
    const captchaData = captcha.generate(secrets)

    const res = await request(app)
      .post('/v1/accounts/' + id + '/forgot-password/send')
      .send({ email: user1.email, captchaText: captchaData.text, captchaProbe: captchaData.probe })
    expect(res.body.status).toBe(401)
  })

  test('success reset forget password  /v1/accounts/:accountId/forgot-password/reset', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'forgot-password', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userNewPassword' })
    expect(res.body.status).toBe(200)
  })

  test(' reset forget password validation error  /v1/accounts/:accountId/forgot-password/reset', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'forgot-password', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userWrongNewPassword' })
    expect(res.body.status).toBe(400)
  })

  test('reset forget password unAuthorized header  /v1/accounts/:accountId/forgot-password/reset', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'userNewPassword', passwordAgain: 'userNewPassword' })
    expect(res.body.status).toBe(403)
  })

  test('reset forget password user email does not exist  /v1/accounts/:accountId/forgot-password/reset', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'forgot-password', user: { _id: user1._id, email: 'user4@gmail.com' } }, secrets[0])
    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'userNewPassword', passwordAgain: 'userNewPassword' })
    expect(res.body.status).toBe(401)
  })
})

describe('System admins forgot-password test', () => {
  let app
  let secrets
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
    process.env.BLUEFOX_TEMPLATE_ID_ADMIN_VERIFY_EMAIL = '123123'
    process.env.BLUEFOX_TEMPLATE_ID_ADMIN_FORGOT_PASSWORD = '123123'
    process.env.BLUEFOX_TEMPLATE_ID_ADMIN_INVITATION = '123123'
    process.env.TEST_STATIC_SERVER_URL = 'http://localhost:10007/'
    process.env.CDN_BASE_URL = 'http://localhost:10007/'
    process.env.AWS_BUCKET_PATH = './tmp/'
    process.env.AWS_BUCKET_NAME = 'bluefox'
    process.env.AWS_FOLDER_NAME = 'mua-auth'
    process.env.AWS_REGION = '<your_aws_region>'
    process.env.AWS_ACCESS_KEY_ID = '<your_aws_access_key_id>'
    process.env.AWS_SECRET_ACCESS_KEY = '<your_aws_secret_access_key>'
    process.env.ALPHA_MODE = 'false'
    process.env.MAX_FILE_SIZE = '5242880'
    secrets = process.env.SECRETS.split(' ')
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
    forgotPassword({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel, SystemAdminModel: SystemAdminTestModel })
    app = app._expressServer
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
  })

  afterAll(async () => {
    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })

  test('success send forget password  /v1/system-admins/forgot-password/send', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()
    const captchaData = captcha.generate(secrets)

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/send')
      .send({ email: user2.email, captchaText: captchaData.text, captchaProbe: captchaData.probe })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
  })

  test('error captcha send forget password  /v1/system-admins/forgot-password/send', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()
    const captchaData = captcha.generate(secrets)

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/send')
      .send({ email: user2.email, captchaText: 'test', captchaProbe: captchaData.probe })

    expect(res.body.status).toBe(400)
  })

  test('send forget password error user not found  /v1/system-admins/forgot-password/send', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()
    const captchaData = captcha.generate(secrets)

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/send')
      .send({ email: 'user2@gmail.com', captchaText: captchaData.text, captchaProbe: captchaData.probe })
    expect(res.body.status).toBe(401)
  })

  test('success reset forget password  /v1/system-admins/forgot-password/reset', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'forgot-password', user: { _id: user2._id, email: user2.email } }, secrets[0])
    const captchaData = captcha.generate(secrets)

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userNewPassword', captchaText: captchaData.text, captchaProbe: captchaData.probe })
    expect(res.body.status).toBe(200)
  })

  test(' reset forget password validation error  /v1/system-admins/forgot-password/reset', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'forgot-password', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userWrongNewPassword' })
    expect(res.body.status).toBe(400)
  })

  test('reset forget password unAuthorized header  /v1/system-admins/forgot-password/reset', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value', user: { _id: user2._id, email: user2.email } }, secrets[0])
    const captchaData = captcha.generate(secrets)

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userNewPassword', captchaText: captchaData.text, captchaProbe: captchaData.probe })
    expect(res.body.status).toBe(403)
  })

  test('reset forget password user email does not exist  /v1/system-admins/forgot-password/reset', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()
    const token = jwt.sign({ type: 'forgot-password', user: { _id: user1._id, email: 'user4@gmail.com' } }, secrets[0])
    const captchaData = captcha.generate(secrets)

    const res = await request(app)
      .post('/v1/system-admins/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userNewPassword', captchaText: captchaData.text, captchaProbe: captchaData.probe })
    expect(res.body.status).toBe(404)
  })
})
