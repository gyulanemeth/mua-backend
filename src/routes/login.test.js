import { describe, test, expect, beforeAll, afterEach, beforeEach, afterAll, vi } from 'vitest'
import createApiServer from 'express-async-api'
import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import request from 'supertest'
import passport from 'passport'

import createMongooseMemoryServer from 'mongoose-memory'

import login from './login.js'

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
  profilePicture: { type: String },
  googleProfileId: { type: String },
  microsoftProfileId: { type: String },
  githubProfileId: { type: String },
  verified: { type: Boolean, default: false }
}, { timestamps: true }))

const SystemAdminTestModel = mongoose.model('SystemAdminTest', new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/, unique: true },
  password: { type: String },
  profilePicture: { type: String }
}, { timestamps: true }))

describe('Accounts login test ', () => {
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
    process.env.AWS_FOLDER_NAME = 'mua-accounts'
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
    login({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel, SystemAdminModel: SystemAdminTestModel })
    app = app._expressServer
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
  })

  afterAll(async () => {
    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })

  test('login with valid password ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id, verified: true })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id, verified: true })
    await user2.save()

    const token = jwt.sign({ type: 'login', user: { email: user1.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/login')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'user1Password' })

    expect(res.body.status).toBe(200)
  })

  test('unverified user login with valid password ', async () => {
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
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id, verified: true })
    await user2.save()

    const token = jwt.sign({ type: 'login', user: { email: user1.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/login')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'user1Password' })

    expect(res.body.status).toBe(405)
    await fetchSpy.mockRestore()
  })

  test('unverified user resend email error ', async () => {
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
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id, verified: true })
    await user2.save()

    const token = jwt.sign({ type: 'login', user: { email: user1.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/login')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'user1Password' })

    expect(res.body.status).toBe(400)
    await fetchSpy.mockRestore()
  })

  test('success login with urlFriendlyName  ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id, verified: true })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id, verified: true })
    await user2.save()

    const token = jwt.sign({ type: 'login', user: { email: user1.email }, account: { urlFriendlyName: 'urlFriendlyName1' } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1.urlFriendlyName + '/login/url-friendly-name')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'user1Password', email: user1.email })

    expect(res.body.status).toBe(200)
  })

  test('unverified user login with urlFriendlyName  ', async () => {
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
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id, verified: true })
    await user2.save()

    const token = jwt.sign({ type: 'login', user: { email: user1.email }, account: { urlFriendlyName: 'urlFriendlyName1' } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1.urlFriendlyName + '/login/url-friendly-name')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'user1Password', email: user1.email })

    expect(res.body.status).toBe(405)
    await fetchSpy.mockRestore()
  })

  test('error login with urlFriendlyName unexist urlFriendlyName  ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'login', user: { email: user1.email }, account: { urlFriendlyName: 'urlFriendlyName1' } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1.urlFriendlyName + '/login/url-friendly-name')
      .set('authorization', 'Bearer ' + token)
      .send({})

    expect(res.body.status).toBe(401)
  })

  test('login with urlFriendlyName wrong password ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'login', user: { email: user1.email }, account: { urlFriendlyName: 'urlFriendlyName1' } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1.urlFriendlyName + '/login/url-friendly-name')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'user4Password', email: user1.email })

    expect(res.body.status).toBe(401)
  })

  test('login with Wrong password', async () => {
    const account1 = new AccountTestModel({ name: 'account_example', urlFriendlyName: 'urlFriendlyName_example' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'login', user: { email: user1.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/login')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'user2Password' })

    expect(res.statusCode).toBe(401)
  })

  test('login with Wrong header', async () => {
    const account1 = new AccountTestModel({ name: 'account_example', urlFriendlyName: 'urlFriendlyName_example' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', user: { email: user1.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/login')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'user1Password' })

    expect(res.statusCode).toBe(403)
  })

  test('login without header account', async () => {
    const account1 = new AccountTestModel({ name: 'account_example', urlFriendlyName: 'urlFriendlyName_example' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/login')
      .send({ password: 'user1Password' })

    expect(res.body.status).toBe(401)
  })

  test('login with unexist account', async () => {
    const account1 = new AccountTestModel({ name: 'account_example', urlFriendlyName: 'urlFriendlyName_example' })
    await account1.save()

    const account2 = new AccountTestModel({ name: 'account_example', urlFriendlyName: 'urlFriendlyName_example' })

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'login;', user: { email: user1.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account2._id + '/login')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'user1Password' })

    expect(res.body.status).toBe(403)
  })

  test('login get accounts with valid email ', async () => {
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

    const res = await request(app)
      .post('/v1/accounts/login')
      .send({ email: user1.email })

    expect(res.body.status).toBe(201)
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

    const res = await request(app)
      .post('/v1/accounts/login')
      .send({ email: user1.email })

    expect(res.body.status).toBe(400)
    await fetchSpy.mockRestore()
  })

  test('login get accounts with unvalid email ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const res = await request(app)
      .post('/v1/accounts/login')
      .send({ email: 'wrongTest@gmail.com' })

    expect(res.body.status).toBe(401)
  })
})

describe('System admin login test ', () => {
  let app
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
    process.env.AWS_FOLDER_NAME = 'mua-accounts'
    process.env.AWS_REGION = '<your_aws_region>'
    process.env.AWS_ACCESS_KEY_ID = '<your_aws_access_key_id>'
    process.env.AWS_SECRET_ACCESS_KEY = '<your_aws_secret_access_key>'
    process.env.ALPHA_MODE = 'false'
    process.env.MAX_FILE_SIZE = '5242880'
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
    login({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel, SystemAdminModel: SystemAdminTestModel })
    app = app._expressServer
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
  })

  afterAll(async () => {
    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })

  test('login with email and password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const res = await request(app)
      .post('/v1/system-admins/login/')
      .send({ email: user1.email, password: 'user1Password' })
    expect(res.body.status).toBe(200)
  })

  test('login with wrong email', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const res = await request(app)
      .post('/v1/system-admins/login/')
      .send({ email: 'user3@gmail.com', password: 'user1Password' })

    expect(res.statusCode).toBe(401)
  })

  test('login with wrong password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const res = await request(app)
      .post('/v1/system-admins/login/')
      .send({ email: user1.email, password: 'user3Password' })

    expect(res.statusCode).toBe(401)
  })
})

describe('System admin login test ', () => {
  let app
  let req, res
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
    process.env.AWS_FOLDER_NAME = 'mua-accounts'
    process.env.AWS_REGION = '<your_aws_region>'
    process.env.AWS_ACCESS_KEY_ID = '<your_aws_access_key_id>'
    process.env.AWS_SECRET_ACCESS_KEY = '<your_aws_secret_access_key>'
    process.env.ALPHA_MODE = 'false'
    process.env.MAX_FILE_SIZE = '5242880'
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
    login({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel, SystemAdminModel: SystemAdminTestModel })
    app = app._expressServer
  })

  beforeEach(() => {
    // Mock the req object
    req = {
      params: {
        id: 'test-account-id',
        provider: 'google'
      }
      // Mock the body, headers, or query if needed
    }

    // Mock the res object
    res = {
      redirectUrl: '',
      statusCode: 200,
      setHeader: vi.fn((header, value) => {
        if (header === 'Location') {
          res.redirectUrl = value // Capture the redirect URL
        }
      }),
      end: vi.fn()
    }
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
    vi.clearAllMocks()
  })

  afterAll(async () => {
    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })

  test('login with provider', async () => {
    process.env.GOOGLE_CLIENT_ID = 'googleClientId'
    process.env.GOOGLE_CLIENT_SECRET = 'googleSecret'
    process.env.MICROSOFT_CLIENT_ID = 'microsoftClientId'
    process.env.MICROSOFT_CLIENT_SECRET = 'microsoftSecret'
    process.env.GITHUB_CLIENT_ID = 'githubClientId'
    process.env.GITHUB_CLIENT_SECRET = 'githubSecret'

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options) => {
      return (req, res, next) => {
        res.redirect(`https://test/provider/${provider}/callback?state=${options.state}`)
        res.setHeader('Location', `https://test/provider/${provider}/callback?state=${options.state}`)
        res.end()
      }
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const response = await request(app)
      .post(`/v1/accounts/${account1._id}/login/provider/google`, req)
      .send()

    expect(mockAuthenticate).toHaveBeenCalledWith('google', expect.anything())

    expect(response.body.result.redirectUrl).toContain('https://test/provider/google/callback')
    mockAuthenticate.mockRestore()
  })

  test('login with provider', async () => {
    process.env.GOOGLE_CLIENT_ID = 'googleClientId'
    process.env.GOOGLE_CLIENT_SECRET = 'googleSecret'
    process.env.MICROSOFT_CLIENT_ID = 'microsoftClientId'
    process.env.MICROSOFT_CLIENT_SECRET = 'microsoftSecret'
    process.env.GITHUB_CLIENT_ID = 'githubClientId'
    process.env.GITHUB_CLIENT_SECRET = 'githubSecret'

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options) => {
      return (req, res, next) => {
        res.redirect(`https://test/provider/google/callback?state=${options.state}`)
        res.setHeader('Location', `https://test/provider/google/callback?state=${options.state}`)
        res.end()
      }
    })

    const response = await request(app)
      .post('/v1/system-admins/login/provider', req)
      .send()

    expect(mockAuthenticate).toHaveBeenCalledWith('google', expect.anything())

    expect(response.body.result.redirectUrl).toContain('https://test/provider/google/callback')
    mockAuthenticate.mockRestore()
  })

  test('admin link with wrong provider', async () => {
    delete process.env.GOOGLE_CLIENT_ID
    delete process.env.GOOGLE_CLIENT_SECRET

    const response = await request(app)
      .post('/v1/system-admins/test123/link', req)
      .send()

    expect(response.body.error.message).toBe('Unsupported provider')
  })

  test('login with wrong provider', async () => {
    process.env.GOOGLE_CLIENT_ID = 'googleClientId'
    process.env.GOOGLE_CLIENT_SECRET = 'googleSecret'
    process.env.MICROSOFT_CLIENT_ID = 'microsoftClientId'
    process.env.MICROSOFT_CLIENT_SECRET = 'microsoftSecret'
    process.env.GITHUB_CLIENT_ID = 'githubClientId'
    process.env.GITHUB_CLIENT_SECRET = 'githubSecret'

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const response = await request(app)
      .post(`/v1/accounts/${account1._id}/login/provider/test`, req)
      .send()

    expect(response.body.error.message).toBe('Unsupported provider')
  })

  test('link with provider', async () => {
    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options) => {
      return (req, res, next) => {
        res.redirect(`https://test/provider/${provider}/callback?state=${options.state}`)
        res.setHeader('Location', `https://test/provider/${provider}/callback?state=${options.state}`)
        res.end()
      }
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const response = await request(app)
      .post(`/v1/accounts/${account1._id}/users/${user1._id}/link/provider/google`, req)
      .send()

    expect(mockAuthenticate).toHaveBeenCalledWith('google', expect.anything())

    expect(response.body.result.redirectUrl).toContain('https://test/provider/google/callback')
    mockAuthenticate.mockRestore()
  })

  test('admin link with provider', async () => {
    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options) => {
      return (req, res, next) => {
        res.redirect(`https://test/provider/${provider}/callback?state=${options.state}`)
        res.setHeader('Location', `https://test/provider/${provider}/callback?state=${options.state}`)
        res.end()
      }
    })

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const response = await request(app)
      .post(`/v1/system-admins/${user1._id}/link`, req)
      .send()

    expect(mockAuthenticate).toHaveBeenCalledWith('google', expect.anything())

    expect(response.body.result.redirectUrl).toContain('https://test/provider/google/callback')
    mockAuthenticate.mockRestore()
  })

  test('link with wrong provider', async () => {
    process.env.GOOGLE_CLIENT_ID = 'googleClientId'
    process.env.GOOGLE_CLIENT_SECRET = 'googleSecret'
    process.env.MICROSOFT_CLIENT_ID = 'microsoftClientId'
    process.env.MICROSOFT_CLIENT_SECRET = 'microsoftSecret'
    process.env.GITHUB_CLIENT_ID = 'githubClientId'
    process.env.GITHUB_CLIENT_SECRET = 'githubSecret'
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const response = await request(app)
      .post(`/v1/accounts/${account1._id}/users/${user1._id}/link/provider/test`, req)
      .send()

    expect(response.body.error.message).toBe('Unsupported provider')
  })

  test('create with provider from scratch', async () => {
    process.env.GOOGLE_CLIENT_ID = 'googleClientId'
    process.env.GOOGLE_CLIENT_SECRET = 'googleSecret'
    process.env.MICROSOFT_CLIENT_ID = 'microsoftClientId'
    process.env.MICROSOFT_CLIENT_SECRET = 'microsoftSecret'
    process.env.GITHUB_CLIENT_ID = 'githubClientId'
    process.env.GITHUB_CLIENT_SECRET = 'githubSecret'
    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options) => {
      return (req, res, next) => {
        res.redirect(`https://test/provider/${provider}/callback?state=${options.state}`)
        res.setHeader('Location', `https://test/provider/${provider}/callback?state=${options.state}`)
        res.end()
      }
    })

    const response = await request(app)
      .post('/v1/accounts/create-account/provider/google', req)
      .send({})

    expect(mockAuthenticate).toHaveBeenCalledWith('google', expect.anything())

    expect(response.body.result.redirectUrl).toContain('https://test/provider/google/callback')
    mockAuthenticate.mockRestore()
  })

  test('create with provider from invitation', async () => {
    process.env.GOOGLE_CLIENT_ID = 'googleClientId'
    process.env.GOOGLE_CLIENT_SECRET = 'googleSecret'
    process.env.MICROSOFT_CLIENT_ID = 'microsoftClientId'
    process.env.MICROSOFT_CLIENT_SECRET = 'microsoftSecret'
    process.env.GITHUB_CLIENT_ID = 'githubClientId'
    process.env.GITHUB_CLIENT_SECRET = 'githubSecret'
    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options) => {
      return (req, res, next) => {
        res.redirect(`https://test/provider/${provider}/callback?state=${options.state}`)
        res.setHeader('Location', `https://test/provider/${provider}/callback?state=${options.state}`)
        res.end()
      }
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', accountId: account1._id })
    await user1.save()

    const response = await request(app)
      .post('/v1/accounts/create-account/provider/google', req)
      .send({ accountId: account1._id, userId: user1._id })

    expect(mockAuthenticate).toHaveBeenCalledWith('google', expect.anything())

    expect(response.body.result.redirectUrl).toContain('https://test/provider/google/callback')
    mockAuthenticate.mockRestore()
  })

  test('link with wrong provider', async () => {
    process.env.GOOGLE_CLIENT_ID = 'googleClientId'
    process.env.GOOGLE_CLIENT_SECRET = 'googleSecret'
    process.env.MICROSOFT_CLIENT_ID = 'microsoftClientId'
    process.env.MICROSOFT_CLIENT_SECRET = 'microsoftSecret'
    process.env.GITHUB_CLIENT_ID = 'githubClientId'
    process.env.GITHUB_CLIENT_SECRET = 'githubSecret'

    const response = await request(app)
      .post('/v1/accounts/create-account/provider/test', req)
      .send({})

    expect(response.body.error.message).toBe('Unsupported provider')
  })

  test('admin link with wrong provider', async () => {
    delete process.env.GOOGLE_CLIENT_ID
    delete process.env.GOOGLE_CLIENT_SECRET

    const response = await request(app)
      .post('/v1/system-admins/login/provider', req)
      .send({})

    expect(response.body.error.message).toBe('Unsupported provider')
  })

  test('admin login with google callback', async () => {
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', googleProfileId: 'id123123' })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'login' })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: user1.email, name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/system-admins/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)
    console.log(response.header.location)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?adminLoginToken`)
    mockAuthenticate.mockRestore()
  })

  test('login with google callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', googleProfileId: 'id123123', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'login', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: user1.email, name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?loginToken`)
    mockAuthenticate.mockRestore()
  })

  test('admin login with google callback error AUTHENTICATION_ERROR', async () => {
    const state = Buffer.from(JSON.stringify({ type: 'login' })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: 'test@gmail.com', name: 'name', profilePicture: 'http://test.com' }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/system-admins/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?failed=AUTHENTICATION_ERROR`)
    mockAuthenticate.mockRestore()
  })

  test('login with google callback error AUTHENTICATION_ERROR', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const state = Buffer.from(JSON.stringify({ type: 'login', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: 'test@gmail.com', name: 'name', profilePicture: 'http://test.com' }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?failed=AUTHENTICATION_ERROR`)
    mockAuthenticate.mockRestore()
  })

  test('login with microsoft provider callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', microsoftProfileId: 'id123123', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'login', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: user1.email, name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/microsoft/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?loginToken`)
    mockAuthenticate.mockRestore()
  })

  test('login with github provider callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', githubProfileId: 'id123123', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'login', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: user1.email, name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/github/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?loginToken`)
    mockAuthenticate.mockRestore()
  })

  test('link with google provider callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'link', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName }, user: { _id: user1._id, email: user1.email } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: user1.email, name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?success=true`)
    mockAuthenticate.mockRestore()
  })

  test('admin link with google provider callback', async () => {
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1' })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'link', user: { _id: user1._id, email: user1.email } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: user1.email, name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/system-admins/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?success=true`)
    mockAuthenticate.mockRestore()
  })

  test('admin link with google provider callback error not found', async () => {
    const user1 = new SystemAdminTestModel({ email: 'user122@gmail.com', name: 'user1' })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'link', user: { _id: user1._id, email: user1.email } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: 'user1@gmail.com', name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/system-admins/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?failed=NOT_FOUND`)
    mockAuthenticate.mockRestore()
  })

  test('admin link with google provider callback error not found', async () => {
    const user1 = new SystemAdminTestModel({ email: 'user122@gmail.com', name: 'user1' })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'link', user: { _id: user1._id, email: user1.email } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: 'user1@gmail.com', name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/system-admins/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?failed=NOT_FOUND`)
    mockAuthenticate.mockRestore()
  })

  test('link with google provider callback error not found', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user122@gmail.com', name: 'user1', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'link', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName }, user: { _id: user1._id, email: user1.email } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: 'user1@gmail.com', name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?failed=NOT_FOUND`)
    mockAuthenticate.mockRestore()
  })

  test('link with microsoft provider callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'link', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName }, user: { _id: user1._id, email: user1.email } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: user1.email, name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/microsoft/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?success=true`)
    mockAuthenticate.mockRestore()
  })

  test('link with github provider callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'link', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName }, user: { _id: user1._id, email: user1.email } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: user1.email, name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/github/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?success=true`)
    mockAuthenticate.mockRestore()
  })

  test('create from scratch with provider callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', googleProfileId: 'id123123', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'create' })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: user1.email, name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?userData`)
    mockAuthenticate.mockRestore()
  })

  test('create from invitation with google provider callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'create', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName }, user: { _id: user1._id, email: user1.email } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: user1.email, name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?loginToken`)
    mockAuthenticate.mockRestore()
  })

  test('create from invitation with google provider callback error not found', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user122@gmail.com', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'create', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName }, user: { _id: user1._id, email: user1.email } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: 'user1@gmail.com', name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?failed=NOT_FOUND`)
    mockAuthenticate.mockRestore()
  })

  test('create from invitation with microsoft provider callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'create', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName }, user: { _id: user1._id, email: user1.name } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: user1.email, name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/microsoft/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?loginToken`)
    mockAuthenticate.mockRestore()
  })

  test('create from invitation with github provider callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'create', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName }, user: { _id: user1._id, email: user1.name } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        const user = { id: 'id123123', email: user1.email, name: user1.name, profilePicture: user1.profilePicture }
        callback(null, user)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/github/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?loginToken`)
    mockAuthenticate.mockRestore()
  })

  test('user failed error provider callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'create', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName }, user: { _id: user1._id, email: user1.name } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        callback(null, false)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/github/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?failed=AUTHENTICATION_ERROR`)
    mockAuthenticate.mockRestore()
  })

  test('err failed error provider callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'create', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName }, user: { _id: user1._id, email: user1.name } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        callback(new Error('test'), false)
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/github/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?failed=AUTHENTICATION_ERROR`)
    mockAuthenticate.mockRestore()
  })

  test('admin err failed error provider callback', async () => {
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1' })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'create', user: { _id: user1._id, email: user1.name } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        callback(new Error('test'), false)
      }
    })

    const response = await request(app)
      .get('/v1/system-admins/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?failed=AUTHENTICATION_ERROR`)
    mockAuthenticate.mockRestore()
  })

  test('passport error provider callback', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', accountId: account1._id })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'create', account: { _id: account1._id, name: account1.name, urlFriendlyName: account1.urlFriendlyName }, user: { _id: user1._id, email: user1.name } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        throw Error('test')
      }
    })

    const response = await request(app)
      .get('/v1/accounts/provider/github/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?failed=AUTHENTICATION_ERROR`)
    mockAuthenticate.mockRestore()
  })

  test('admin passport error provider callback', async () => {
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1' })
    await user1.save()

    const state = Buffer.from(JSON.stringify({ type: 'create', user: { _id: user1._id, email: user1.name } })).toString('base64')

    const mockAuthenticate = vi.spyOn(passport, 'authenticate').mockImplementation((provider, options, callback) => {
      return (req, res, next) => {
        throw Error('test')
      }
    })

    const response = await request(app)
      .get('/v1/system-admins/provider/google/callback?state=' + state, req)
      .send()

    expect(response.status).toBe(302)

    expect(response.header.location).toContain(`${process.env.APP_URL}provider-auth?failed=AUTHENTICATION_ERROR`)
    mockAuthenticate.mockRestore()
  })
})
