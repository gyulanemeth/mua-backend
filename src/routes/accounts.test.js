import { describe, test, expect, beforeAll, afterEach, afterAll, vi } from 'vitest'
import createApiServer from 'express-async-api'
import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import request from 'supertest'

import createMongooseMemoryServer from 'mongoose-memory'

import accounts from './accounts.js'
import aws from '../helpers/awsBucket.js'
import StaticServer from 'static-server'

import path from 'path'
import { fileURLToPath } from 'url'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

const __dirname = path.dirname(fileURLToPath(import.meta.url))

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

describe('accounts test', () => {
  let app
  let s3
  let originalEnv
  let server
  let secrets
  beforeAll(async () => {
    await mongooseMemoryServer.start()
    await mongooseMemoryServer.connect('test-db')
    process.env.NODE_ENV = 'development'
    process.env.SECRETS = 'verylongsecret1 verylongsecret2'
    process.env.APP_URL = 'http://app.emailfox.link/'
    process.env.BLUEFOX_TRANSACTIONAL_EMAIL_API_URL = 'http://app.emailfox.link/v1/send-transactional'
    process.env.BLUEFOX_API_KEY = '<your_bluefox_api_key>'
    process.env.BLUEFOX_TEMPLATE_ACCOUNT_FINALIZE_REGISTRATION_ID = '123123'
    process.env.BLUEFOX_TEMPLATE_ACCOUNT_FORGOT_PASSWORD_ID = '123123'
    process.env.BLUEFOX_TEMPLATE_ACCOUNT_INVITATION_ID = '123123'
    process.env.BLUEFOX_TEMPLATE_ACCOUNT_LOGIN_SELECT_ID = '123123'
    process.env.BLUEFOX_TEMPLATE_ACCOUNT_VERIFY_EMAIL_ID = '123123'

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
    accounts({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel })
    app = app._expressServer

    s3 = await aws()
    server = new StaticServer({
      rootPath: './tmp/' + process.env.AWS_BUCKET_NAME, // required, the root of the server file tree
      port: parseInt(process.env.TEST_STATIC_SERVER_URL.split(':')[2]), // required, the port to listen
      name: process.env.TEST_STATIC_SERVER_URL
    })
  })

  afterEach(async () => {
    await mongooseMemoryServer.purge()
    process.env = originalEnv
    await server.stop()
  })

  afterAll(async () => {
    await s3.deleteBucket({ Bucket: process.env.AWS_BUCKET_NAME }).promise()

    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })

  test('success get all accounts   /v1/accounts/', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success get account by urlFriendlyName  /v1/accounts/by-url-friendly-name/:urlFriendlyName', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const res = await request(app)
      .get('/v1/accounts/by-url-friendly-name/' + account1.urlFriendlyName)
      .send()

    expect(res.body.status).toBe(200)
    expect(res.body.result.name).toBe('accountExample1')
  })

  test('error get account by urlFriendlyName account not found  /v1/accounts/by-url-friendly-name/:urlFriendlyName', async () => {
    const res = await request(app)
      .get('/v1/accounts/by-url-friendly-name/urlFriendlyNameTest')
      .send()

    expect(res.body.status).toBe(404)
  })

  test('get all accounts unAuthorized header   /v1/accounts/', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('success admin create account   /v1/accounts/', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'accountExample2', urlFriendlyName: 'urlFriendlyNameExample2' })

    expect(res.body.status).toBe(201)
  })

  test('admin create account unAuthorized header    /v1/accounts/', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'accountExample2', urlFriendlyName: 'urlFriendlyNameExample2' })

    expect(res.body.status).toBe(403)
  })

  test('success get account by id   /v1/accounts/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success get account by id   /v1/accounts/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('get account by id unAuthorized header   /v1/accounts/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('success update account name by admin   /v1/accounts/:id/name', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'accountNameUpdated' })

    expect(res.body.status).toBe(200)
  })

  test('update account name by user role admin   /v1/accounts/:id/name', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'accountNameUpdated' })

    expect(res.body.status).toBe(200)
  })

  test('update account name error unAuthorized header   /v1/accounts/:id/name', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'accountNameUpdated' })

    expect(res.body.status).toBe(403)
  })

  test('update account unAuthorized user   /v1/accounts/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const id = new mongoose.Types.ObjectId()
    const token = jwt.sign({ type: 'user', account: { _id: id }, role: 'user' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'accountNameUpdated' })

    expect(res.body.status).toBe(403)
  })

  test('success update account urlFriendlyName by admin   /v1/accounts/:id/urlFriendlyName', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/urlFriendlyName')
      .set('authorization', 'Bearer ' + token)
      .send({ urlFriendlyName: 'accountUrlFriendlyNameUpdated' })

    expect(res.body.status).toBe(200)
  })

  test('update account urlFriendlyName by user role admin   /v1/accounts/:id/urlFriendlyName', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/urlFriendlyName')
      .set('authorization', 'Bearer ' + token)
      .send({ urlFriendlyName: 'accountUrlFriendlyNameUpdated' })

    expect(res.body.status).toBe(200)
  })

  test('update account urlFriendlyName error unAuthorized header   /v1/accounts/:id/urlFriendlyName', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/urlFriendlyName')
      .set('authorization', 'Bearer ' + token)
      .send({ urlFriendlyName: 'accountUrlFriendlyNameUpdated' })

    expect(res.body.status).toBe(403)
  })

  test('update account unAuthorized user   /v1/accounts/:id/urlFriendlyName', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const id = new mongoose.Types.ObjectId()
    const token = jwt.sign({ type: 'user', account: { _id: id }, role: 'user' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/urlFriendlyName')
      .set('authorization', 'Bearer ' + token)
      .send({ urlFriendlyName: 'accountUrlFriendlyNameUpdated' })

    expect(res.body.status).toBe(403)
  })

  test('success delete account  /v1/accounts/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const account2 = new AccountTestModel({ name: 'accountExample2', urlFriendlyName: 'urlFriendlyNameExample2' })
    await account2.save()

    const account3 = new AccountTestModel({ name: 'accountExample3', urlFriendlyName: 'urlFriendlyNameExample3' })
    await account3.save()

    const account4 = new AccountTestModel({ name: 'accountExample4', urlFriendlyName: 'urlFriendlyNameExample4' })
    await account4.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const hash3 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user3 = new UserTestModel({ email: 'user3@gmail.com', name: 'user3', password: hash3, accountId: account1._id })
    await user3.save()

    const hash4 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user4 = new UserTestModel({ email: 'user4@gmail.com', name: 'user4', password: hash4, accountId: account1._id })
    await user4.save()

    const token = jwt.sign({ type: 'delete' }, secrets[0])
    const res = await request(app)
      .delete('/v1/accounts/' + account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('delete account error unAuthorized header   /v1/accounts/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('success create account   /v1/accounts/create', async () => {
    process.env.ALPHA_MODE = false

    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const res = await request(app)
      .post('/v1/accounts/create')
      .send({
        user: { name: 'user1', email: 'user1@gmail.com', password: 'userPassword' },
        account: { name: 'account1', urlFriendlyName: 'account1UrlFriendlyName' }
      })

    expect(res.body.status).toBe(200)
    await fetchSpy.mockRestore()
  })

  test('error create account without password, google, microsoft or github  /v1/accounts/create', async () => {
    process.env.ALPHA_MODE = false

    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const res = await request(app)
      .post('/v1/accounts/create')
      .send({
        user: { name: 'user1', email: 'user1@gmail.com' },
        account: { name: 'account1', urlFriendlyName: 'account1UrlFriendlyName' }
      })

    expect(res.body.status).toBe(400)
    expect(res.body.error.message).toBe('Please provide password or create using Google, Microsoft or Github')

    await fetchSpy.mockRestore()
  })

  test('success create account with google, microsoft or github  /v1/accounts/create', async () => {
    process.env.ALPHA_MODE = false

    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const res = await request(app)
      .post('/v1/accounts/create')
      .send({
        user: { name: 'user1', email: 'user1@gmail.com', googleProfileId: 'test123' },
        account: { name: 'account1', urlFriendlyName: 'account1UrlFriendlyName' }
      })

    expect(res.body.status).toBe(200)
    await fetchSpy.mockRestore()
  })

  test('success create account alpha   /v1/accounts/create', async () => {
    process.env.ALPHA_MODE = true

    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    // in alpah version just system admin can create account
    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/create')
      .set('authorization', 'Bearer ' + token)
      .send({
        user: { name: 'user1', email: 'user1@gmail.com', password: 'userPassword' },
        account: { name: 'account1', urlFriendlyName: 'account1UrlFriendlyName' }
      })

    expect(res.body.status).toBe(200)
    await fetchSpy.mockRestore()
  })

  test('error fetch', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ error: { name: 'error', message: 'error test' }, status: 400 })
    })

    // in alpah version just system admin can create account
    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/create')
      .set('authorization', 'Bearer ' + token)
      .send({
        user: { name: 'user1', email: 'user1@gmail.com', password: 'userPassword' },
        account: { name: 'account1', urlFriendlyName: 'account1UrlFriendlyName' }
      })

    expect(res.body.status).toBe(400)
    await fetchSpy.mockRestore()
  })

  test('error create account alpha non-admin   /v1/accounts/create', async () => {
    process.env.ALPHA_MODE = true

    const res = await request(app)
      .post('/v1/accounts/create')
      .send({
        user: { name: 'user1', email: 'user1@gmail.com', password: 'userPassword' },
        account: { name: 'account1', urlFriendlyName: 'account1UrlFriendlyName' }
      })

    expect(res.body.status).toBe(401)
  })

  test('create account urlFriendlyName exist   /v1/accounts/create', async () => {
    process.env.ALPHA_MODE = false

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const res = await request(app)
      .post('/v1/accounts/create')
      .send({
        user: { name: 'user1', email: 'user1@gmail.com', password: 'userPassword' },
        account: { name: 'account1', urlFriendlyName: 'urlFriendlyNameExample1' }
      })

    expect(res.body.status).toBe(409)
  })

  test('success check-availability   /v1/accounts/check-availability', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const res = await request(app)
      .get('/v1/accounts/check-availability')
      .query({
        urlFriendlyName: 'urlFriendlyNameExample1'
      }).send()

    expect(res.body.status).toBe(200)
  })

  test('check-availability account not found   /v1/accounts/check-availability', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const res = await request(app)
      .get('/v1/accounts/check-availability')
      .query({
        urlFrientlyName: 'test'
      })
      .send()
    expect(res.body.status).toBe(200)
  })

  test('success upload logo ', async () => {
    process.env.CDN_BASE_URL = process.env.TEST_STATIC_SERVER_URL

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app).post(`/v1/accounts/${account1._id}/logo`)
      .set('authorization', 'Bearer ' + token)
      .attach('logo', path.join(__dirname, '..', 'helpers/testPics', 'test.png'))

    const accountData = await request(app)
      .get('/v1/accounts/' + account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    await server.start()
    const pic = await fetch(accountData.body.result.logo)
    expect(pic.status).toBe(200)
    expect(res.body.status).toBe(200)
  })

  test('upload logo max file size error ', async () => {
    process.env.CDN_BASE_URL = process.env.TEST_STATIC_SERVER_URL
    process.env.MAX_FILE_SIZE = 20000
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    let sizeTestApp = createApiServer((e) => {
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
    accounts({ apiServer: sizeTestApp, UserModel: UserTestModel, AccountModel: AccountTestModel })
    sizeTestApp = sizeTestApp._expressServer

    const res = await request(sizeTestApp).post(`/v1/accounts/${account1._id}/logo`)
      .set('authorization', 'Bearer ' + token)
      .attach('logo', path.join(__dirname, '..', 'helpers/testPics', 'test.png'))

    expect(res.body.status).toBe(413)
    expect(res.body.error.message).toBe('File size limit exceeded. Maximum file size allowed is 0.02mb')
  })

  test('success delete logo ', async () => {
    process.env.CDN_BASE_URL = process.env.TEST_STATIC_SERVER_URL

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const uploadRes = await request(app).post(`/v1/accounts/${account1._id}/logo`)
      .set('authorization', 'Bearer ' + token)
      .attach('logo', path.join(__dirname, '..', 'helpers/testPics', 'test.png'))

    await server.start()
    const picBeforeDelete = await fetch(uploadRes.body.result.logo)
    expect(picBeforeDelete.status).toBe(200)

    const res = await request(app).delete(`/v1/accounts/${account1._id}/logo`)
      .set('authorization', 'Bearer ' + token).send()

    const pic = await fetch(uploadRes.body.result.logo)
    expect(pic.status).toBe(404)
    expect(res.body.status).toBe(200)
  })
})
