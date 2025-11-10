import { describe, test, expect, beforeAll, afterEach, afterAll, vi } from 'vitest'
import createApiServer from 'express-async-api'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import request from 'supertest'

import createMongooseMemoryServer from 'mongoose-memory'

import invitation from './invitation.js'
const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

const AccountTestModel = mongoose.model('AccountTest', new mongoose.Schema({
  name: { type: String },
  urlFriendlyName: { type: String, unique: true },
  logo: { type: String }
}, { timestamps: true }))

const UserProjectAccessSchema = new mongoose.Schema({
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  permission: { type: String, enum: ['viewer', 'editor'], required: true }
}, { _id: false })

const UserTestModel = mongoose.model('UserTest', new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/ },
  password: { type: String },
  role: { type: String, default: 'user', enum: ['user', 'admin', 'client'] },
  projectsAccess: { type: [UserProjectAccessSchema], default: [] },
  accountId: { type: mongoose.Schema.Types.ObjectId, ref: 'Account', required: true },
  profilePicture: { type: String }
}, { timestamps: true }))

const SystemAdminTestModel = mongoose.model('Test', new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/, unique: true },
  password: { type: String },
  profilePicture: { type: String }
}, { timestamps: true }))

describe('Accounts invitation test', () => {
  let app
  let originalEnv
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
    }, () => { })
    invitation({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel, SystemAdminModel: SystemAdminTestModel })
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

  test('success send invitation by admin /v1/accounts/:accountId/invitation/send', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const adminHash = await bcrypt.hash('user1Password', 10)
    const admin1 = new SystemAdminTestModel({ email: 'admin1@gmail.com', name: 'user1', password: adminHash })
    await admin1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: admin1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(201)
    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('success send invitation role client by admin /v1/accounts/:accountId/invitation/send', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const adminHash = await bcrypt.hash('user1Password', 10)
    const admin1 = new SystemAdminTestModel({ email: 'admin1@gmail.com', name: 'user1', password: adminHash })
    await admin1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: admin1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/send').set('authorization', 'Bearer ' + token).send({
        email: 'user3@gmail.com',
        role: 'client',
        projectsAccess: [{
          projectId: mongoose.Types.ObjectId(),
          permission: 'editor'
        }]
      })

    expect(res.body.status).toBe(201)
    expect(res.body.result.success).toBe(true)
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

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', role: 'admin', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', role: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(400)
    await fetchSpy.mockRestore()
  })

  test('success resend invitation by admin /v1/accounts/:accountId/invitation/resend', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', accountId: account1._id })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', role: 'admin', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', role: 'admin', user: { _id: user2._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/resend').set('authorization', 'Bearer ' + token).send({ email: 'user1@gmail.com' })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('success resend invitation role client by admin /v1/accounts/:accountId/invitation/resend', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({
      email: 'user1@gmail.com',
      accountId: account1._id,
      role: 'client',
      projectsAccess: [{
        projectId: mongoose.Types.ObjectId(),
        permission: 'editor'
      }]
    })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', role: 'admin', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', role: 'admin', user: { _id: user2._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/resend').set('authorization', 'Bearer ' + token).send({
        email: 'user1@gmail.com'
      })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('success resend invitation by admin /v1/accounts/:accountId/invitation/resend', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const adminHash = await bcrypt.hash('user1Password', 10)
    const admin1 = new SystemAdminTestModel({ email: 'admin1@gmail.com', name: 'user1', password: adminHash })
    await admin1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', accountId: account1._id })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', role: 'admin', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: admin1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/resend').set('authorization', 'Bearer ' + token).send({ email: 'user1@gmail.com' })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('success send invitation by user role admin  /v1/accounts/:accountId/invitation/send', async () => {
    process.env.ALPHA_MODE = false

    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', role: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(201)
    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('send invitation error user exist  /v1/accounts/:accountId/invitation/send', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user1@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('resend invitation error user alread verified  /v1/accounts/:accountId/invitation/resend', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/resend').set('authorization', 'Bearer ' + token).send({ email: 'user1@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('resend invitation error user not exist  /v1/accounts/:accountId/invitation/resend', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/resend').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('send invitation error sending  /v1/accounts/:accountId/invitation/send', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const adminHash = await bcrypt.hash('user1Password', 10)
    const admin1 = new SystemAdminTestModel({ email: 'admin1@gmail.com', name: 'user1', password: adminHash })
    await admin1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: admin1._id } }, secrets[0])
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockRejectedValue(new Error('test mock send email error'))
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
    }, () => { })
    invitation({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel, SystemAdminModel: SystemAdminTestModel })
    app = app._expressServer

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.error.message).toEqual('test mock send email error')
    await fetchSpy.mockRestore()
  })

  test('send invitation error unAuthorized header  /v1/accounts/:accountId/invitation/send', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(403)
  })

  test('success accept invitation  /v1/accounts/:accountId/invitation/accept', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const user2 = new UserTestModel({ email: 'user2@gmail.com', accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', account: { _id: account1._id }, user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(200)
  })

  test('success accept invitation client /v1/accounts/:accountId/invitation/accept', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const user2 = new UserTestModel({
      email: 'user2@gmail.com',
      accountId: account1._id,
      role: 'client',
      projectsAccess: [{
        projectId: mongoose.Types.ObjectId(),
        permission: 'editor'
      }]
    })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', account: { _id: account1._id }, user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(200)
  })

  test('accept invitation error user exist   /v1/accounts/:accountId/invitation/accept', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', account: { _id: account1._id }, user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })

    expect(res.body.status).toBe(405)
  })

  test('success invitation error unAuthorized header  /v1/accounts/:accountId/invitation/accept', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(403)
  })

  test('success invitation error unAuthorized access to account  /v1/accounts/:accountId/invitation/accept', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', account: { _id: account1._id }, user: { _id: user1._id, email: user1.email } }, secrets[0])
    const id = new mongoose.Types.ObjectId()

    const res = await request(app)
      .post('/v1/accounts/' + id + '/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(403)
  })

  test('accept invitation password Validation Error  /v1/accounts/:accountId/invitation/accept', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', accountId: account1._id })
    await user2.save()
    const token = jwt.sign({ type: 'invitation', account: { _id: account1._id }, user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'user222PasswordUpdated' })
    expect(res.body.status).toBe(400)
  })

  test('accept invitation user email does not exist /v1/accounts/:accountId/invitation/accept', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', account: { _id: account1._id }, user: { _id: user2._id, email: 'user4@gmail.com' } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(404)
  })

  // admin invitation tests

  test('success send invitation  /v1/system-admins/invitation/send', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(201)
    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('error fetch', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ status: 400, error: { message: 'test error', name: 'error' } })
    })

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(400)
    await fetchSpy.mockRestore()
  })

  test('success resend invitation', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com' })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/resend').set('authorization', 'Bearer ' + token).send({ email: 'user1@gmail.com' })

    expect(res.body.status).toBe(201)
    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('send invitation error user exist  /v1/system-admins/invitation/send', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user2@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('send invitation error user not exist  /v1/system-admins/invitation/send', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])
    const res = await request(app)
      .post('/v1/system-admins/invitation/resend').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('send invitation error user already verified', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])
    const res = await request(app)
      .post('/v1/system-admins/invitation/resend').set('authorization', 'Bearer ' + token).send({ email: 'user1@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('send invitation error unAuthorized header  /v1/system-admins/invitation/send', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(403)
  })

  test('send invitation sending error   /v1/system-admins/invitation/send', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockRejectedValue(new Error('test mock send email error'))

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    app = createApiServer((e) => {
      return {
        status: e.status,
        error: {
          name: e.name,
          message: e.message
        }
      }
    }, () => { })
    invitation({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel, SystemAdminModel: SystemAdminTestModel })
    app = app._expressServer

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.error.message).toEqual('test mock send email error')
  })

  test('success accept invitation  /v1/system-admins/invitation/accept', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com' })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(200)
  })

  test('send invitation error user exist  /v1/system-admins/invitation/accept', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })

    expect(res.body.status).toBe(405)
  })

  test('send invitation error unAuthorized header  /v1/system-admins/invitation/accept', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(403)
  })

  test('success accept invitation  /v1/system-admins/invitation/accept', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com' })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'user222PasswordUpdated' })
    expect(res.body.status).toBe(400)
  })

  test('accept invitation user email does not exist /v1/system-admins/invitation/accept', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com' })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', user: { _id: user1._id, email: 'user4@gmail.com' } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(401)
  })
})

describe('System admin invitation test', () => {
  let app
  let originalEnv
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
    }, () => { })
    invitation({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel, SystemAdminModel: SystemAdminTestModel })
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

  test('success send invitation  /v1/system-admins/invitation/send', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(201)
    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('error fetch', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ status: 400, error: { message: 'test error', name: 'error' } })
    })

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(400)
    await fetchSpy.mockRestore()
  })

  test('success resend invitation', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com' })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/resend').set('authorization', 'Bearer ' + token).send({ email: 'user1@gmail.com' })

    expect(res.body.status).toBe(201)
    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('send invitation error user exist  /v1/system-admins/invitation/send', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user2@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('send invitation error user not exist  /v1/system-admins/invitation/send', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])
    const res = await request(app)
      .post('/v1/system-admins/invitation/resend').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('send invitation error user already verified', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])
    const res = await request(app)
      .post('/v1/system-admins/invitation/resend').set('authorization', 'Bearer ' + token).send({ email: 'user1@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('send invitation error unAuthorized header  /v1/system-admins/invitation/send', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(403)
  })

  test('send invitation sending error   /v1/system-admins/invitation/send', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockRejectedValue(new Error('test mock send email error'))

    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    app = createApiServer((e) => {
      return {
        status: e.status,
        error: {
          name: e.name,
          message: e.message
        }
      }
    }, () => { })
    invitation({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel, SystemAdminModel: SystemAdminTestModel })
    app = app._expressServer

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.error.message).toEqual('test mock send email error')
  })

  test('success accept invitation  /v1/system-admins/invitation/accept', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com' })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(200)
  })

  test('send invitation error user exist  /v1/system-admins/invitation/accept', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })

    expect(res.body.status).toBe(405)
  })

  test('send invitation error unAuthorized header  /v1/system-admins/invitation/accept', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = await bcrypt.hash('user2Password', 10)
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(403)
  })

  test('success accept invitation  /v1/system-admins/invitation/accept', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com' })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'user222PasswordUpdated' })
    expect(res.body.status).toBe(400)
  })

  test('accept invitation user email does not exist /v1/system-admins/invitation/accept', async () => {
    const hash1 = await bcrypt.hash('user1Password', 10)
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com' })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', user: { _id: user1._id, email: 'user4@gmail.com' } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(401)
  })
})
