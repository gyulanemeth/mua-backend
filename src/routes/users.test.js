import { describe, test, expect, beforeAll, afterEach, afterAll, vi } from 'vitest'
import createApiServer from 'express-async-api'
import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import request from 'supertest'
import StaticServer from 'static-server'

import createMongooseMemoryServer from 'mongoose-memory'

import aws from '../helpers/awsBucket.js'

import path from 'path'
import { fileURLToPath } from 'url'

import users from './users.js'

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
  githubProfileId: { type: String }
}, { timestamps: true }))

describe('users test', () => {
  let app
  let s3
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
    users({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel })
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
    await server.stop()
  })

  afterAll(async () => {
    await s3.deleteBucket({ Bucket: process.env.AWS_BUCKET_NAME }).promise()

    await mongooseMemoryServer.disconnect()
    await mongooseMemoryServer.stop()
  })

  test('success update user name in account by admin  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'userUpdate' })

    expect(res.body.status).toBe(200)
  })

  test('success resend finalize user  /v1/accounts/:accoutId/users/:userId/resend-finalize-registration', async () => {
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

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users/' + user1._id + '/resend-finalize-registration')
      .send()

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

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users/' + user1._id + '/resend-finalize-registration')
      .send()

    expect(res.body.status).toBe(400)
    await fetchSpy.mockRestore()
  })

  test('success update user name in account by user with role admin  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'userUpdate' })

    expect(res.body.status).toBe(200)
  })

  test('success update user name in account by user himself  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'userUpdate' })

    expect(res.body.status).toBe(200)
  })

  test('update user name unAuthorized header  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'userUpdate' })

    expect(res.body.status).toBe(403)
  })

  test('update undefined user name  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'userUpdate' })

    expect(res.body.status).toBe(403)
  })

  test('success update user password in account by admin  /v1/accounts/:accountId/users/:id/password', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password', newPassword: 'updatePassword', newPasswordAgain: 'updatePassword' })

    expect(res.body.status).toBe(200)
  })

  test('success send create password email user /v1/accounts/:accountId/users/:id/password', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', googleProfileId: 'googleProfileId', accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, user: { _id: user1._id } }, secrets[0])
    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'newPassword', newPasswordAgain: 'newPassword' })

    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('success update user password in account by user with role admin  /v1/accounts/:accountId/users/:id/password', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password', newPassword: 'updatePassword', newPasswordAgain: 'updatePassword' })

    expect(res.body.status).toBe(200)
  })

  test('success update user password in account by user himself  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password', newPassword: 'updatePassword', newPasswordAgain: 'updatePassword' })

    expect(res.body.status).toBe(200)
  })

  test('update user password unAuthorized header  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'updatePassword', newPasswordAgain: 'updatePassword' })

    expect(res.body.status).toBe(403)
  })

  test('update password undefined user  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'updatePassword', newPasswordAgain: 'updatePassword' })

    expect(res.body.status).toBe(403)
  })

  test('update user password in account by admin Validation error  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'updatePassword', newPasswordAgain: 'update111111Password' })

    expect(res.body.status).toBe(400)
  })

  test('update user password not match with old password error   /v1/accounts/:accountId/users/:id/password', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'userPassword', newPassword: 'updatePassword', newPasswordAgain: 'updatePassword' })

    expect(res.body.status).toBe(400)
  })

  test('success update user role in account by admin  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'admin' })

    expect(res.body.status).toBe(200)
  })

  test('success update user role in account by user with role admin  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'admin' })

    expect(res.body.status).toBe(200)
  })

  test('update user role in account methode not allowed error (last admin)  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, role: 'admin', accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'user' })
    expect(res.body.status).toBe(405)
  })

  test('success update user role from admin to user in account by admin   /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', role: 'admin', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'user' })

    expect(res.body.status).toBe(200)
  })

  test('update user role unAuthorized header  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'admin' })

    expect(res.body.status).toBe(403)
  })

  test('update undefined user role  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'admin' })

    expect(res.body.status).toBe(403)
  })

  test('update user role in account error last admin  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'user' })

    expect(res.body.status).toBe(405)
  })

  test('success delete user in account by admin  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'delete' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success delete user  in account by user with role admin  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'delete', user: { _id: 123123 }, account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success delete user where admin more than 1   /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', role: 'admin', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'delete' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('delete user role unAuthorized header  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'admin' })

    expect(res.body.status).toBe(403)
  })

  test('update undefined user role  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('delete user role in account error last admin  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'delete', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(405)
  })

  test('success get user access token with admin   /v1/accounts/:accountId/users/:id/access-token ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id + '/access-token')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success get user access token with user same user   /v1/accounts/:accountId/users/:id/access-token ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id + '/access-token')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('get user access token unAuthorized header   /v1/accounts/:accountId/users/:id/access-token ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value', user: { _id: user1._id, accountId: account1._id } }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id + '/access-token')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('success post user finalize-registration   /v1/accounts/:accountId/users/:id/finalize-registration ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', role: 'user', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'registration', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users/' + user1._id + '/finalize-registration')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('post user finalize-registration unAuthorized header   /v1/accounts/:accountId/users/:id/finalize-registration ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', role: 'user', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', role: 'user', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users/' + user1._id + '/finalize-registration')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('post user finalize-registration for undefined account   /v1/accounts/:accountId/users/:id/finalize-registration ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()
    const id = new mongoose.Types.ObjectId()
    const token = jwt.sign({ type: 'registration', user: { _id: user1._id }, account: { _id: id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + id + '/users/' + user1._id + '/finalize-registration')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(404)
  })

  test('post user finalize-registration for undefined user   /v1/accounts/:accountId/users/:id/finalize-registration ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const id = new mongoose.Types.ObjectId()
    const token = jwt.sign({ type: 'registration', user: { _id: id }, account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users/' + id + '/finalize-registration')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(404)
  })

  test('success get all account users  by admin  /v1/accounts/:accountId/users', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success get all account users by user  /v1/accounts/:accountId/users', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('get all account users unAuthorized header  /v1/accounts/:accountId/users', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('get all account users account not found  /v1/accounts/:accountId/users', async () => {
    const token = jwt.sign({ type: 'user' }, secrets[0])
    const id = new mongoose.Types.ObjectId()
    const res = await request(app)
      .get('/v1/accounts/' + id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(404)
  })

  test('success add user  by admin  /v1/accounts/:accountId/users', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send({ email: 'user2@gmail.com', name: 'user2', password: 'user2Password' })

    expect(res.body.status).toBe(201)
  })

  test('success add user by user  /v1/accounts/:accountId/users', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send({ email: 'user2@gmail.com', name: 'user2', password: 'user2Password' })

    expect(res.body.status).toBe(201)
  })

  test('add user unAuthorized header  /v1/accounts/:accountId/users', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send({ email: 'user2@gmail.com', name: 'user2', password: 'user2Password' })

    expect(res.body.status).toBe(403)
  })

  test('add user user exist error  /v1/accounts/:accountId/users', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send({ email: 'user1@gmail.com', name: 'user1', password: 'user1Password' })

    expect(res.body.status).toBe(405)
  })

  test('add user undefined account  /v1/accounts/:accountId/users', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user' }, secrets[0])
    const id = new mongoose.Types.ObjectId()
    const res = await request(app)
      .post('/v1/accounts/' + id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send({ email: 'user2@gmail.com', name: 'user2', password: 'user2Password' })

    expect(res.body.status).toBe(404)
  })

  test('success get account user  by admin  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success get account user by user  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('get account user unAuthorized header  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('get account user account not found  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])
    const id = new mongoose.Types.ObjectId()
    const res = await request(app)
      .get('/v1/accounts/' + id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('get account user user not found  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const token = jwt.sign({ type: 'user' }, secrets[0])
    const id = new mongoose.Types.ObjectId()
    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('success patch email req send  /v1/accounts/:accountId/users/:id/email', async () => {
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

    const token = jwt.sign({ type: 'user', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch(`/v1/accounts/${account1._id}/users/${user1._id}/email`).set('authorization', 'Bearer ' + token).send({ newEmail: 'userUpdate@gmail.com', newEmailAgain: 'userUpdate@gmail.com' })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('patch email required password req send  /v1/accounts/:accountId/users/:id/email', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch(`/v1/accounts/${account1._id}/users/${user1._id}/email`).set('authorization', 'Bearer ' + token).send({ newEmail: 'userUpdate@gmail.com', newEmailAgain: 'userUpdate@gmail.com' })

    expect(res.body.status).toBe(405)
    expect(res.body.error.message).toBe('Password is required to change the email for this account. Please set a password to proceed.')
    await fetchSpy.mockRestore()
  })

  test('patch email req send error email exist /v1/accounts/:accountId/users/:id/email', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch(`/v1/accounts/${account1._id}/users/${user1._id}/email`).set('authorization', 'Bearer ' + token).send({ newEmail: 'user1@gmail.com', newEmailAgain: 'user1@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('patch email req send error email don\'t match /v1/accounts/:accountId/users/:id/email', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch(`/v1/accounts/${account1._id}/users/${user1._id}/email`).set('authorization', 'Bearer ' + token).send({ newEmail: 'userUpdate@gmail.com', newEmailAgain: 'userUpdate123@gmail.com' })

    expect(res.body.status).toBe(400)
  })

  test('update email success /v1/accounts/:accountId/users/:id/emai/v1/admins/:id/email-confirm', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'verfiy-email', user: { _id: user1._id }, account: { _id: account1._id }, newEmail: 'userUpdate@gmail.com' }, secrets[0])

    const res = await request(app)
      .patch(`/v1/accounts/${account1._id}/users/${user1._id}/email-confirm`)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
  })

  test('delete admin permission needed error', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  test('success get permission ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', user: { email: 'user1@gmail.com' } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/permission/delete').set('authorization', 'Bearer ' + token)
      .send({ password: 'user1Password' })

    expect(res.body.status).toBe(200)
  })

  test('get permission error wrong Password ', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new UserTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', user: { email: 'user1@gmail.com' } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/permission/delete').set('authorization', 'Bearer ' + token)
      .send({ password: 'wrongPassword' })

    expect(res.body.status).toBe(401)
  })

  test('success upload profilePicture ', async () => {
    process.env.CDN_BASE_URL = process.env.TEST_STATIC_SERVER_URL
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])

    const res = await request(app).post(`/v1/accounts/${account1._id}/users/${user1._id}/profile-picture`)
      .set('authorization', 'Bearer ' + token)
      .attach('profilePicture', path.join(__dirname, '..', 'helpers/testPics', 'test.png'))

    const userData = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    await server.start()
    const pic = await fetch(userData.body.result.profilePicture)
    expect(pic.status).toBe(200)
    expect(res.body.status).toBe(200)
  })

  test('upload profilePicture max file size error ', async () => {
    process.env.CDN_BASE_URL = process.env.TEST_STATIC_SERVER_URL
    process.env.MAX_FILE_SIZE = 20000

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])

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
    users({ apiServer: sizeTestApp, UserModel: UserTestModel, AccountModel: AccountTestModel })
    sizeTestApp = sizeTestApp._expressServer

    const res = await request(sizeTestApp).post(`/v1/accounts/${account1._id}/users/${user1._id}/profile-picture`)
      .set('authorization', 'Bearer ' + token)
      .attach('profilePicture', path.join(__dirname, '..', 'helpers/testPics', 'test.png'))

    console.log(res.body, '/////////////////')
    expect(res.body.status).toBe(413)
    expect(res.body.error.message).toBe('File size limit exceeded. Maximum file size allowed is 0.02mb')
  })

  test('success delete profilePicture ', async () => {
    process.env.CDN_BASE_URL = process.env.TEST_STATIC_SERVER_URL

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id }, account: { _id: account1._id } }, secrets[0])

    const uploadRes = await request(app).post(`/v1/accounts/${account1._id}/users/${user1._id}/profile-picture`)
      .set('authorization', 'Bearer ' + token)
      .attach('profilePicture', path.join(__dirname, '..', 'helpers/testPics', 'test.png'))

    await server.start()
    const picBeforeDelete = await fetch(uploadRes.body.result.profilePicture)
    expect(picBeforeDelete.status).toBe(200)

    const res = await request(app).delete(`/v1/accounts/${account1._id}/users/${user1._id}/profile-picture`)
      .set('authorization', 'Bearer ' + token).send()

    const pic = await fetch(uploadRes.body.result.profilePicture)
    expect(pic.status).toBe(404)
    expect(res.body.status).toBe(200)
  })

  test('success create password email user /v1/accounts/:accountId/users/:id/create-password', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ result: { success: true }, status: 200 })
    })

    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', googleProfileId: 'googleProfileId', accountId: account1._id })
    await user1.save()

    const hash = crypto.createHash('md5').update('passTest').digest('hex')
    const token = jwt.sign({ type: 'create-password', account: { _id: account1._id }, user: { _id: user1._id }, newPassword: hash }, secrets[0])
    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/create-password')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('success disconnect google provider  /v1/accounts/:accountId/users/:id/provider/:provider', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id, googleProfileId: '123123' })
    await user1.save()

    const token = jwt.sign({ type: 'disconnect', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/provider/google')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success disconnect microsoft provider  /v1/accounts/:accountId/users/:id/provider/:provider', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id, microsoftProfileId: '123123' })
    await user1.save()

    const token = jwt.sign({ type: 'disconnect', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/provider/microsoft')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success disconnect github provider  /v1/accounts/:accountId/users/:id/provider/:provider', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id, githubProfileId: '123123' })
    await user1.save()

    const token = jwt.sign({ type: 'disconnect', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/provider/github')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('disconnect error mising password github provider  /v1/accounts/:accountId/users/:id/provider/:provider', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', accountId: account1._id, githubProfileId: '123123' })
    await user1.save()

    const token = jwt.sign({ type: 'disconnect', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/provider/github')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(405)
    expect(res.body.error.name).toBe('METHOD_NOT_ALLOWED')
    expect(res.body.error.message).toBe('Password is required')
  })
})
