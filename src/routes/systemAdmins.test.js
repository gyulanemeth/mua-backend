import { describe, test, expect, beforeAll, afterEach, afterAll, vi } from 'vitest'
import createApiServer from 'express-async-api'
import crypto from 'crypto'

import mongoose from 'mongoose'
import request from 'supertest'
import jwt from 'jsonwebtoken'

import createMongooseMemoryServer from 'mongoose-memory'

import admins from './systemAdmins.js'
import aws from '../helpers/awsBucket.js'
import StaticServer from 'static-server'

import path from 'path'
import { fileURLToPath } from 'url'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const SystemAdminTestModel = mongoose.model('Test', new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/, unique: true },
  password: { type: String },
  profilePicture: { type: String }
}, { timestamps: true }))

describe('/v1/system-admins/ ', () => {
  let app
  let s3
  let server
  let secrets
  beforeAll(async () => {
    await mongooseMemoryServer.start()
    await mongooseMemoryServer.connect('test-db')
    process.env.NODE_ENV = 'development'
    process.env.SECRETS = 'verylongsecret1 verylongsecret2'
    process.env.BLUEFOX_TEMPLATE_ADMIN_VERIFY_EMAIL = ''
    process.env.BLUEFOX_TEMPLATE_ADMIN_FORGOT_PASSWORD = ''
    process.env.BLUEFOX_TEMPLATE_ADMIN_INVITATION = ''
    process.env.BLUEFOX_API_KEY = '<your_bluefox_api_key>'
    process.env.MAX_FILE_SIZE = '5242880'
    process.env.AWS_BUCKET_NAME = 'bluefox'
    process.env.AWS_FOLDER_NAME = 'mua-system-admins'
    process.env.AWS_BUCKET_PATH = './tmp/'
    process.env.AWS_REGION = '<your_aws_region>'
    process.env.AWS_ACCESS_KEY_ID = '<your_aws_access_key_id>'
    process.env.AWS_SECRET_ACCESS_KEY = '<your_aws_secret_access_key>'
    process.env.CDN_BASE_URL = 'http://localhost:10006/'
    process.env.TEST_STATIC_SERVER_URL = 'http://localhost:10006/'
    process.env.APP_URL = 'http://app.emailfox.link/'
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
    admins({ apiServer: app, SystemAdminModel: SystemAdminTestModel })
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

  // get admin list tests
  test('success get admin list  /v1/system-admins/', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const user3 = new SystemAdminTestModel({ email: 'user3@gmail.com', name: 'user3' })
    await user3.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .get('/v1/system-admins/').set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(200)
    expect(res.body.result.count).toBe(3)
  })

  test('unAuthorized header  /v1/system-admins/', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .get('/v1/system-admins/').set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  // get spicific admin tests
  test('success get admin  /v1/system-admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .get('/v1/system-admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(200)
    expect(res.body.result.email).toBe(user1.email)
  })

  test('unAuthorized header /v1/system-admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .get('/v1/system-admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  // delete admin tests
  test('success delete admin /v1/system-admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'delete' }, secrets[0])

    const res = await request(app)
      .delete('/v1/system-admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(200)
  })

  test('delete admin permission needed error /v1/system-admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .delete('/v1/system-admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  test('success get permission ', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { email: 'user1@gmail.com' } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/permission/delete').set('authorization', 'Bearer ' + token)
      .send({ password: 'user1Password' })

    expect(res.body.status).toBe(200)
  })

  test('get permission error wrong Password ', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { email: 'user1@gmail.com' } }, secrets[0])

    const res = await request(app)
      .post('/v1/system-admins/permission/delete').set('authorization', 'Bearer ' + token)
      .send({ password: 'wrongPassword' })

    expect(res.body.status).toBe(401)
  })

  test('delete last admin error /v1/system-admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const token = jwt.sign({ type: 'delete' }, secrets[0])

    const res = await request(app)
      .delete('/v1/system-admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(405)
  })

  test('unAuthorized header for delete /v1/system-admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .delete('/v1/system-admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  // access Token tests
  test('success get access-token /v1/system-admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'login', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .get('/v1/system-admins/' + user1._id + '/access-token').set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(200)
  })

  test('success refresh access-token /v1/system-admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .get('/v1/system-admins/' + user1._id + '/access-token').set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(200)
  })

  test('access-token unAuthorized header /v1/system-admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .get('/v1/system-admins/' + user1._id + '/access-token').set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  test('access-token unAuthorized user /v1/system-admins/:id', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user2._id } }, secrets[0])

    const res = await request(app)
      .get('/v1/system-admins/' + user1._id + '/access-token').set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(403)
  })

  // update admin tests
  test('update name /v1/system-admins/:id/name', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/system-admins/' + user1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'user3' })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
  })

  test('update password success /v1/system-admins/:id/password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/system-admins/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password', newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
  })

  test('update password unAuthorized user  /v1/system-admins/:id/password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user2._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/system-admins/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password', newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })

    expect(res.body.status).toBe(403)
  })

  test('update password wrong newPasswordAgain validation error  /v1/system-admins/:id/password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/system-admins/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password', newPassword: 'userPasswordUpdated', newPasswordAgain: 'user11PasswordUpdated' })

    expect(res.body.status).toBe(400)
  })

  test('update password wrong password authorization error  /v1/system-admins/:id/password', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/system-admins/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ oldPassword: 'user1Password_wrong', newPassword: 'user11PasswordUpdated', newPasswordAgain: 'user11PasswordUpdated' })

    expect(res.body.status).toBe(403)
    expect(res.body.error.message).toBe('Wrong password.')
  })

  test('success patch email req send  /v1/system-admins/:id/email', async () => {
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

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch(`/v1/system-admins/${user1._id}/email`).set('authorization', 'Bearer ' + token).send({ newEmail: 'userUpdate@gmail.com', newEmailAgain: 'userUpdate@gmail.com' })

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
    await fetchSpy.mockRestore()
  })

  test('error fetch', async () => {
    const fetchSpy = vi.spyOn(global, 'fetch')
    fetchSpy.mockResolvedValue({
      ok: true,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ status: 400 })
    })

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch(`/v1/system-admins/${user1._id}/email`).set('authorization', 'Bearer ' + token).send({ newEmail: 'userUpdate@gmail.com', newEmailAgain: 'userUpdate@gmail.com' })

    expect(res.body.status).toBe(400)
    await fetchSpy.mockRestore()
  })

  test('patch email req send error email exist /v1/system-admins/:id/email', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch(`/v1/system-admins/${user1._id}/email`).set('authorization', 'Bearer ' + token).send({ newEmail: 'user2@gmail.com', newEmailAgain: 'user2@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('patch email req send error email don\'t match /v1/system-admins/:id/email', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch(`/v1/system-admins/${user1._id}/email`).set('authorization', 'Bearer ' + token).send({ newEmail: 'updateEmail@gmail.com', newEmailAgain: 'updateEmail2@gmail.com' })

    expect(res.body.status).toBe(400)
  })

  test('update email success /v1/system-admins/:id/email-confirm', async () => {
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new SystemAdminTestModel({ email: 'user2@gmail.com', name: 'user2', password: hash2 })
    await user2.save()

    const token = jwt.sign({ type: 'verfiy-email', user: { _id: user1._id }, newEmail: 'userUpdate@gmail.com' }, secrets[0])

    const res = await request(app)
      .patch('/v1/system-admins/' + user1._id + '/email-confirm')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
  })

  test('success upload profilePicture ', async () => {
    process.env.CDN_BASE_URL = process.env.TEST_STATIC_SERVER_URL

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const res = await request(app).post(`/v1/system-admins/${user1._id}/profile-picture`)
      .set('authorization', 'Bearer ' + token)
      .attach('profilePicture', path.join(__dirname, '..', 'helpers/testPics', 'test.png'))

    const adminData = await request(app)
      .get('/v1/system-admins/' + user1._id).set('authorization', 'Bearer ' + token).send()

    await server.start()
    const pic = await fetch(adminData.body.result.profilePicture)
    expect(pic.status).toBe(200)
    expect(res.body.status).toBe(200)
  })

  test('upload profilePicture max file size error ', async () => {
    process.env.CDN_BASE_URL = process.env.TEST_STATIC_SERVER_URL
    process.env.MAX_FILE_SIZE = 20000
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

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
    admins({ apiServer: sizeTestApp, SystemAdminModel: SystemAdminTestModel })
    sizeTestApp = sizeTestApp._expressServer

    const res = await request(sizeTestApp).post(`/v1/system-admins/${user1._id}/profile-picture`)
      .set('authorization', 'Bearer ' + token)
      .attach('profilePicture', path.join(__dirname, '..', 'helpers/testPics', 'test.png'))

    expect(res.body.status).toBe(413)
    expect(res.body.error.message).toBe('File size limit exceeded. Maximum file size allowed is 0.02mb')
  })

  test('success delete profilePicture ', async () => {
    process.env.CDN_BASE_URL = process.env.TEST_STATIC_SERVER_URL
    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new SystemAdminTestModel({ email: 'user1@gmail.com', name: 'user1', password: hash1 })
    await user1.save()

    const token = jwt.sign({ type: 'admin', user: { _id: user1._id } }, secrets[0])

    const uploadRes = await request(app).post(`/v1/system-admins/${user1._id}/profile-picture`)
      .set('authorization', 'Bearer ' + token)
      .attach('profilePicture', path.join(__dirname, '..', 'helpers/testPics', 'test.png'))

    await server.start()
    const picBeforeDelete = await fetch(uploadRes.body.result.profilePicture)
    expect(picBeforeDelete.status).toBe(200)

    const res = await request(app).delete(`/v1/system-admins/${user1._id}/profile-picture `)
      .set('authorization', 'Bearer ' + token).send()

    const pic = await fetch(uploadRes.body.result.profilePicture)
    expect(pic.status).toBe(404)
    expect(res.body.status).toBe(200)
  })
})
