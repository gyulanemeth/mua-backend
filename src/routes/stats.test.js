import { describe, test, expect, beforeAll, afterEach, afterAll } from 'vitest'
import createApiServer from 'express-async-api'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import request from 'supertest'

import createMongooseMemoryServer from 'mongoose-memory'

import stats from './stats.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

const AccountTestModel = mongoose.model('AccountTest', new mongoose.Schema({
  name: { type: String },
  urlFriendlyName: { type: String, unique: true },
  logo: { type: String },
  deleted: { type: Boolean }
}, { timestamps: true }))

const UserTestModel = mongoose.model('UserTest', new mongoose.Schema({
  name: { type: String },
  email: { type: String, lowercase: true, required: true, match: /.+[\\@].+\..+/ },
  password: { type: String },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  accountId: { type: mongoose.Schema.Types.ObjectId, ref: 'Account', required: true },
  profilePicture: { type: String },
  deleted: { type: Boolean }
}, { timestamps: true }))

describe('stats test', () => {
  let app
  let originalEnv
  let secrets
  beforeAll(async () => {
    await mongooseMemoryServer.start()
    await mongooseMemoryServer.connect('test-db')
    process.env.NODE_ENV = 'development'
    process.env.SECRETS = 'verylongsecret1 verylongsecret2'
    process.env.APP_URL = 'http://app.emailfox.link/'
    originalEnv = process.env
    secrets = process.env.SECRETS.split(' ')
    app = createApiServer((e) => {
      return {
        status: e.status,
        error: {
          name: e.name,
          message: e.message
        }
      }
    }, () => {})
    stats({ apiServer: app, UserModel: UserTestModel, AccountModel: AccountTestModel })
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

  test('success get overall stats', async () => {
    const account1 = new AccountTestModel({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const account2 = new AccountTestModel({ name: 'accountExample2', urlFriendlyName: 'urlFriendlyNameExample2' })
    await account2.save()

    const account3 = new AccountTestModel({ name: 'accountExample3', urlFriendlyName: 'urlFriendlyNameExample3' })
    await account3.save()

    const user1 = new UserTestModel({ email: 'user1@gmail.com', name: 'user1', password: 'hash1', accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])
    const res = await request(app).get('/v1/statistics/overall')
      .set('authorization', 'Bearer ' + token).send()

    expect(res.body.status).toBe(200)
    expect(res.body.result.activeAccounts).toBe(3)
    expect(res.body.result.activeUsers).toBe(1)
  })

  test('success get accounts monthly statistics', async () => {
    const account1 = new AccountTestModel({
      name: 'accountExample1',
      urlFriendlyName: 'urlFriendlyNameExample1',
      updatedAt: new Date('2024-8-9'),
      createdAt: new Date('2024-8-9')
    })
    await account1.save()

    const account2 = new AccountTestModel({
      name: 'accountExample2',
      urlFriendlyName: 'urlFriendlyNameExample2',
      updatedAt: new Date('2024-10-10'),
      createdAt: new Date('2024-10-10')
    })
    await account2.save()

    const account3 = new AccountTestModel({
      name: 'accountExample3',
      urlFriendlyName: 'urlFriendlyNameExample3',
      updatedAt: new Date('2024-10-11'),
      createdAt: new Date('2024-10-11')
    })
    await account3.save()

    const account4 = new AccountTestModel({
      name: 'accountExample3',
      urlFriendlyName: 'urlFriendlyNameExample3',
      updatedAt: new Date('2024-10-10'),
      createdAt: new Date('2024-10-10'),
      deleted: true
    })
    await account4.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app).get('/v1/statistics/accounts')
      .set('authorization', 'Bearer ' + token)
      .query({ filter: { startDate: new Date('2024-10'), endDate: new Date('2024-11') } })

    expect(res.body.status).toBe(200)
    expect(res.body.result['2024-10'].accounts).toBe(2)
    expect(res.body.result['2024-10'].deleted).toBe(1)
  })

  test('success get accounts monthly statistics without query', async () => {
    const account1 = new AccountTestModel({
      name: 'accountExample1',
      urlFriendlyName: 'urlFriendlyNameExample1'
    })
    await account1.save()

    const account2 = new AccountTestModel({
      name: 'accountExample2',
      urlFriendlyName: 'urlFriendlyNameExample2'
    })
    await account2.save()

    const account3 = new AccountTestModel({
      name: 'accountExample3',
      urlFriendlyName: 'urlFriendlyNameExample3'
    })
    await account3.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app).get('/v1/statistics/accounts')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
    expect(res.body.result[new Date().toISOString().slice(0, 7)].accounts).toBe(3)
  })

  test('success get accounts weekly statistics', async () => {
    const account1 = new AccountTestModel({
      name: 'accountExample1',
      urlFriendlyName: 'urlFriendlyNameExample1'
    })
    await account1.save()

    const account2 = new AccountTestModel({
      name: 'accountExample2',
      urlFriendlyName: 'urlFriendlyNameExample2'
    })
    await account2.save()

    const account3 = new AccountTestModel({
      name: 'accountExample3',
      urlFriendlyName: 'urlFriendlyNameExample3'
    })
    await account3.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const start = new Date()
    start.setDate(start.getDate() - start.getDay()) // Start of the week
    const end = new Date()
    end.setDate(end.getDate() + (6 - end.getDay())) // End of the week
    const weekly = `${start.getFullYear()}-${String(start.getMonth() + 1).padStart(2, '0')}-${String(start.getDate()).padStart(2, '0')} to ${end.getFullYear()}-${String(end.getMonth() + 1).padStart(2, '0')}-${String(end.getDate()).padStart(2, '0')}`

    const res = await request(app).get('/v1/statistics/accounts')
      .set('authorization', 'Bearer ' + token)
      .query({ filter: { type: 'weekly' } })

    expect(res.body.status).toBe(200)
    expect(res.body.result[weekly].accounts).toBe(3)
  })

  test('success get accounts daily statistics', async () => {
    const account1 = new AccountTestModel({
      name: 'accountExample1',
      urlFriendlyName: 'urlFriendlyNameExample1',
      updatedAt: new Date('2024-8-9'),
      createdAt: new Date('2024-8-9')
    })
    await account1.save()

    const account2 = new AccountTestModel({
      name: 'accountExample2',
      urlFriendlyName: 'urlFriendlyNameExample2',
      updatedAt: new Date('2024-10-10'),
      createdAt: new Date('2024-10-10')
    })
    await account2.save()

    const account3 = new AccountTestModel({
      name: 'accountExample3',
      urlFriendlyName: 'urlFriendlyNameExample3',
      updatedAt: new Date('2024-10-11'),
      createdAt: new Date('2024-10-11')
    })
    await account3.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app).get('/v1/statistics/accounts')
      .set('authorization', 'Bearer ' + token)
      .query({ filter: { type: 'daily', startDate: new Date('2024-10-01'), endDate: new Date('2024-11-01') } })

    expect(res.body.status).toBe(200)
    expect(res.body.result['2024-10-10'].accounts).toBe(1)
    expect(res.body.result['2024-10-11'].accounts).toBe(1)
  })
  test('success get accounts hourly statistics', async () => {
    const account1 = new AccountTestModel({
      name: 'accountExample1',
      urlFriendlyName: 'urlFriendlyNameExample1'
    })
    await account1.save()

    const account2 = new AccountTestModel({
      name: 'accountExample2',
      urlFriendlyName: 'urlFriendlyNameExample2'
    })
    await account2.save()

    const account3 = new AccountTestModel({
      name: 'accountExample3',
      urlFriendlyName: 'urlFriendlyNameExample3'
    })
    await account3.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const date = new Date(new Date().toLocaleString('en-US', { timeZone: 'UTC' }))
    const hourly = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:00`

    const res = await request(app).get('/v1/statistics/accounts')
      .set('authorization', 'Bearer ' + token)
      .query({ filter: { type: 'hourly' } })

    expect(res.body.status).toBe(200)
    expect(res.body.result[hourly].accounts).toBe(3)
  })

  test('success get accounts hourly statistics TimeZone', async () => {
    const account1 = new AccountTestModel({
      name: 'accountExample1',
      urlFriendlyName: 'urlFriendlyNameExample1',
      updatedAt: new Date('2024-10-10T10:20:00+0000'),
      createdAt: new Date('2024-10-10T10:20:00+0000')
    })
    await account1.save()

    const account2 = new AccountTestModel({
      name: 'accountExample2',
      urlFriendlyName: 'urlFriendlyNameExample2',
      updatedAt: new Date('2024-10-10T11:20:00+0000'),
      createdAt: new Date('2024-10-10T11:20:00+0000')
    })
    await account2.save()

    const account3 = new AccountTestModel({
      name: 'accountExample3',
      urlFriendlyName: 'urlFriendlyNameExample3',
      updatedAt: new Date('2024-10-10T22:20:00+0000'),
      createdAt: new Date('2024-10-10T22:20:00+0000')
    })
    await account3.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app).get('/v1/statistics/accounts')
      .set('authorization', 'Bearer ' + token)
      .query({ timeZone: 'UTC', filter: { type: 'hourly', startDate: new Date('2024-10-09'), endDate: new Date('2024-10-11') } })

    expect(res.body.status).toBe(200)
    expect(res.body.result['2024-10-10 10:00'].accounts).toBe(1)
    expect(res.body.result['2024-10-10 11:00'].accounts).toBe(1)
    expect(res.body.result['2024-10-10 22:00'].accounts).toBe(1)
    expect(res.body.result['2024-10-08 08:00']).toBe(undefined)
  })

  test('error date range exceeds get accounts monthly statistics', async () => {
    const token = jwt.sign({ type: 'admin' }, secrets[0])
    const res = await request(app).get('/v1/statistics/accounts')
      .set('authorization', 'Bearer ' + token)
      .query({ filter: { type: 'monthly', startDate: new Date(new Date().setMonth(new Date().getMonth() - 13)), endDate: new Date() } })

    expect(res.body.status).toBe(405)
  })

  test('error date range exceeds get accounts hourly statistics', async () => {
    const token = jwt.sign({ type: 'admin' }, secrets[0])
    const res = await request(app).get('/v1/statistics/accounts')
      .set('authorization', 'Bearer ' + token)
      .query({ filter: { type: 'hourly', startDate: new Date(new Date().setMonth(new Date().getMonth() - 1)), endDate: new Date() } })

    expect(res.body.status).toBe(405)
  })

  test('success get users monthly statistics', async () => {
    const accountId = mongoose.Types.ObjectId()

    const user1 = new UserTestModel({
      email: 'user1@gmail.com',
      name: 'user1',
      password: 'hash1',
      accountId,
      updatedAt: new Date('2024-8-9'),
      createdAt: new Date('2024-8-9')
    })
    await user1.save()

    const user2 = new UserTestModel({
      email: 'user2@gmail.com',
      name: 'user2',
      password: 'hash1',
      accountId,
      updatedAt: new Date('2024-10-10'),
      createdAt: new Date('2024-10-10')
    })
    await user2.save()

    const user3 = new UserTestModel({
      email: 'user3@gmail.com',
      name: 'user3',
      password: 'hash1',
      accountId,
      updatedAt: new Date('2024-10-11'),
      createdAt: new Date('2024-10-11')
    })
    await user3.save()

    const user4 = new UserTestModel({
      email: 'user4@gmail.com',
      name: 'user4',
      password: 'hash1',
      accountId,
      updatedAt: new Date('2024-10-10'),
      createdAt: new Date('2024-10-10'),
      deleted: true
    })
    await user4.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app).get('/v1/statistics/users')
      .set('authorization', 'Bearer ' + token)
      .query({ filter: { startDate: new Date('2024-10'), endDate: new Date('2024-11') } })

    expect(res.body.status).toBe(200)
    expect(res.body.result['2024-10'].users).toBe(2)
    expect(res.body.result['2024-10'].deleted).toBe(1)
  })

  test('success get users monthly statistics without query', async () => {
    const accountId = mongoose.Types.ObjectId()

    const user1 = new UserTestModel({
      email: 'user1@gmail.com',
      name: 'user1',
      password: 'hash1',
      accountId
    })
    await user1.save()

    const user2 = new UserTestModel({
      email: 'user2@gmail.com',
      name: 'user2',
      password: 'hash1',
      accountId
    })
    await user2.save()

    const user3 = new UserTestModel({
      email: 'user3@gmail.com',
      name: 'user3',
      password: 'hash1',
      accountId
    })
    await user3.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app).get('/v1/statistics/users')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
    expect(res.body.result[new Date().toISOString().slice(0, 7)].users).toBe(3)
  })

  test('success get users weekly statistics', async () => {
    const accountId = mongoose.Types.ObjectId()

    const user1 = new UserTestModel({
      email: 'user1@gmail.com',
      name: 'user1',
      password: 'hash1',
      accountId
    })
    await user1.save()

    const user2 = new UserTestModel({
      email: 'user2@gmail.com',
      name: 'user2',
      password: 'hash1',
      accountId
    })
    await user2.save()

    const user3 = new UserTestModel({
      email: 'user3@gmail.com',
      name: 'user3',
      password: 'hash1',
      accountId
    })
    await user3.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const start = new Date()
    start.setDate(start.getDate() - start.getDay()) // Start of the week
    const end = new Date()
    end.setDate(end.getDate() + (6 - end.getDay())) // End of the week
    const weekly = `${start.getFullYear()}-${String(start.getMonth() + 1).padStart(2, '0')}-${String(start.getDate()).padStart(2, '0')} to ${end.getFullYear()}-${String(end.getMonth() + 1).padStart(2, '0')}-${String(end.getDate()).padStart(2, '0')}`

    const res = await request(app).get('/v1/statistics/users')
      .set('authorization', 'Bearer ' + token)
      .query({ filter: { type: 'weekly' } })

    expect(res.body.status).toBe(200)
    expect(res.body.result[weekly].users).toBe(3)
  })

  test('success get users daily statistics', async () => {
    const accountId = mongoose.Types.ObjectId()

    const user1 = new UserTestModel({
      email: 'user1@gmail.com',
      name: 'user1',
      password: 'hash1',
      accountId,
      updatedAt: new Date('2024-8-9'),
      createdAt: new Date('2024-8-9')
    })
    await user1.save()

    const user2 = new UserTestModel({
      email: 'user2@gmail.com',
      name: 'user2',
      password: 'hash1',
      accountId,
      updatedAt: new Date('2024-10-10'),
      createdAt: new Date('2024-10-10')
    })
    await user2.save()

    const user3 = new UserTestModel({
      email: 'user3@gmail.com',
      name: 'user3',
      password: 'hash1',
      accountId,
      updatedAt: new Date('2024-10-11'),
      createdAt: new Date('2024-10-11')
    })
    await user3.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app).get('/v1/statistics/users')
      .set('authorization', 'Bearer ' + token)
      .query({ filter: { type: 'daily', startDate: new Date('2024-10-01'), endDate: new Date('2024-11-01') } })

    expect(res.body.status).toBe(200)
    expect(res.body.result['2024-10-10'].users).toBe(1)
    expect(res.body.result['2024-10-11'].users).toBe(1)
  })

  test('success get users hourly statistics', async () => {
    const accountId = mongoose.Types.ObjectId()

    const user1 = new UserTestModel({
      email: 'user1@gmail.com',
      name: 'user1',
      password: 'hash1',
      accountId
    })
    await user1.save()

    const user2 = new UserTestModel({
      email: 'user2@gmail.com',
      name: 'user2',
      password: 'hash1',
      accountId
    })
    await user2.save()

    const user3 = new UserTestModel({
      email: 'user3@gmail.com',
      name: 'user3',
      password: 'hash1',
      accountId
    })
    await user3.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const date = new Date(new Date().toLocaleString('en-US', { timeZone: 'UTC' }))
    const hourly = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:00`

    const res = await request(app).get('/v1/statistics/users')
      .set('authorization', 'Bearer ' + token)
      .query({ filter: { type: 'hourly' } })

    expect(res.body.status).toBe(200)
    expect(res.body.result[hourly].users).toBe(3)
  })

  test('success get accounts hourly statistics TimeZone', async () => {
    const accountId = mongoose.Types.ObjectId()

    const user1 = new UserTestModel({
      email: 'user1@gmail.com',
      name: 'user1',
      password: 'hash1',
      accountId,
      updatedAt: new Date('2024-10-10T10:20:00+0000'),
      createdAt: new Date('2024-10-10T10:20:00+0000')
    })
    await user1.save()

    const user2 = new UserTestModel({
      email: 'user2@gmail.com',
      name: 'user2',
      password: 'hash1',
      accountId,
      updatedAt: new Date('2024-10-10T11:20:00+0000'),
      createdAt: new Date('2024-10-10T11:20:00+0000')
    })
    await user2.save()

    const user3 = new UserTestModel({
      email: 'user3@gmail.com',
      name: 'user3',
      password: 'hash1',
      accountId,
      updatedAt: new Date('2024-10-10T22:20:00+0000'),
      createdAt: new Date('2024-10-10T22:20:00+0000')
    })
    await user3.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app).get('/v1/statistics/users')
      .set('authorization', 'Bearer ' + token)
      .query({ timeZone: 'UTC', filter: { type: 'hourly', startDate: new Date('2024-10-09'), endDate: new Date('2024-10-11') } })

    expect(res.body.status).toBe(200)
    expect(res.body.result['2024-10-10 10:00'].users).toBe(1)
    expect(res.body.result['2024-10-10 11:00'].users).toBe(1)
    expect(res.body.result['2024-10-10 22:00'].users).toBe(1)
    expect(res.body.result['2024-10-08 08:00']).toBe(undefined)
  })

  test('error date range exceeds get users monthly statistics', async () => {
    const token = jwt.sign({ type: 'admin' }, secrets[0])
    const res = await request(app).get('/v1/statistics/users')
      .set('authorization', 'Bearer ' + token)
      .query({ filter: { type: 'monthly', startDate: new Date(new Date().setMonth(new Date().getMonth() - 13)), endDate: new Date() } })

    expect(res.body.status).toBe(405)
  })

  test('error date range exceeds get users hourly statistics', async () => {
    const token = jwt.sign({ type: 'admin' }, secrets[0])
    const res = await request(app).get('/v1/statistics/users')
      .set('authorization', 'Bearer ' + token)
      .query({ filter: { type: 'hourly', startDate: new Date(new Date().setMonth(new Date().getMonth() - 1)), endDate: new Date() } })

    expect(res.body.status).toBe(405)
  })
})
