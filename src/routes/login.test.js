import mongoose from 'mongoose'
import request from 'supertest'
import crypto from 'crypto'
import createMongooseMemoryServer from 'mongoose-memory'

import createServer from './index.js'

import User from '../models/User.js'
import Account from '../models/Account.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

describe('login test ', () => {
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

  test('login with valid email and password', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/login')
      .send({ email: user1.email, password: 'user1Password' })
    expect(res.body.status).toBe(200)
  })

  test('login with wronge email', async () => {
    const account1 = new Account({ name: 'account_example', urlFriendlyName: 'urlFriendlyName_example' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/login')
      .send({ email: 'user3@gmail.com', password: 'user1Password' })

    expect(res.statusCode).toBe(401)
  })

  test('login with wronge password', async () => {
    const account1 = new Account({ name: 'account_example', urlFriendlyName: 'urlFriendlyName_example' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/login')
      .send({ email: user1.email, password: 'user3Password' })

    expect(res.statusCode).toBe(401)
  })

  test('login to unexcited account', async () => {
    const account1 = new Account({ name: 'account_example', urlFriendlyName: 'urlFriendlyName_example' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()
    const id = new mongoose.Types.ObjectId()
    const res = await request(app)
      .post('/v1/accounts/' + id + '/login')
      .send({ email: user1.email, password: 'user1Password' })
    expect(res.body.status).toBe(401)
  })
})
