import mongoose from 'mongoose'
import request from 'supertest'
import crypto from 'crypto'
import createMongooseMemoryServer from 'mongoose-memory'
import jwt from 'jsonwebtoken'
import createServer from './index.js'

import User from '../models/User.js'
import Account from '../models/Account.js'
const mongooseMemoryServer = createMongooseMemoryServer(mongoose)
const secrets = process.env.SECRETS.split(' ')

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

  test('login with valid password ', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'login', user:{email:user1.email} }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/login')
      .set('authorization', 'Bearer ' + token)
      .send({ password: "user1Password" })

    expect(res.body.status).toBe(200)
  })

  test('login with wronge password', async () => {
    const account1 = new Account({ name: 'account_example', urlFriendlyName: 'urlFriendlyName_example' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()


    const token = jwt.sign({ type: 'login', user:{email:user1.email} }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/login')
      .set('authorization', 'Bearer ' + token)
      .send({ password: "user2Password" })

    expect(res.statusCode).toBe(401)
  })

  test('login with wronge header', async () => {
    const account1 = new Account({ name: 'account_example', urlFriendlyName: 'urlFriendlyName_example' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', user:{email:user1.email} }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/login')
      .set('authorization', 'Bearer ' + token)
      .send({ password: "user1Password" })

    expect(res.statusCode).toBe(403)
  })

  test('login without header account', async () => {
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
      .send({ password: "user1Password" })

    expect(res.body.status).toBe(401)
  })

  test('login with unexist account', async () => {
    const account1 = new Account({ name: 'account_example', urlFriendlyName: 'urlFriendlyName_example' })
    await account1.save()

    const account2 = new Account({ name: 'account_example', urlFriendlyName: 'urlFriendlyName_example' })

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'login;', user:{email:user1.email} }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account2._id + '/login')
      .set('authorization', 'Bearer ' + token)
      .send({ password: "user1Password" })

    expect(res.body.status).toBe(403)
  })


  test('login get accounts with valid email ', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const res = await request(app)
      .post('/v1/accounts/login')
      .send({ email: user1.email })

    expect(res.body.status).toBe(201)
  })

  test('login get accounts with unvalid email ', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const res = await request(app)
      .post('/v1/accounts/login')
      .send({ email: "wrongTest@gmail.com" })

    expect(res.body.status).toBe(401)
  })


})
