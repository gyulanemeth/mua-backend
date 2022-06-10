import mongoose from 'mongoose'
import request from 'supertest'
import crypto from 'crypto'
import createMongooseMemoryServer from 'mongoose-memory'
import jwt from 'jsonwebtoken'

import createServer from './index.js'
// import nodemailer from 'nodemailer'

import Account from '../models/Account.js'
import User from '../models/User.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)
const secrets = process.env.SECRETS.split(' ')

describe('forgot-password test', () => {
  let app

  /*  function emailTesting (info, toBeType, toBeEmail) {
    const messageUrl = nodemailer.getTestMessageUrl(info)

    fetch(messageUrl).then(function (response) {
      return response.text()
    }).then(function (html) {
      const regex = /<a id=\"forgetPasswordLink\" href=\".*\?token=([^"&]+)">/g
      const found = html.match(regex)[0]
      const tokenPosition = found.indexOf('token=')
      const endTagPosition = found.indexOf('\\">')
      const token = found.substring(tokenPosition + 6, endTagPosition)
      const verifiedToken = jwt.verify(token, secrets[0])

      expect(token).toBeDefined()
      expect(verifiedToken.type).toBe(toBeType)
      expect(verifiedToken.email).toBe(toBeEmail)
    })
  } */
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
  // forget password  send tests
  test('success send forget password  /v1/accounts/:accountId/forgot-password/send', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/send')
      .set('authorization', 'Bearer ' + token)
      .send({ email: user1.email })
    expect(res.body.status).toBe(200)
    expect(res.body.result.success).toBe(true)
  //  emailTesting(res.body.result.info, 'forgot-password', user1.email)
  })

  test('send forget password error user not found  /v1/accounts/:accountId/forgot-password/send', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/send')
      .set('authorization', 'Bearer ' + token)
      .send({ email: 'user3@gmail.com' })
    expect(res.body.status).toBe(401)
  })

  test('send forget password for wrong account  /v1/accounts/:accountId/forgot-password/send', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()
    const id = new mongoose.Types.ObjectId()
    const token = jwt.sign({ type: 'User', role: 'admin', account: { _id: id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/send')
      .set('authorization', 'Bearer ' + token)
      .send({ email: user1.email })

    expect(res.body.status).toBe(403)
  })

  // forget password  reset tests

  test('success reset forget password  /v1/accounts/:accountId/forgot-password/reset', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'forgot-password', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'userNewPassword', passwordAgain: 'userNewPassword' })
    expect(res.body.status).toBe(200)
  })

  test(' reset forget password validation error  /v1/accounts/:accountId/forgot-password/reset', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'forgot-password', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'userNewPassword', passwordAgain: 'userWrongeNewPassword' })
    expect(res.body.status).toBe(400)
  })

  test('reset forget password unAuthorized header  /v1/accounts/:accountId/forgot-password/reset', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'userNewPassword', passwordAgain: 'userNewPassword' })
    expect(res.body.status).toBe(403)
  })

  test('reset forget password user email does not exist  /v1/accounts/:accountId/forgot-password/reset', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'forgot-password', user: { _id: user1._id, email: 'user4@gmail.com' } }, secrets[0])
    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/forgot-password/reset')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'userNewPassword', passwordAgain: 'userNewPassword' })
    expect(res.body.status).toBe(401)
  })
})
