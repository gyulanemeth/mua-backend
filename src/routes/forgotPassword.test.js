import crypto from 'crypto'

import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import request from 'supertest'
import nodemailer from 'nodemailer'

import createMongooseMemoryServer from 'mongoose-memory'

import createServer from './index.js'
import Account from '../models/Account.js'
import User from '../models/User.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)

const secrets = process.env.SECRETS.split(' ')

describe('forgot-password test', () => {
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

    // testing email sent

    const messageUrl = nodemailer.getTestMessageUrl(res.body.result.info)

    const html = await fetch(messageUrl).then(response => response.text())
    const regex = /<a[\s]+id=\\"forgetPasswordLink\\"[^\n\r]*\?token&#x3D([^"&]+)">/g
    const found = html.match(regex)[0]
    const tokenPosition = found.indexOf('token&#x3D')
    const endTagPosition = found.indexOf('\\">')
    const htmlToken = found.substring(tokenPosition + 11, endTagPosition)
    const verifiedToken = jwt.verify(htmlToken, secrets[0])
    expect(htmlToken).toBeDefined()
    expect(verifiedToken.type).toBe('forgot-password')
    expect(verifiedToken.user.email).toBe(user1.email)
    expect(JSON.stringify(verifiedToken.account._id)).toBe(JSON.stringify(user1.accountId))
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
    const id = new mongoose.Types.ObjectId()
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const res = await request(app)
      .post('/v1/accounts/' + id + '/forgot-password/send')
      .send({ email: user1.email })
    expect(res.body.status).toBe(401)
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
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userNewPassword' })
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
      .send({ newPassword: 'userNewPassword', newPasswordAgain: 'userWrongNewPassword' })
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
