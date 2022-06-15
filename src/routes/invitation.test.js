import mongoose from 'mongoose'
import request from 'supertest'
import crypto from 'crypto'
import createMongooseMemoryServer from 'mongoose-memory'
import jwt from 'jsonwebtoken'
import nodemailer from 'nodemailer'

import createServer from './index.js'

import Account from '../models/Account.js'
import User from '../models/User.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)
const secrets = process.env.SECRETS.split(' ')

describe('invitation test', () => {
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

  test('success send invitation by admin /v1/accounts/:accountId/invitation/send', async () => {
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
      .post('/v1/accounts/' + account1._id + '/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(201)
    expect(res.body.result.success).toBe(true)

    // testing email sent

      const messageUrl = nodemailer.getTestMessageUrl(res.body.result.info)

        const html = await fetch(messageUrl).then(response => response.text())
        const regex = /<a[\s]+id=\\"invitationLink\\"[^\n\r]*\?token=([^"&]+)">/g
        const found = html.match(regex)[0]
        const tokenPosition = found.indexOf('token=')
        const endTagPosition = found.indexOf('\\">')
        const htmlToken = found.substring(tokenPosition + 6, endTagPosition)
        const verifiedToken = jwt.verify(htmlToken, secrets[0])

        expect(htmlToken).toBeDefined()
        expect(verifiedToken.type).toBe('invitation')
        expect(verifiedToken.user.email).toBe('user3@gmail.com')

  })

  test('success send invitation by user role admin  /v1/accounts/:accountId/invitation/send', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', role: 'admin' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(201)
    expect(res.body.result.success).toBe(true)

    // testing email sent

        const messageUrl = nodemailer.getTestMessageUrl(res.body.result.info)

          const html = await fetch(messageUrl).then(response => response.text())
          const regex = /<a[\s]+id=\\"invitationLink\\"[^\n\r]*\?token=([^"&]+)">/g
          const found = html.match(regex)[0]
          const tokenPosition = found.indexOf('token=')
          const endTagPosition = found.indexOf('\\">')
          const htmlToken = found.substring(tokenPosition + 6, endTagPosition)
          const verifiedToken = jwt.verify(htmlToken, secrets[0])

          expect(htmlToken).toBeDefined()
          expect(verifiedToken.type).toBe('invitation')
          expect(verifiedToken.user.email).toBe('user3@gmail.com')

  })

  test('send invitation error user exist  /v1/accounts/:accountId/invitation/send', async () => {
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
      .post('/v1/accounts/' + account1._id + '/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user1@gmail.com' })

    expect(res.body.status).toBe(405)
  })

  test('send invitation error unAuthorized header  /v1/accounts/:accountId/invitation/send', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/send').set('authorization', 'Bearer ' + token).send({ email: 'user3@gmail.com' })

    expect(res.body.status).toBe(403)
  })

  // invitation accept tests
  test('success accept invitation  /v1/accounts/:accountId/invitation/accept', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const user2 = new User({ email: 'user2@gmail.com', accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', account: { _id: account1._id }, user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(200)
  })

  test('accept invitation error user exist   /v1/accounts/:accountId/invitation/accept', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', account: { _id: account1._id }, user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })

    expect(res.body.status).toBe(405)
  })

  test('success invitation error unAuthorized header  /v1/accounts/:accountId/invitation/accept', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value', user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(403)
  })

  test('success invitation error unAuthorized access to account  /v1/accounts/:accountId/invitation/accept', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', accountId: account1._id })
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
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', accountId: account1._id })
    await user2.save()
    const token = jwt.sign({ type: 'invitation', account: { _id: account1._id }, user: { _id: user2._id, email: user2.email } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'user222PasswordUpdated' })
    expect(res.body.status).toBe(400)
  })

  test('accept invitation user email does not exist /v1/accounts/:accountId/invitation/accept', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'invitation', account: { _id: account1._id }, user: { _id: user2._id, email: 'user4@gmail.com' } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/invitation/accept')
      .set('authorization', 'Bearer ' + token)
      .send({ newPassword: 'userPasswordUpdated', newPasswordAgain: 'userPasswordUpdated' })
    expect(res.body.status).toBe(404)
  })
})
