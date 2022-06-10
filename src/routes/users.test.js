import mongoose from 'mongoose'
import request from 'supertest'
import crypto from 'crypto'
import createMongooseMemoryServer from 'mongoose-memory'
import jwt from 'jsonwebtoken'

import createServer from './index.js'

import Account from '../models/Account.js'
import User from '../models/User.js'

const mongooseMemoryServer = createMongooseMemoryServer(mongoose)
const secrets = process.env.SECRETS.split(' ')

describe('users test', () => {
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

  test('success update user name in account by admin  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'userUpdate' })

    expect(res.body.status).toBe(200)
  })

  test('success update user name in account by user with role admin  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'userUpdate' })

    expect(res.body.status).toBe(200)
  })

  test('success update user name in account by user himself  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'userUpdate' })

    expect(res.body.status).toBe(200)
  })

  test('update user name unAuthorized header  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'userUpdate' })

    expect(res.body.status).toBe(403)
  })

  test('update undefined user name  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/name')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'userUpdate' })

    expect(res.body.status).toBe(403)
  })

  test('success update user password in account by admin  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'updatePassword', passwordAgain: 'updatePassword' })

    expect(res.body.status).toBe(200)
  })

  test('success update user password in account by user with role admin  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'updatePassword', passwordAgain: 'updatePassword' })

    expect(res.body.status).toBe(200)
  })

  test('success update user password in account by user himself  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'updatePassword', passwordAgain: 'updatePassword' })

    expect(res.body.status).toBe(200)
  })

  test('update user password unAuthorized header  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'updatePassword', passwordAgain: 'updatePassword' })

    expect(res.body.status).toBe(403)
  })

  test('update password undefined user  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'updatePassword', passwordAgain: 'updatePassword' })

    expect(res.body.status).toBe(403)
  })

  test('update user password in account by admin Validation error  /v1/accounts/:accountId/users/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/password')
      .set('authorization', 'Bearer ' + token)
      .send({ password: 'updatePassword', passwordAgain: 'update111111Password' })

    expect(res.body.status).toBe(400)
  })

  test('success update user role in account by admin  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'admin' })

    expect(res.body.status).toBe(200)
  })

  test('success update user role in account by user with role admin  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'admin' })

    expect(res.body.status).toBe(200)
  })

  test('update user role in account methode not allowed error (last admin)  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, role: 'admin', accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'user' })
    expect(res.body.status).toBe(405)
  })

  test('success update user role from admin to user in account by admin   /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', role: 'admin', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'user' })

    expect(res.body.status).toBe(200)
  })

  test('update user role unAuthorized header  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'admin' })

    expect(res.body.status).toBe(403)
  })

  test('update undefined user role  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'admin' })

    expect(res.body.status).toBe(403)
  })

  test('update user role in account error last admin  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/' + account1._id + '/users/' + user1._id + '/role')
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'user' })

    expect(res.body.status).toBe(405)
  })

  test('success delete user in account by admin  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success delete user  in account by user with role admin  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success delete user where admin more than 1   /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', role: 'admin', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('delete user role unAuthorized header  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send({ role: 'admin' })

    expect(res.body.status).toBe(403)
  })

  test('update undefined user role  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id } }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('delete user role in account error last admin  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account: { _id: account1._id }, role: 'admin' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(405)
  })

  test('success get user access token with admin   /v1/accounts/:accountId/users/:id/access-token ', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id + '/access-token')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success get user access token with user same user   /v1/accounts/:accountId/users/:id/access-token ', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', user: { _id: user1._id, accountId: account1._id } }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id + '/access-token')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('get user access token unAuthorized header   /v1/accounts/:accountId/users/:id/access-token ', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value', user: { _id: user1._id, accountId: account1._id } }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id + '/access-token')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('success post user finalize-registration   /v1/accounts/:accountId/users/:id/finalize-registration ', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', role: 'user', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'registration', user: { accountId: account1._id, _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users/' + user1._id + '/finalize-registration')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('post user finalize-registration unAuthorized header   /v1/accounts/:accountId/users/:id/finalize-registration ', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', role: 'user', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', role: 'user', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users/' + user1._id + '/finalize-registration')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('post user finalize-registration for undefined account   /v1/accounts/:accountId/users/:id/finalize-registration ', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()
    const id = new mongoose.Types.ObjectId()
    const token = jwt.sign({ type: 'registration', user: { accountId: id, _id: user1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + id + '/users/' + user1._id + '/finalize-registration')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(404)
  })

  test('post user finalize-registration for undefined user   /v1/accounts/:accountId/users/:id/finalize-registration ', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', role: 'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const id = new mongoose.Types.ObjectId()
    const token = jwt.sign({ type: 'registration', user: { _id: id, accountId: account1._id } }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users/' + id + '/finalize-registration')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(404)
  })

  test('success get all account users  by admin  /v1/accounts/:accountId/users', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success get all account users by user  /v1/accounts/:accountId/users', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('get all account users unAuthorized header  /v1/accounts/:accountId/users', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
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
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send({ email: 'user2@gmail.com', name: 'user2', password: 'user2Password' })

    expect(res.body.status).toBe(201)
  })

  test('success add user by user  /v1/accounts/:accountId/users', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send({ email: 'user2@gmail.com', name: 'user2', password: 'user2Password' })

    expect(res.body.status).toBe(201)
  })

  test('add user unAuthorized header  /v1/accounts/:accountId/users', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send({ email: 'user2@gmail.com', name: 'user2', password: 'user2Password' })

    expect(res.body.status).toBe(403)
  })

  test('add user user exist error  /v1/accounts/:accountId/users', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/' + account1._id + '/users')
      .set('authorization', 'Bearer ' + token)
      .send({ email: 'user1@gmail.com', name: 'user1', password: 'user1Password' })

    expect(res.body.status).toBe(405)
  })

  test('add user undefined account  /v1/accounts/:accountId/users', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
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
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success get account user by user  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('get account user unAuthorized header  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('get account user account not found  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user' }, secrets[0])
    const id = new mongoose.Types.ObjectId()
    const res = await request(app)
      .get('/v1/accounts/' + id + '/users/' + user1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(404)
  })

  test('get account user user not found  /v1/accounts/:accountId/users/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const token = jwt.sign({ type: 'user' }, secrets[0])
    const id = new mongoose.Types.ObjectId()
    const res = await request(app)
      .get('/v1/accounts/' + account1._id + '/users/' + id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(404)
  })
})
