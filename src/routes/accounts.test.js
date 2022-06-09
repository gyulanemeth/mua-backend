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

describe('/v1/accounts/:accountId/forgot-password/send', () => {
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

  test('success get all accounts   /v1/accounts/', async () => {
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
      .get('/v1/accounts/')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('get all accounts unAuthorized header   /v1/accounts/', async () => {
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
      .get('/v1/accounts/')
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('success admin create account   /v1/accounts/', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'accountExample2', urlFriendlyName: 'urlFriendlyNameExample2' })

    expect(res.body.status).toBe(201)
  })

  test('admin create account unAuthorized header    /v1/accounts/', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'value' }, secrets[0])

    const res = await request(app)
      .post('/v1/accounts/')
      .set('authorization', 'Bearer ' + token)
      .send({ name: 'accountExample2', urlFriendlyName: 'urlFriendlyNameExample2' })

    expect(res.body.status).toBe(403)
  })

  test('success get account by id   /v1/accounts/:id', async () => {
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
      .get('/v1/accounts/'+account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('success get account by id   /v1/accounts/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', account:{_id:account1._id} }, secrets[0])

    const res = await request(app)
      .get('/v1/accounts/'+account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('get account by id unAuthorized header   /v1/accounts/:id', async () => {
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
      .get('/v1/accounts/'+account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('success update account name by admin   /v1/accounts/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/'+account1._id+'/name')
      .set('authorization', 'Bearer ' + token)
      .send({name:'accountNameUpdated'})

    expect(res.body.status).toBe(200)
  })

  test('update account name by user role admin   /v1/accounts/:id/name', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', account:{_id:account1._id}, role:'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/'+account1._id+'/name')
      .set('authorization', 'Bearer ' + token)
      .send({name:'accountNameUpdated'})

    expect(res.body.status).toBe(200)
  })

  test('update account name error unAuthorized header   /v1/accounts/:id/name', async () => {
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
      .patch('/v1/accounts/'+account1._id+'/name')
      .set('authorization', 'Bearer ' + token)
      .send({name:'accountNameUpdated'})

    expect(res.body.status).toBe(403)
  })

  test('update account unAuthorized user   /v1/accounts/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()


    var id = new mongoose.Types.ObjectId();
    const token = jwt.sign({ type: 'user', account: { _id: id }, role:'user' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/'+account1._id+'/name')
      .set('authorization', 'Bearer ' + token)
      .send({name:'accountNameUpdated'})

    expect(res.body.status).toBe(403)
  })


  test('success update account urlFriendlyName by admin   /v1/accounts/:id/urlFriendlyName', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/'+account1._id+'/urlFriendlyName')
      .set('authorization', 'Bearer ' + token)
      .send({urlFriendlyName:'accountUrlFriendlyNameUpdated'})

    expect(res.body.status).toBe(200)
  })

  test('update account urlFriendlyName by user role admin   /v1/accounts/:id/urlFriendlyName', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', account:{_id:account1._id}, role:'admin' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/'+account1._id+'/urlFriendlyName')
      .set('authorization', 'Bearer ' + token)
      .send({urlFriendlyName:'accountUrlFriendlyNameUpdated'})

    expect(res.body.status).toBe(200)
  })

  test('update account urlFriendlyName error unAuthorized header   /v1/accounts/:id/urlFriendlyName', async () => {
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
      .patch('/v1/accounts/'+account1._id+'/urlFriendlyName')
      .set('authorization', 'Bearer ' + token)
      .send({urlFriendlyName:'accountUrlFriendlyNameUpdated'})

    expect(res.body.status).toBe(403)
  })

  test('update account unAuthorized user   /v1/accounts/:id/urlFriendlyName', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()


    var id = new mongoose.Types.ObjectId();
    const token = jwt.sign({ type: 'user', account: { _id: id }, role:'user' }, secrets[0])

    const res = await request(app)
      .patch('/v1/accounts/'+account1._id+'/urlFriendlyName')
      .set('authorization', 'Bearer ' + token)
      .send({urlFriendlyName:'accountUrlFriendlyNameUpdated'})

    expect(res.body.status).toBe(403)
  })

  test('success delete account by admin   /v1/accounts/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const account2 = new Account({ name: 'accountExample2', urlFriendlyName: 'urlFriendlyNameExample2' })
    await account2.save()

    const account3 = new Account({ name: 'accountExample3', urlFriendlyName: 'urlFriendlyNameExample3' })
    await account3.save()

    const account4 = new Account({ name: 'accountExample4', urlFriendlyName: 'urlFriendlyNameExample4' })
    await account4.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash1, accountId: account1._id })
    await user2.save()

    const hash3 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user3 = new User({ email: 'user3@gmail.com', name: 'user3', password: hash1, accountId: account1._id })
    await user3.save()

    const hash4 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user4 = new User({ email: 'user4@gmail.com', name: 'user4', password: hash1, accountId: account1._id })
    await user4.save()

    const token = jwt.sign({ type: 'admin' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/'+account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('delete account by user role admin   /v1/accounts/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()

    const token = jwt.sign({ type: 'user', account:{_id:account1._id}, role:'admin' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/'+account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(200)
  })

  test('delete account error unAuthorized header   /v1/accounts/:id', async () => {
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
      .delete('/v1/accounts/'+account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('delete account unAuthorized user   /v1/accounts/:id', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const hash2 = crypto.createHash('md5').update('user2Password').digest('hex')
    const user2 = new User({ email: 'user2@gmail.com', name: 'user2', password: hash2, accountId: account1._id })
    await user2.save()


    var id = new mongoose.Types.ObjectId();
    const token = jwt.sign({ type: 'user', account: { _id: id }, role:'user' }, secrets[0])

    const res = await request(app)
      .delete('/v1/accounts/'+account1._id)
      .set('authorization', 'Bearer ' + token)
      .send()

    expect(res.body.status).toBe(403)
  })

  test('success create account   /v1/accounts/create', async () => {

   const res = await request(app)
     .post('/v1/accounts/create')
     .send({
       user: {name: "user1", email: 'user1@gmail.com', password: 'userPassword' },
       account: {name: 'account1', urlFriendlyName: 'account1UrlFriendlyName'}
     })

   expect(res.body.status).toBe(200)

  })

  test('create account urlFriendlyName exist   /v1/accounts/create', async () => {

    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

   const res = await request(app)
     .post('/v1/accounts/create')
     .send({
       user: {name: "user1", email: 'user1@gmail.com', password: 'userPassword' },
       account: {name: 'account1', urlFriendlyName: 'urlFriendlyNameExample1'}
     })

   expect(res.body.status).toBe(409)

  })

/*
 test('success check-availability   /v1/accounts/check-availability', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()


    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
    await user1.save()

    const res = await request(app)
      .get('/v1/accounts/check-availability')
      .send()

    expect(res.body.status).toBe(200)
  })




  test('success check-availability   /v1/accounts/check-availability', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const res = await request(app)
      .get('/v1/accounts/check-availability/')
      .send()
console.log(res.body);
    expect(res.body.status).toBe(200)
  })

  test('check-availability account not found   /v1/accounts/check-availability', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const res = await request(app)
      .get('/v1/accounts/check-availability')
      .query({
        urlFrientlyName: 'test',
       })
      .send()
      console.log(res.body);
    expect(res.body.status).toBe(401)
  })

*/

})
