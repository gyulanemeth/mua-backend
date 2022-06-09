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




    test('success update user name in account by admin  /v1/accounts/:accountId/users/:id/name', async () => {
      const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
      await account1.save()

      const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
      const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
      await user1.save()

      const token = jwt.sign({ type: 'admin' }, secrets[0])

      const res = await request(app)
        .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/name')
        .set('authorization', 'Bearer ' + token)
        .send({name:'userUpdate'})

      expect(res.body.status).toBe(200)
    })



    test('success update user name in account by user with role admin  /v1/accounts/:accountId/users/:id/name', async () => {
      const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
      await account1.save()

      const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
      const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
      await user1.save()

      const token = jwt.sign({ type: 'user', account:{_id:account1._id}, role:'admin' }, secrets[0])


      const res = await request(app)
        .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/name')
        .set('authorization', 'Bearer ' + token)
        .send({name:'userUpdate'})

      expect(res.body.status).toBe(200)
    })

  /*  test('success update user name in account by user himself  /v1/accounts/:accountId/users/:id/name', async () => {
      const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
      await account1.save()

      const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
      const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
      await user1.save()

      const token = jwt.sign({ type: 'user', user:{ _id: user1._id } }, secrets[0])

      const res = await request(app)
        .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/name')
        .set('authorization', 'Bearer ' + token)
        .send({name:'userUpdate'})

      expect(res.body.status).toBe(200)
    })*/

    test('update user name unAuthorized header  /v1/accounts/:accountId/users/:id/name', async () => {
      const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
      await account1.save()

      const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
      const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
      await user1.save()

      const token = jwt.sign({ type: 'value', account:{_id:account1._id}, role:'admin' }, secrets[0])


      const res = await request(app)
        .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/name')
        .set('authorization', 'Bearer ' + token)
        .send({name:'userUpdate'})

      expect(res.body.status).toBe(403)
    })

    test('update undefined user name  /v1/accounts/:accountId/users/:id/name', async () => {
      const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
      await account1.save()

      const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
      const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
      await user1.save()

      const token = jwt.sign({ type: 'user', account:{_id:account1._id} }, secrets[0])


      const res = await request(app)
        .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/name')
        .set('authorization', 'Bearer ' + token)
        .send({name:'userUpdate'})

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
        .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/password')
        .set('authorization', 'Bearer ' + token)
        .send({password:'updatePassword', passwordAgain:'updatePassword'})

      expect(res.body.status).toBe(200)
    })



  /*  test('success update user password in account by user with role admin  /v1/accounts/:accountId/users/:id/name', async () => {
      const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
      await account1.save()

      const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
      const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
      await user1.save()

      const token = jwt.sign({ type: 'user', account:{_id:account1._id}, role:'admin' }, secrets[0])


      const res = await request(app)
        .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/password')
        .set('authorization', 'Bearer ' + token)
        .send({password:'updatePassword', passwordAgain:'updatePassword'})

      expect(res.body.status).toBe(200)
    })

    test('success update user password in account by user himself  /v1/accounts/:accountId/users/:id/name', async () => {
      const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
      await account1.save()

      const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
      const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
      await user1.save()

      const token = jwt.sign({ type: 'user', user:{ _id: user1._id } }, secrets[0])

      const res = await request(app)
        .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/password')
        .set('authorization', 'Bearer ' + token)
        .send({password:'updatePassword', passwordAgain:'updatePassword'})

      expect(res.body.status).toBe(200)
    })*/

    test('update user password unAuthorized header  /v1/accounts/:accountId/users/:id/name', async () => {
      const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
      await account1.save()

      const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
      const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
      await user1.save()

      const token = jwt.sign({ type: 'value', account:{_id:account1._id}, role:'admin' }, secrets[0])


      const res = await request(app)
        .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/password')
        .set('authorization', 'Bearer ' + token)
        .send({password:'updatePassword', passwordAgain:'updatePassword'})

      expect(res.body.status).toBe(403)
    })

    test('update password undefined user  /v1/accounts/:accountId/users/:id/name', async () => {
      const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
      await account1.save()

      const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
      const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
      await user1.save()

      const token = jwt.sign({ type: 'user', account:{_id:account1._id} }, secrets[0])


      const res = await request(app)
        .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/password')
        .set('authorization', 'Bearer ' + token)
        .send({password:'updatePassword', passwordAgain:'updatePassword'})

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
        .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/password')
        .set('authorization', 'Bearer ' + token)
        .send({password:'updatePassword', passwordAgain:'update111111Password'})

      expect(res.body.status).toBe(400)
    })


    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/


        test('success update user role in account by admin  /v1/accounts/:accountId/users/:id/role', async () => {
          const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
          await account1.save()

          const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
          const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
          await user1.save()

          const token = jwt.sign({ type: 'admin' }, secrets[0])

          const res = await request(app)
            .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/role')
            .set('authorization', 'Bearer ' + token)
            .send({role:'admin'})

          expect(res.body.status).toBe(200)
        })



        test('success update user role in account by user with role admin  /v1/accounts/:accountId/users/:id/role', async () => {
          const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
          await account1.save()

          const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
          const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
          await user1.save()

          const token = jwt.sign({ type: 'user', account:{_id:account1._id}, role:'admin' }, secrets[0])


          const res = await request(app)
            .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/role')
            .set('authorization', 'Bearer ' + token)
            .send({role:'admin'})

          expect(res.body.status).toBe(200)
        })

      /*  test('success update user role in account by user himself  /v1/accounts/:accountId/users/:id/role', async () => {
          const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
          await account1.save()

          const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
          const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
          await user1.save()

          const token = jwt.sign({ type: 'user', user:{ _id: user1._id } }, secrets[0])

          const res = await request(app)
            .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/role')
            .set('authorization', 'Bearer ' + token)
            .send({role:'admin'})

          expect(res.body.status).toBe(200)
        })*/

        test('update user role unAuthorized header  /v1/accounts/:accountId/users/:id/role', async () => {
          const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
          await account1.save()

          const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
          const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
          await user1.save()

          const token = jwt.sign({ type: 'value', account:{_id:account1._id}, role:'admin' }, secrets[0])


          const res = await request(app)
            .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/role')
            .set('authorization', 'Bearer ' + token)
            .send({role:'admin'})

          expect(res.body.status).toBe(403)
        })

        test('update undefined user role  /v1/accounts/:accountId/users/:id/role', async () => {
          const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
          await account1.save()

          const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
          const user1 = new User({ email: 'user1@gmail.com', name: 'user1', password: hash1, accountId: account1._id })
          await user1.save()

          const token = jwt.sign({ type: 'user', account:{_id:account1._id} }, secrets[0])


          const res = await request(app)
            .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/role')
            .set('authorization', 'Bearer ' + token)
            .send({role:'admin'})

          expect(res.body.status).toBe(403)
        })



  test('update user role in account error last admin  /v1/accounts/:accountId/users/:id/role', async () => {
    const account1 = new Account({ name: 'accountExample1', urlFriendlyName: 'urlFriendlyNameExample1' })
    await account1.save()

    const hash1 = crypto.createHash('md5').update('user1Password').digest('hex')
    const user1 = new User({ email: 'user1@gmail.com', name: 'user1', role:'admin', password: hash1, accountId: account1._id })
    await user1.save()

    const token = jwt.sign({ type: 'user', account:{_id:account1._id}, role:'admin' }, secrets[0])


    const res = await request(app)
      .patch('/v1/accounts/'+account1._id+'/users/'+user1._id+'/role')
      .set('authorization', 'Bearer ' + token)
      .send({role:'user'})

    expect(res.body.status).toBe(405)
  })




})
