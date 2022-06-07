import { list, readOne, deleteOne, deleteMany, patchOne, createOne } from 'mongoose-crudl'
//import jwt from 'jsonwebtoken'
import allowAccessTo from 'bearer-jwt-auth'
import AccounModel from '../models/Account.js'
import UserModel from '../models/User.js'
import { MethodNotAllowedError, ValidationError, NotFoundError } from 'standard-api-errors'

import allowAccessTo from 'bearer-jwt-auth'
import crypto from 'crypto'

export default (apiServer) => {
  const secrets = process.env.SECRETS.split(' ')


  apiServer.patchOne('/v1/accounts/:accountId/users/:id/name', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }, { type: 'user', id: req.params.id }])
    const user = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { name: req.body.name } )
    return user
    })

  apiServer.patchOne('/v1/accounts/:accountId/users/:id/password', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', id: req.params.id }])
    if (req.body.password !== req.body.passwordAgain) {
      throw new ValidationError("Validation error passwords didn't match ")
    }
    const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
    const user = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { password: hash } )
    return user
    })

  apiServer.patchOne('/v1/accounts/:accountId/users/:id/role', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])

    const user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId })
    if(user.result.role === 'admin'){
      const admin = await list(UserModel, { role: 'admin' }, req.query)
      if(admin.result.count < 2){
        throw new MethodNotAllowedError('Removing the last admin is not allowed')
      }
    }
    const updatedUser = await patchOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, { role: req.body.role } )
    return updatedUser;
    })

  apiServer.deleteOne('/v1/accounts/:accountId/users/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])

    let user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId })
    if(user.result.role === 'admin'){
      const admin = await list(UserModel, { role: 'admin' }, req.query)
      if(admin.result.count < 2){
        throw new MethodNotAllowedError('Removing the last admin is not allowed')
      }
    }
    user = await deleteOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, req.query)
    return user;

    })


    apiServer.get('/v1/accounts/:accountId/users/:id/access-token', async req => {
      allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', user: { _id: req.params.id, accountId: req.params.accountId} }])

      const account = await readOne(AccountModel, { id: req.params.accountId }, req.query )

      const user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, req.query )
      //ask about token type
      const payload = {
        type: 'user',
        user: {
          _id: response.result._id,
          email: response.result.email
        },
        account:{
          _id: account.result._id,
          urlFriendlyName: account.result.urlFriendlyName
        },
        role: user.result.role
      }
      const token = jwt.sign(payload, secrets[0])
      return {
        status: 200,
        result: {
          accessToken: 'Bearer ' + token
        }
      }
      })


  apiServer.post('/v1/accounts/:accountId/users/:id/finalize-registration', async req => {
    allowAccessTo(req, secrets, [{ type: 'registration' }])

    const account = await list(AccountModel, { id: data.accountId }, req.query )
    let user = await list(UserModel, { id: data.userId }, req.query)
    if(account.result.count === 0 && user.result.count === 0 ){
      throw new NotFoundError("account or user not found")
    }
    user = await patchOne(UserModel, { id: data.userId, role: "admin" }, req.query)
    return user
  })


    apiServer.get('/v1/accounts/:accountId/users', async req => {
      allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user' }])
      const userList = await list(UserModel, { accountId: req.params.accountId }, req.query )
      return userList
    })

    apiServer.post('/v1/accounts/:accountId/users', async req => {
      allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user' }])
      await list(AccountModel, { id: req.params.accountId }, req.query )

      const checkUser = await list(UserModel, { email: req.body.email, accountId: req.params.accountId }, req.query )
      if(checkUser.result.count !== 0 ){
        throw new MethodNotAllowedError('User exist')
      }
      const hash = crypto.createHash('md5').update(req.body.password).digest('hex')
      const newUser = await createOne(UserModel, req.params, {name: req.body.name, email: req.body.email, password: hash, accountId: req.params.accountId })

      return newUser
      })

    apiServer.get('/v1/accounts/:accountId/users/:id', async req => {
      allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user' }])
      const user = await readOne(UserModel, { id: req.params.id, accountId: req.params.accountId }, req.query )
      return user
      })




}
