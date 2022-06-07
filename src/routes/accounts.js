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

  apiServer.get('/v1/accounts/', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(AccounModel, req.params, req.query)
    return response
  })

  apiServer.post('/v1/accounts/', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await createOne(AccountModel, req.params, req.body)
    return response
  })

  apiServer.get('/v1/accounts/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' },{ type: 'user' }])
    const response = await readOne(AccounModel, {id:req.params.id}, req.query)
    return response
  })

  apiServer.patchOne('/v1/accounts/:id/name', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' },{ type: 'user', role: 'admin' }])
    const response = await patchOne(AccounModel, { id: req.params.id }, { name: req.body.name })
    return response
  })

  apiServer.patchOne('/v1/accounts/:id/urlFriendlyName', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' },{ type: 'user', role: 'admin' }])
    const response = await patchOne(AccounModel, { id: req.params.id }, { urlFriendlyName: req.body.urlFriendlyName })
    return response
  })

  apiServer.delete('/v1/accounts/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' },{ type: 'user', role: 'admin' }])
    const deletedUsers = await deleteMany(UserModel, { accountId: req.params.id })
    const deletedAccount = await deleteOne(AccounModel, { id: req.params.id })
    return {
      status: 200,
      result: {
        deletedUsers:deletedUsers.result,
        deletedAccount:deletedAccount.result
      }
    }
  })

  apiServer.get('/v1/accounts/check-availability', async req => {
    const response = await readOne(AccounModel, req.params, {urlFriendlyName:req.query.urlFriendlyName})
    return {
      status:200,
      result: {
        availability: true
      }
    }
  })

  apiServer.post('/v1/accounts/create', async req => {
    const newAccount = await createOne(AccountModel, req.params, {name: req.body.account.name, urlFriendlyName: req.body.account.urlFriendlyName })
    const hash = crypto.createHash('md5').update(req.body.user.password).digest('hex')
    const newUser = await createOne(UserModel, req.params, {name: req.body.user.name, email: req.body.user.email, password: hash, accountId: newAccount.result._id })
    // send email with token to user
    return {
      status:200,
      result:{
        newAccount:newAccount.result,
        newUser:newUser.result
      }
    }
  })





/*    apiServer.get('/v1/config', async req => {

    })*/
}
