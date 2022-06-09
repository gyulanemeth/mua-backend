import { list, readOne, deleteOne, deleteMany, patchOne, createOne } from 'mongoose-crudl'
import jwt from 'jsonwebtoken'
import allowAccessTo from 'bearer-jwt-auth'
import AccountModel from '../models/Account.js'
import UserModel from '../models/User.js'
import { MethodNotAllowedError, ValidationError, NotFoundError, AuthenticationError } from 'standard-api-errors'
import crypto from 'crypto'

export default (apiServer) => {
  const secrets = process.env.SECRETS.split(' ')

  apiServer.post('/v1/accounts/:id/login', async req => {
    req.body.email = req.body.email.toLowerCase()
    req.body.password = crypto.createHash('md5').update(req.body.password).digest('hex')
    const findUser = await list(UserModel, { email: req.body.email , accountId: req.params.id, password: req.body.password }, req.query)
    if (findUser.result.count === 0) {
      throw new AuthenticationError('Invalid email or password')
    }
    const getAccount = await readOne(AccountModel, { id:req.params.id }, req.query)
    const payload = {
      type: 'user',
      user: {
        _id: findUser.result.items[0]._id,
        email: findUser.result.items[0].email
      },
      account:{
        _id: getAccount.result._id,
        urlFriendlyName: getAccount.result.urlFriendlyName
      },
      role: findUser.result.items[0].role
    }

    const token = jwt.sign(payload, secrets[0])
    return {
      status: 200,
      result: {
        loginToken: 'Bearer ' + token
      }
    }
  })
}
