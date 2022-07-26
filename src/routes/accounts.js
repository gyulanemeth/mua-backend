import crypto from 'crypto'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'

import jwt from 'jsonwebtoken'
import handlebars from 'handlebars'

import allowAccessTo from 'bearer-jwt-auth'
import { ConflictError } from 'standard-api-errors'
import { list, readOne, deleteOne, deleteMany, patchOne, createOne } from 'mongoose-crudl'

import AccountModel from '../models/Account.js'
import UserModel from '../models/User.js'
import sendEmail from '../helpers/sendEmail.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const registration = fs.readFileSync(path.join(__dirname, '..', 'email-templates', 'registration.html'), 'utf8')

const secrets = process.env.SECRETS.split(' ')

export default (apiServer) => {
  apiServer.get('/v1/accounts/check-availability', async req => {
    let available = false
    const response = await list(AccountModel, { urlFriendlyName: req.query.urlFriendlyName })
    if (response.result.count > 0) {
      available = true
    }
    return {
      status: 200,
      result: {
        available
      }
    }
  })

  apiServer.get('/v1/accounts/', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await list(AccountModel, req.params, req.query)
    return response
  })

  apiServer.post('/v1/accounts/', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }])
    const response = await createOne(AccountModel, req.params, req.body)
    return response
  })

  apiServer.get('/v1/accounts/:id', async req => { /// update user should be associated to account
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', account: { _id: req.params.id } }])
    const response = await readOne(AccountModel, { id: req.params.id }, req.query)
    return response
  })

  apiServer.patch('/v1/accounts/:id/name', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    const response = await patchOne(AccountModel, { id: req.params.id }, { name: req.body.name })
    return response
  })

  apiServer.patch('/v1/accounts/:id/urlFriendlyName', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    const response = await patchOne(AccountModel, { id: req.params.id }, { urlFriendlyName: req.body.urlFriendlyName })
    return response
  })

  apiServer.delete('/v1/accounts/:id', async req => {
    allowAccessTo(req, secrets, [{ type: 'admin' }, { type: 'user', role: 'admin' }])
    deleteMany(UserModel, { accountId: req.params.id })
    const deletedAccount = await deleteOne(AccountModel, { id: req.params.id })
    return {
      status: 200,
      result: {
        deletedAccount: deletedAccount.result
      }
    }
  })

  apiServer.post('/v1/accounts/create', async req => {
    const response = await list(AccountModel, { urlFriendlyName: req.body.account.urlFriendlyName }, req.query)
    if (response.result.count > 0) {
      throw new ConflictError('urlFriendlyName exist')
    }
    const newAccount = await createOne(AccountModel, req.params, { name: req.body.account.name, urlFriendlyName: req.body.account.urlFriendlyName })
    const hash = crypto.createHash('md5').update(req.body.user.password).digest('hex')
    const newUser = await createOne(UserModel, req.params, { name: req.body.user.name, email: req.body.user.email, password: hash, accountId: newAccount.result._id })
    const payload = {
      type: 'registration',
      user: {
        _id: newUser.result._id,
        email: newUser.result.email
      },
      account: {
        _id: newAccount.result._id
      }
    }
    const token = jwt.sign(payload, secrets[0], { expiresIn: '24h' })
    const template = handlebars.compile(registration)
    const html = template({ href: `${process.env.APP_URL}finalize-registration?token=${token}` })
    const mail = await sendEmail(newUser.result.email, 'Registration link ', html)

    return {
      status: 200,
      result: {
        newAccount: newAccount.result,
        newUser: newUser.result,
        info: mail.result.info
      }
    }
  })
}
